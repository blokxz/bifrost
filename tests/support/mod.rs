//! Shared by the pseudo-terminal test binaries: a running `bifrost` in a pty and
//! an emulation of what its terminal would show.
//!
//! Each test binary uses part of this, so unused items are expected.

#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use bifrost_ssh::domain::{Host, Hosts};
use bifrost_ssh::store::{HOSTS_FILE, Store};
use rustix::fs::{Mode, OFlags};
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{
    ControlModes, InputModes, LocalModes, OutputModes, Winsize, tcgetattr, tcsetwinsize,
};

/// How long to wait for anything to happen before declaring a test failed.
pub const PATIENCE: Duration = Duration::from_secs(10);

pub const ESC: &[u8] = b"\x1b";
pub const CTRL_C: &[u8] = b"\x03";

/// What the terminal would show, rebuilt from the bytes the app wrote.
///
/// bifrost only positions the cursor with `ESC [ row ; col H`, styles text with
/// `ESC [ ... m`, clears with `ESC [ 2 J`, switches modes with `ESC [ ? ... h/l`
/// and asks for the clipboard with `ESC ] 52 ; ... BEL`. That is all this
/// understands; anything else is ignored.
pub struct Screen {
    pub rows: Vec<Vec<char>>,
    pub alt_screen: bool,
    pub cursor_visible: bool,
    /// Everything written while the alternate screen was off, in order, with
    /// line breaks kept: what ssh (and the banner before it) put on the user's
    /// normal screen. Escape sequences are not part of it.
    pub normal_text: String,
    /// Whether text was ever written to the normal screen with the cursor hidden.
    pub hidden_cursor_on_normal_screen: bool,
}

impl Screen {
    pub fn from_output(output: &[u8], height: usize, width: usize) -> Screen {
        let mut screen = Screen {
            rows: vec![vec![' '; width]; height],
            alt_screen: false,
            cursor_visible: true,
            normal_text: String::new(),
            hidden_cursor_on_normal_screen: false,
        };
        let text = String::from_utf8_lossy(output);
        let mut chars = text.chars().peekable();
        let (mut row, mut col) = (0, 0);
        while let Some(c) = chars.next() {
            if c != '\x1b' {
                if !c.is_control() {
                    if let Some(cell) = screen.rows.get_mut(row).and_then(|r| r.get_mut(col)) {
                        *cell = c;
                    }
                    col += 1;
                    if !screen.alt_screen {
                        screen.normal_text.push(c);
                        screen.hidden_cursor_on_normal_screen |= !screen.cursor_visible;
                    }
                } else if c == '\n' && !screen.alt_screen {
                    screen.normal_text.push('\n');
                }
                continue;
            }
            if chars.next_if_eq(&']').is_some() {
                // An OSC sequence (such as the clipboard request) ends with BEL
                // or ESC \ and draws nothing.
                while let Some(c) = chars.next() {
                    if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
                continue;
            }
            if chars.next_if_eq(&'[').is_none() {
                continue;
            }
            let mut params = String::new();
            while let Some(p) = chars.next_if(|p| p.is_ascii_digit() || matches!(p, ';' | '?')) {
                params.push(p);
            }
            let Some(last) = chars.next() else { break };
            let numbers: Vec<usize> = params
                .trim_start_matches('?')
                .split(';')
                .filter_map(|n| n.parse().ok())
                .collect();
            match (last, params.starts_with('?')) {
                ('H', false) => {
                    row = numbers.first().copied().unwrap_or(1).saturating_sub(1);
                    col = numbers.get(1).copied().unwrap_or(1).saturating_sub(1);
                }
                ('J', false) if numbers == [2] => screen.clear(),
                ('h' | 'l', true) => {
                    let on = last == 'h';
                    match numbers.first() {
                        Some(1049) => {
                            screen.alt_screen = on;
                            // Leaving restores the normal screen, which the app
                            // never wrote to; entering starts blank.
                            screen.clear();
                        }
                        Some(25) => screen.cursor_visible = on,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        screen
    }

    pub fn clear(&mut self) {
        for row in &mut self.rows {
            row.fill(' ');
        }
    }

    pub fn lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|row| row.iter().collect::<String>().trim_end().to_string())
            .collect()
    }

    pub fn text(&self) -> String {
        self.lines().join("\n")
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.lines().iter().any(|line| line.contains(needle))
    }

    /// Whether `needle` was written to the normal screen (not the alternate one).
    pub fn normal_contains(&self, needle: &str) -> bool {
        self.normal_text.contains(needle)
    }

    pub fn is_blank(&self) -> bool {
        self.lines().iter().all(String::is_empty)
    }
}

/// Whether the raw output styles anything with a color (as opposed to bold,
/// dim, or a reset to the default color).
pub fn uses_color(output: &[u8]) -> bool {
    let text = String::from_utf8_lossy(output);
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("\x1b[") {
        rest = &rest[start + 2..];
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == ';'))
            .unwrap_or(rest.len());
        if rest[end..].starts_with('m') {
            let colored = rest[..end].split(';').any(|param| {
                matches!(
                    param.parse::<u32>(),
                    Ok(30..=37 | 38 | 40..=47 | 48 | 58 | 90..=97 | 100..=107)
                )
            });
            if colored {
                return true;
            }
        }
    }
    false
}

/// The terminal settings that decide how input and output behave: line editing,
/// echo, signals from the keyboard, newline translation. Comparing them is how
/// the tests know raw mode was really left, not just that the app said so.
#[derive(Debug, PartialEq, Eq)]
pub struct Modes {
    input: InputModes,
    output: OutputModes,
    control: ControlModes,
    local: LocalModes,
}

impl Modes {
    pub fn of(fd: &impl AsFd) -> Modes {
        let termios = tcgetattr(fd).expect("read the terminal modes");
        Modes {
            input: termios.input_modes,
            output: termios.output_modes,
            control: termios.control_modes,
            local: termios.local_modes,
        }
    }
}

/// Serializes writing test scripts and starting processes. A file that is open
/// for writing in a forked child that has not yet exec'd makes executing it fail
/// with "text file busy"; with tests running in parallel, that is possible
/// between one test writing a fake ssh and another starting bifrost.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Held while starting a process (or while a call that does, such as
/// `connect::run`, spawns one), so that the case above cannot happen.
pub fn serialize_spawns() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Writes an executable script, without racing a spawn (see [`SPAWN_LOCK`]).
pub fn write_script(path: &Path, content: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _serialized = serialize_spawns();
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A running `bifrost` with a pseudo-terminal as its stdin, stdout and stderr.
pub struct Session {
    /// The terminal's modes as the shell would have left them.
    initial_modes: Modes,
    pub child: Child,
    pub master: File,
    pub chunks: Receiver<Vec<u8>>,
    pub output: Vec<u8>,
    pub height: u16,
    pub width: u16,
}

impl Session {
    pub fn start(config_dir: &Path, height: u16, width: u16, env: &[(&str, &str)]) -> Session {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("open a pty");
        // Keep the master out of the child, which must only see the slave side.
        fcntl_setfd(&master, FdFlags::CLOEXEC).expect("set close-on-exec");
        grantpt(&master).expect("grant the pty");
        unlockpt(&master).expect("unlock the pty");
        set_size(&master, height, width);

        let slave_path = ptsname(&master, Vec::new()).expect("name the pty");
        let slave: OwnedFd = rustix::fs::open(
            slave_path.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open the slave side");

        // Before the child exists: it switches the terminal as soon as it starts.
        let initial_modes = Modes::of(&master);

        let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
        command
            // Its own process group, so that a signal for "the foreground group"
            // can be sent to bifrost and whatever it starts, and to nothing else.
            .process_group(0)
            .env("BIFROST_CONFIG_DIR", config_dir)
            .env("TERM", "xterm-256color")
            .env_remove("NO_COLOR")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        for (key, value) in env {
            command.env(key, value);
        }
        let child = {
            let _serialized = serialize_spawns();
            command.spawn().expect("the bifrost binary should start")
        };
        // Drop the parent's copies of the slave so that reading the master ends
        // when the child exits.
        drop(command);

        let (sender, chunks) = mpsc::channel();
        let mut reader = File::from(master.try_clone().unwrap());
        thread::spawn(move || {
            let mut buffer = [0; 4096];
            // The read fails (Linux) or returns 0 (macOS) once the child is gone.
            while let Ok(n @ 1..) = reader.read(&mut buffer) {
                if sender.send(buffer[..n].to_vec()).is_err() {
                    break;
                }
            }
        });

        Session {
            initial_modes,
            child,
            master: File::from(master),
            chunks,
            output: Vec::new(),
            height,
            width,
        }
    }

    pub fn screen(&self) -> Screen {
        // The grid is as large as the biggest terminal used, so that output
        // drawn before a resize still lands where it was drawn.
        Screen::from_output(
            &self.output,
            usize::from(self.height.max(24)),
            usize::from(self.width.max(80)),
        )
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).expect("send keys");
        self.master.flush().expect("flush keys");
    }

    /// Changes the terminal's size. A real terminal driver also sends SIGWINCH
    /// to the foreground process group; this pty has no controlling terminal
    /// for the driver to look that up in, so the signal is sent here, to the
    /// same processes.
    pub fn resize(&mut self, height: u16, width: u16) {
        set_size(&self.master, height, width);
        self.signal_foreground_group(Signal::WINCH);
    }

    /// What the keyboard's Ctrl-C does in a terminal in its normal mode: SIGINT
    /// to every process of the foreground group, here bifrost and what it started.
    /// (In raw mode Ctrl-C is a byte, sent with [`Session::send`] instead.) The
    /// kernel's own translation of the byte into the signal is not what is under
    /// test, and it needs a controlling terminal that a plain pty does not have.
    pub fn press_ctrl_c_in_a_normal_terminal(&self) {
        self.signal_foreground_group(Signal::INT);
    }

    fn signal_foreground_group(&self, signal: Signal) {
        let group = Pid::from_raw(self.child.id().try_into().unwrap()).expect("a valid pid");
        // The group may already be gone if the test is racing its own end; the
        // assertions that follow are what decide the test.
        let _ = kill_process_group(group, signal);
    }

    /// Reads output until `ready` is true of the screen, or fails the test.
    pub fn wait_until(&mut self, what: &str, ready: impl Fn(&Screen) -> bool) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let screen = self.screen();
            if ready(&screen) {
                return;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.chunks.recv_timeout(left) {
                Ok(chunk) => self.output.extend(chunk),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => panic!(
                    "gave up waiting for {what}. The screen was:\n{}\n(alt screen: {}, cursor \
                     visible: {}). Normal-screen text: {:?}. Last raw output: {:?}",
                    screen.text(),
                    screen.alt_screen,
                    screen.cursor_visible,
                    screen.normal_text,
                    String::from_utf8_lossy(&self.output[self.output.len().saturating_sub(600)..])
                ),
            }
        }
    }

    /// Waits for the process to exit and returns its status with everything it
    /// wrote.
    pub fn finish(mut self) -> (ExitStatus, Vec<u8>) {
        let deadline = Instant::now() + PATIENCE;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll the child") {
                break status;
            }
            assert!(Instant::now() < deadline, "bifrost did not exit");
            thread::sleep(Duration::from_millis(10));
        };
        // The strongest check of "the terminal is as the shell left it": the
        // real modes, read from the terminal itself after bifrost has gone.
        assert_eq!(
            Modes::of(&self.master),
            self.initial_modes,
            "the terminal's modes were not restored when bifrost exited"
        );
        // The reader thread ends when the pty closes; collect what is left.
        while let Ok(chunk) = self.chunks.recv_timeout(Duration::from_millis(500)) {
            self.output.extend(chunk);
        }
        let output = std::mem::take(&mut self.output);
        (status, output)
    }

    /// Whether bifrost is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Sends SIGINT to bifrost alone, as `kill -INT` would (the keyboard's
    /// Ctrl-C reaches the whole foreground group instead).
    pub fn sigint_bifrost_only(&self) {
        let pid = Pid::from_raw(self.child.id().try_into().unwrap()).expect("a valid pid");
        kill_process(pid, Signal::INT).expect("send SIGINT");
    }
}

impl Drop for Session {
    /// A test that fails must not leave a TUI running.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn set_size(fd: &impl std::os::fd::AsFd, height: u16, width: u16) {
    let size = Winsize {
        ws_row: height,
        ws_col: width,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    tcsetwinsize(fd, size).expect("set the terminal size");
}

/// A store with two hosts, in a directory Bifrost created itself so that its
/// permissions are the private ones Bifrost expects (no warnings).
pub fn healthy_store() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut hosts = Hosts::new();
    hosts.add(Host::new("web", "192.0.2.1")).unwrap();
    hosts.add(Host::new("db", "192.0.2.2")).unwrap();
    Store::at(&config).save(&hosts).unwrap();
    (dir, config)
}

pub fn corrupt_store() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(HOSTS_FILE),
        "version = 1\n\n[[hosts]]\nname = \"bad name\"\nhostname = \"192.0.2.1\"\n",
    )
    .unwrap();
    let config = dir.path().to_path_buf();
    (dir, config)
}

/// The terminal must be exactly as the shell left it.
pub fn assert_restored(output: &[u8]) {
    let screen = Screen::from_output(output, 24, 80);
    assert!(!screen.alt_screen, "still on the alternate screen");
    assert!(screen.cursor_visible, "the cursor was left hidden");
    assert!(
        screen.is_blank(),
        "the normal screen was drawn on:\n{}",
        screen.text()
    );
    assert!(
        output.ends_with(b"\x1b[?25h\x1b[?1049l"),
        "the last thing written should be showing the cursor and leaving the \
         alternate screen, got {:?}",
        String::from_utf8_lossy(&output[output.len().saturating_sub(40)..])
    );
}

pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A fake `ssh`: a shell script in a temporary directory that is first in the
/// child's `PATH`, so bifrost finds it exactly as it would find the real one.
/// It records how it was started.
pub struct FakeSsh {
    dir: tempfile::TempDir,
}

impl FakeSsh {
    /// `body` is shell code that runs after the arguments are recorded. `$GO`
    /// is the path of a file the test can create to release the script.
    pub fn new(body: &str) -> FakeSsh {
        let fake = FakeSsh::absent();
        let script = format!(
            "#!/bin/sh\n\
             LOG='{log}'\n\
             GO='{go}'\n\
             {{ printf '%s\\n' \"$0\"; for a in \"$@\"; do printf '%s\\n' \"$a\"; done; }} > \"$LOG\"\n\
             {body}\n",
            log = fake.log_path().display(),
            go = fake.go_path().display(),
        );
        write_script(&fake.program(), &script, 0o755);
        fake
    }

    /// Adds a second fake program next to the ssh, such as `ssh-keygen`, that
    /// records how it was started the same way. `body` is shell code.
    pub fn add_program(&self, name: &str, body: &str) {
        let script = format!(
            "#!/bin/sh\n\
             LOG='{log}'\n\
             {{ printf '%s\\n' \"$0\"; for a in \"$@\"; do printf '%s\\n' \"$a\"; done; }} > \"$LOG\"\n\
             {body}\n",
            log = self.dir.path().join(format!("{name}.log")).display(),
        );
        write_script(&self.dir.path().join("bin").join(name), &script, 0o755);
    }

    /// Whether the extra program was started, and with what: its arguments, not
    /// counting the program path.
    pub fn program_arguments(&self, name: &str) -> Option<Vec<String>> {
        let log = std::fs::read_to_string(self.dir.path().join(format!("{name}.log"))).ok()?;
        Some(log.lines().skip(1).map(str::to_string).collect())
    }

    /// A `PATH` directory with no ssh in it.
    pub fn absent() -> FakeSsh {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bin")).unwrap();
        FakeSsh { dir }
    }

    pub fn program(&self) -> PathBuf {
        self.dir.path().join("bin").join("ssh")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.path().join("argv.log")
    }

    /// Create this file to release a script that waits for `$GO`.
    pub fn go_path(&self) -> PathBuf {
        self.dir.path().join("go")
    }

    pub fn release(&self) {
        std::fs::write(self.go_path(), "").unwrap();
    }

    /// The `PATH` for the bifrost under test: the fake first, then the system
    /// tools a script needs (`stty`, `sleep`, `dd`).
    pub fn path_env(&self) -> String {
        format!("{}:/usr/bin:/bin", self.dir.path().join("bin").display())
    }

    /// The `PATH` that holds only the directory without an ssh.
    pub fn path_env_without_tools(&self) -> String {
        self.dir.path().join("bin").display().to_string()
    }

    /// The program path as the fake saw it in `$0`, and its arguments.
    pub fn invocation(&self) -> (String, Vec<String>) {
        let log = std::fs::read_to_string(self.log_path()).expect("the fake ssh was never started");
        let mut lines = log.lines().map(str::to_string);
        let program = lines.next().expect("the program path");
        (program, lines.collect())
    }

    pub fn was_started(&self) -> bool {
        self.log_path().exists()
    }
}
