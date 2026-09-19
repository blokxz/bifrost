//! The real `bifrost` binary, run inside a real (pseudo) terminal.
//!
//! Unit tests cover the state and the rendering; these cover what only a
//! terminal can show: that raw mode and the alternate screen are entered and
//! left again, that the cursor comes back, that keys reach the app, that a
//! resize is noticed and that `NO_COLOR` really removes color.
//!
//! Unix only: pseudo-terminals are a Unix feature, and the Windows console has
//! no equivalent that a test can drive without a new dependency. Hermetic: the
//! child gets a temporary config directory and touches nothing else.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use bifrost_ssh::domain::{Host, Hosts};
use bifrost_ssh::store::{HOSTS_FILE, Store};
use rustix::fs::{Mode, OFlags};
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

/// How long to wait for anything to happen before declaring a test failed.
const PATIENCE: Duration = Duration::from_secs(10);

const ESC: &[u8] = b"\x1b";
const CTRL_C: &[u8] = b"\x03";

/// What the terminal would show, rebuilt from the bytes the app wrote.
///
/// bifrost only positions the cursor with `ESC [ row ; col H`, styles text with
/// `ESC [ ... m`, clears with `ESC [ 2 J`, switches modes with `ESC [ ? ... h/l`
/// and asks for the clipboard with `ESC ] 52 ; ... BEL`. That is all this
/// understands; anything else is ignored.
struct Screen {
    rows: Vec<Vec<char>>,
    alt_screen: bool,
    cursor_visible: bool,
}

impl Screen {
    fn from_output(output: &[u8], height: usize, width: usize) -> Screen {
        let mut screen = Screen {
            rows: vec![vec![' '; width]; height],
            alt_screen: false,
            cursor_visible: true,
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

    fn clear(&mut self) {
        for row in &mut self.rows {
            row.fill(' ');
        }
    }

    fn lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|row| row.iter().collect::<String>().trim_end().to_string())
            .collect()
    }

    fn text(&self) -> String {
        self.lines().join("\n")
    }

    fn contains(&self, needle: &str) -> bool {
        self.lines().iter().any(|line| line.contains(needle))
    }

    fn is_blank(&self) -> bool {
        self.lines().iter().all(String::is_empty)
    }
}

/// Whether the raw output styles anything with a color (as opposed to bold,
/// dim, or a reset to the default color).
fn uses_color(output: &[u8]) -> bool {
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

/// A running `bifrost` with a pseudo-terminal as its stdin, stdout and stderr.
struct Session {
    child: Child,
    master: File,
    chunks: Receiver<Vec<u8>>,
    output: Vec<u8>,
    height: u16,
    width: u16,
}

impl Session {
    fn start(config_dir: &Path, height: u16, width: u16, env: &[(&str, &str)]) -> Session {
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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
        command
            .env("BIFROST_CONFIG_DIR", config_dir)
            .env("TERM", "xterm-256color")
            .env_remove("NO_COLOR")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        for (key, value) in env {
            command.env(key, value);
        }
        let child = command.spawn().expect("the bifrost binary should start");
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
            child,
            master: File::from(master),
            chunks,
            output: Vec::new(),
            height,
            width,
        }
    }

    fn screen(&self) -> Screen {
        // The grid is as large as the biggest terminal used, so that output
        // drawn before a resize still lands where it was drawn.
        Screen::from_output(
            &self.output,
            usize::from(self.height.max(24)),
            usize::from(self.width.max(80)),
        )
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).expect("send keys");
        self.master.flush().expect("flush keys");
    }

    fn resize(&mut self, height: u16, width: u16) {
        set_size(&self.master, height, width);
    }

    /// Reads output until `ready` is true of the screen, or fails the test.
    fn wait_until(&mut self, what: &str, ready: impl Fn(&Screen) -> bool) {
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
                     visible: {})",
                    screen.text(),
                    screen.alt_screen,
                    screen.cursor_visible
                ),
            }
        }
    }

    /// Waits for the process to exit and returns its status with everything it
    /// wrote.
    fn finish(mut self) -> (ExitStatus, Vec<u8>) {
        let deadline = Instant::now() + PATIENCE;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll the child") {
                break status;
            }
            assert!(Instant::now() < deadline, "bifrost did not exit");
            thread::sleep(Duration::from_millis(10));
        };
        // The reader thread ends when the pty closes; collect what is left.
        while let Ok(chunk) = self.chunks.recv_timeout(Duration::from_millis(500)) {
            self.output.extend(chunk);
        }
        let output = std::mem::take(&mut self.output);
        (status, output)
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

fn set_size(fd: &impl std::os::fd::AsFd, height: u16, width: u16) {
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
fn healthy_store() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut hosts = Hosts::new();
    hosts.add(Host::new("web", "192.0.2.1")).unwrap();
    hosts.add(Host::new("db", "192.0.2.2")).unwrap();
    Store::at(&config).save(&hosts).unwrap();
    (dir, config)
}

fn corrupt_store() -> (tempfile::TempDir, PathBuf) {
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
fn assert_restored(output: &[u8]) {
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

#[test]
fn opens_explains_a_broken_store_navigates_and_restores_the_terminal() {
    let (_dir, config) = corrupt_store();
    let mut session = Session::start(&config, 24, 80, &[]);

    session.wait_until("the home screen explaining the error", |s| {
        s.alt_screen
            && s.contains("Saved hosts: unknown")
            && s.contains("Error: Bifrost could not read your saved hosts.")
            && s.contains("hosts.toml.bak")
    });
    assert!(
        !session.screen().cursor_visible,
        "the cursor should be hidden"
    );

    session.send(b"?");
    session.wait_until("the help screen", |s| {
        s.contains("These keys work in Bifrost:") && s.contains("?/Esc close help")
    });

    // A lone Esc closes the help; it must not quit.
    session.send(ESC);
    session.wait_until("the home screen again", |s| {
        s.contains("Saved hosts: unknown") && !s.contains("These keys work")
    });

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

#[test]
fn ctrl_c_quits_and_restores_the_terminal() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the home screen", |s| {
        s.alt_screen && s.contains("Saved hosts: 2")
    });

    session.send(CTRL_C);
    let (status, output) = session.finish();

    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

#[test]
fn a_terminal_that_is_too_small_shows_a_message_and_still_quits() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 10, 40, &[]);

    session.wait_until("the size message", |s| {
        s.contains("Terminal too small (40x10).")
    });
    assert!(!session.screen().contains("Saved hosts"));

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

#[test]
fn a_resize_is_noticed_in_both_directions() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the home screen", |s| s.contains("Saved hosts: 2"));

    session.resize(10, 40);
    session.wait_until("the size message after shrinking", |s| {
        s.contains("Terminal too small (40x10).")
    });

    session.resize(24, 80);
    session.wait_until("the home screen after growing back", |s| {
        s.contains("Saved hosts: 2") && !s.contains("Terminal too small")
    });

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

/// Runs to the home screen and quits; returns everything the app wrote.
fn output_of_a_quick_session(env: &[(&str, &str)]) -> Vec<u8> {
    let (_dir, config) = corrupt_store();
    let mut session = Session::start(&config, 24, 80, env);
    session.wait_until("the home screen", |s| s.contains("Error:"));
    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    output
}

#[test]
fn the_default_theme_uses_colors() {
    // Guards the NO_COLOR test below: without this it could pass vacuously.
    assert!(uses_color(&output_of_a_quick_session(&[])));
}

/// What the user sees under `NO_COLOR`: no color anywhere, and the meaning
/// intact.
///
/// This checks the end result, not which layer produced it: crossterm also
/// strips color when `NO_COLOR` is set, so this test alone would pass even if
/// Bifrost's own `Theme::from_env` ignored the variable. The theme's part (gray
/// text becomes dim, so it stays distinguishable once color is gone) is covered
/// by the unit tests in `tui/theme.rs` and `tui/ui.rs`.
#[test]
fn no_color_removes_every_color_from_the_output() {
    let output = output_of_a_quick_session(&[("NO_COLOR", "1")]);
    assert!(!uses_color(&output));
    // The meaning survives without color: the label is text.
    assert!(String::from_utf8_lossy(&output).contains("Error:"));
    assert_restored(&output);
}

#[test]
fn searching_filters_the_list_live_and_esc_brings_everything_back() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("both hosts listed", |s| {
        s.contains("db") && s.contains("192.0.2.1") && s.contains("192.0.2.2")
    });

    session.send(b"/");
    session.wait_until("the search box", |s| s.contains("Search:"));
    session.send(b"we");
    session.wait_until("only web left", |s| {
        s.contains("Search: we") && s.contains("192.0.2.1") && !s.contains("192.0.2.2")
    });
    // Typed letters are text, not commands: nothing quit, nothing changed.
    session.send(b"q");
    session.wait_until("q typed into the search", |s| s.contains("Search: weq"));
    assert!(session.screen().contains("No hosts match"));

    session.send(ESC);
    session.wait_until("everything back", |s| {
        !s.contains("Search:") && s.contains("192.0.2.1") && s.contains("192.0.2.2")
    });

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

#[test]
fn f_saves_the_favorite_to_disk_through_the_real_store() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));

    // Alphabetical: db is selected first.
    session.send(b"f");
    session.wait_until("the confirmation", |s| {
        s.contains("'db' is now a favorite.")
    });
    // The favorite moved to the top and carries its marker.
    session.wait_until("the marker", |s| s.contains("* db"));

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);

    let store = Store::at(&config);
    let loaded = store.load().unwrap();
    assert!(loaded.hosts.get("db").unwrap().favorite, "saved to disk");
    assert!(!loaded.hosts.get("web").unwrap().favorite);
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    assert!(store.backup_path().exists(), "the previous version is kept");
}

const CTRL_S: &[u8] = b"\x13";
const TAB: &[u8] = b"\t";

#[test]
fn adding_a_host_through_the_form_saves_it_to_disk() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));
    assert!(
        !session.screen().cursor_visible,
        "no text cursor on the list"
    );

    session.send(b"a");
    session.wait_until("the form with a visible text cursor", |s| {
        s.contains("Add host")
            && s.contains("A short label for this connection")
            && s.cursor_visible
    });

    session.send(b"app");
    session.send(TAB);
    session.send(b"app.example.com");
    session.wait_until("the typed values", |s| {
        s.contains("app") && s.contains("app.example.com")
    });
    session.send(CTRL_S);
    session.wait_until("the confirmation and the list again", |s| {
        s.contains("Added host 'app'.") && s.contains("Saved hosts: 3") && !s.cursor_visible
    });

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);

    let loaded = Store::at(&config).load().unwrap();
    assert_eq!(loaded.hosts.get("app").unwrap().hostname, "app.example.com");
    assert_eq!(loaded.hosts.len(), 3);
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
}

#[test]
fn a_blocked_save_writes_nothing_and_leaving_asks_before_discarding() {
    let (_dir, config) = healthy_store();
    let before = std::fs::read(config.join(HOSTS_FILE)).unwrap();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));

    session.send(b"a");
    session.wait_until("the form", |s| s.contains("Add host"));
    session.send(b"bad name");
    session.send(CTRL_S);
    session.wait_until("the blocked save explained", |s| {
        s.contains("Fix the fields marked with an error before saving.")
            && s.contains("Name may only contain letters")
    });

    session.send(ESC);
    session.wait_until("the question", |s| {
        s.contains("Discard changes?") && s.contains("You have unsaved changes.")
    });
    session.send(b"n");
    session.wait_until("back to editing with the input kept", |s| {
        !s.contains("Discard changes?") && s.contains("bad name")
    });

    session.send(ESC);
    session.wait_until("the question again", |s| s.contains("Discard changes?"));
    session.send(b"y");
    session.wait_until("the list again", |s| {
        s.contains("Saved hosts: 2") && !s.contains("Add host")
    });

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
    assert_eq!(
        std::fs::read(config.join(HOSTS_FILE)).unwrap(),
        before,
        "nothing was written"
    );
}

/// The clipboard request the app sends for `command`, as it appears on the wire.
fn clipboard_request(command: &str) -> Vec<u8> {
    bifrost_ssh::tui::clipboard::osc52(command)
        .expect("a command without control characters can be copied")
        .into_bytes()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn deleting_a_host_needs_its_name_and_removes_it_from_disk() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));

    // Alphabetical: db is selected.
    session.send(b"d");
    session.wait_until("the confirmation", |s| {
        s.contains("Delete host 'db'?")
            && s.contains("Type the host name to confirm:")
            && s.cursor_visible
    });

    // Cancelling changes nothing.
    session.send(ESC);
    session.wait_until("back on the list", |s| {
        !s.contains("Type the host name") && s.contains("Saved hosts: 2")
    });
    assert!(Store::at(&config).load().unwrap().hosts.get("db").is_some());

    // A wrong name is refused, in words.
    session.send(b"d");
    session.wait_until("the confirmation again", |s| {
        s.contains("Type the host name")
    });
    session.send(b"wrong\r");
    session.wait_until("the mismatch explained", |s| {
        s.contains("That is not the host's name.")
    });
    assert!(Store::at(&config).load().unwrap().hosts.get("db").is_some());
    session.send(ESC);
    session.wait_until("back on the list", |s| !s.contains("Type the host name"));

    // The exact name deletes it.
    session.send(b"d");
    session.wait_until("the confirmation once more", |s| {
        s.contains("Type the host name")
    });
    session.send(b"db\r");
    session.wait_until("the deletion confirmed", |s| {
        s.contains("Deleted host 'db'.") && s.contains("Saved hosts: 1") && !s.cursor_visible
    });

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);

    let store = Store::at(&config);
    let loaded = store.load().unwrap();
    assert!(loaded.hosts.get("db").is_none(), "deleted from disk");
    assert!(loaded.hosts.get("web").is_some());
    assert!(store.backup_path().exists(), "the previous version is kept");
}

#[test]
fn a_host_that_others_jump_through_cannot_be_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut client = Host::new("client", "192.0.2.2");
    client.proxy_jump = Some("bastion".to_string());
    let hosts = Hosts::from_vec(vec![Host::new("bastion", "192.0.2.1"), client]).unwrap();
    Store::at(&config).save(&hosts).unwrap();

    let mut session = Session::start(&config, 24, 100, &[]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));
    // Alphabetical: bastion is selected first.
    session.send(b"d");
    session.wait_until("the refusal", |s| {
        s.contains("Host 'bastion' is the jump host of 'client'.")
    });
    assert!(!session.screen().contains("Type the host name"));

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
    assert!(
        Store::at(&config)
            .load()
            .unwrap()
            .hosts
            .get("bastion")
            .is_some()
    );
}

#[test]
fn c_shows_the_command_and_sends_the_clipboard_request_to_the_terminal() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));

    // Alphabetical: db is selected; it has neither user nor port.
    session.send(b"c");
    session.wait_until("the command on screen", |s| {
        s.contains("ssh command for 'db'")
            && s.contains("ssh -- 192.0.2.2")
            && s.contains("Copy requested")
    });
    assert!(
        !session.screen().contains("Copied"),
        "the app cannot know it worked, so it must not say so"
    );

    session.send(b"x"); // any key closes it
    session.wait_until("the list again", |s| {
        !s.contains("ssh command for") && s.contains("Saved hosts: 2")
    });

    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);

    let request = clipboard_request("ssh -- 192.0.2.2");
    assert!(
        contains_bytes(&output, &request),
        "the OSC 52 request should have been written to the terminal"
    );
    // Once: closing the panel does not ask again.
    let count = output
        .windows(request.len())
        .filter(|w| *w == &request[..])
        .count();
    assert_eq!(count, 1);
}

#[test]
fn nothing_is_sent_to_the_clipboard_unless_c_is_pressed() {
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));
    session.send(b"jkfq");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert!(
        !contains_bytes(&output, b"\x1b]52;"),
        "no clipboard request without an explicit copy"
    );
}
