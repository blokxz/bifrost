//! Running the real `bifrost <host>` against a fake ssh, on any platform.
//!
//! The command line path needs no terminal, so these tests run on Windows too.
//! Hermetic: the child's `PATH` (and, on Windows, `SystemRoot`) point at
//! temporary directories, so the real ssh is never found, and its home and
//! config directories are temporary as well.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

use bifrost_ssh::domain::{Host, Hosts};
use bifrost_ssh::store::Store;

/// Held while a file is written or a process is started. A forked child that has
/// not yet run `exec` holds every file another thread has open for writing, and
/// executing such a file then fails with "text file busy"; with tests running in
/// parallel that happens between one test installing its fake ssh and another
/// starting bifrost. So both take this lock, and nothing is started while a
/// fake is being written.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn serialize_spawns() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The fake, compiled once per test run.
fn compiled_fake() -> &'static Path {
    static FAKE: OnceLock<PathBuf> = OnceLock::new();
    FAKE.get_or_init(|| {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cli_support/fake_ssh.rs");
        let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(&out_dir).unwrap();
        // One name per process: two test binaries may run at once.
        let out = out_dir.join(format!(
            "fake_ssh_{}{}",
            std::process::id(),
            std::env::consts::EXE_SUFFIX
        ));
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let status = Command::new(rustc)
            .args(["--edition", "2021", "-o"])
            .arg(&out)
            .arg(&source)
            .status()
            .expect("run rustc to build the fake ssh");
        assert!(status.success(), "the fake ssh did not compile");
        out
    })
}

/// A directory tree holding fake `ssh` and `ssh-keygen`, in the place bifrost
/// looks for them, and a home and config directory of their own.
pub struct World {
    dir: tempfile::TempDir,
}

impl World {
    /// No programs yet: `install` adds them.
    pub fn new() -> World {
        let world = World {
            dir: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir_all(world.bin_dir()).unwrap();
        std::fs::create_dir_all(world.home()).unwrap();
        world
    }

    /// Where bifrost looks for ssh: the system OpenSSH directory under
    /// `SystemRoot` on Windows, a `PATH` entry elsewhere.
    fn bin_dir(&self) -> PathBuf {
        if cfg!(windows) {
            self.dir.path().join("Windows/System32/OpenSSH")
        } else {
            self.dir.path().join("bin")
        }
    }

    pub fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    pub fn known_hosts(&self) -> PathBuf {
        self.home().join(".ssh").join("known_hosts")
    }

    pub fn config_dir(&self) -> PathBuf {
        self.dir.path().join("config")
    }

    fn program(&self, name: &str) -> PathBuf {
        self.bin_dir()
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
    }

    /// Installs a fake `name` that runs `script` (see `fake_ssh.rs`).
    pub fn install(&self, name: &str, script: &[&str]) {
        let _serialized = serialize_spawns();
        std::fs::create_dir_all(self.bin_dir()).unwrap();
        std::fs::copy(compiled_fake(), self.program(name)).unwrap();
        std::fs::write(
            self.program(name).with_extension("script"),
            script.join("\n"),
        )
        .unwrap();
    }

    /// The path the fake `name` was started as, and its arguments, if it was.
    pub fn started(&self, name: &str) -> Option<(PathBuf, Vec<String>)> {
        let log = std::fs::read_to_string(self.program(name).with_extension("log")).ok()?;
        let mut lines = log.lines().map(str::to_string);
        Some((PathBuf::from(lines.next()?), lines.collect()))
    }

    pub fn installed_path(&self, name: &str) -> PathBuf {
        self.program(name)
    }

    /// Saves `hosts` in the config directory.
    pub fn save(&self, hosts: Vec<Host>) {
        Store::at(self.config_dir())
            .save(&Hosts::from_vec(hosts).unwrap())
            .unwrap();
    }

    /// `bifrost` with a clean environment pointing at this world.
    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
        if cfg!(windows) {
            // Windows programs need much of the environment to start; replace
            // only what decides where things are found.
            command
                .env("SystemRoot", self.dir.path().join("Windows"))
                .env("PATH", self.dir.path().join("empty"))
                .env("USERPROFILE", self.home());
        } else {
            command
                .env_clear()
                .env("PATH", self.dir.path().join("bin"))
                .env("HOME", self.home())
                .env("TERM", "xterm-256color");
        }
        command
            .env("BIFROST_CONFIG_DIR", self.config_dir())
            .env_remove("NO_COLOR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Starts `command` (which must have come from [`World::command`]).
    pub fn spawn(&self, command: &mut Command) -> Child {
        let _serialized = serialize_spawns();
        command.spawn().expect("start bifrost")
    }

    /// Runs `command` to the end and collects what it printed.
    pub fn output(&self, command: &mut Command) -> Output {
        self.spawn(command)
            .wait_with_output()
            .expect("wait for bifrost")
    }

    /// Runs `bifrost args...` to the end.
    pub fn run(&self, args: &[&str]) -> Output {
        self.output(self.command().args(args))
    }
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Whether two paths are the same file as ssh would see them, ignoring how the
/// platform spells them.
pub fn same_path(a: &Path, b: &Path) -> bool {
    let normal = |p: &Path| {
        let text = p.to_string_lossy().replace('\\', "/");
        if cfg!(windows) {
            text.to_ascii_lowercase()
        } else {
            text
        }
    };
    normal(a) == normal(b)
}
