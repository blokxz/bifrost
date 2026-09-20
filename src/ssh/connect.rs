//! Running ssh attached to the user's terminal.
//!
//! [`run`] starts the program with an argument vector (never through a shell),
//! gives it the real stdin and stdout, and waits. Its stderr goes through a pipe
//! so that two things can happen at once: every byte is passed on to the real
//! stderr as it arrives (so the user sees ssh's own messages, unaltered), and the
//! last [`RETAINED`] bytes are kept for [`Outcome`], which is what later lets
//! Bifrost explain a failure.
//!
//! This module prints nothing itself and does not touch raw mode or the
//! alternate screen: giving the terminal away and taking it back is the
//! caller's job (see `tui::handover`). What it does own is what must hold while
//! ssh runs, whoever the caller is:
//!
//! - Ctrl-C reaching Bifrost's process group does not kill Bifrost
//!   ([`super::interrupt`]).
//! - The terminal's modes are back as they were when ssh ends, even if ssh
//!   died without restoring them ([`super::tty`]).
//! - ssh never outlives a failure or panic in Bifrost ([`ChildGuard`]).
//! - A process that inherited the stderr pipe and outlives ssh (a
//!   `ControlPersist` master) cannot make Bifrost wait forever.

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use super::command::SshArgs;
use super::interrupt;
use super::tty::SavedModes;

/// How much of ssh's stderr is kept: the end of it, which is where ssh puts the
/// reason it gave up.
pub const RETAINED: usize = 64 * 1024;

/// How long to wait for the end of ssh's stderr once ssh itself has ended. It
/// arrives at once unless another process still holds the pipe open.
const STDERR_GRACE: Duration = Duration::from_millis(200);

/// How the ssh process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// It exited with this status. ssh uses 255 for its own failures; any other
    /// value is the exit status of the remote session or command.
    Code(i32),
    /// It was ended by this signal. Only happens on Unix.
    Signal(i32),
}

/// The Windows exit status of a process that was ended by Ctrl-C.
#[cfg(windows)]
const STATUS_CONTROL_C_EXIT: i32 = 0xC000_013Au32 as i32;

/// What happened while ssh ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit: Exit,
    /// The end of what ssh wrote to stderr, at most [`RETAINED`] bytes. Raw:
    /// it may hold anything, including control characters, and must be
    /// sanitized before it is shown.
    pub stderr: Vec<u8>,
    /// Ctrl-C reached Bifrost while ssh ran.
    pub interrupted: bool,
}

impl Outcome {
    /// Whether the user cancelled with Ctrl-C.
    pub fn was_interrupted(&self) -> bool {
        #[cfg(windows)]
        if self.exit == Exit::Code(STATUS_CONTROL_C_EXIT) {
            return true;
        }
        self.interrupted || self.exit == Exit::Signal(SIGINT)
    }
}

/// SIGINT is 2 on every Unix Bifrost supports.
const SIGINT: i32 = 2;

/// Runs `program` with `args` on the real terminal and waits for it.
///
/// `tee` receives everything ssh writes to stderr, as it is written, on another
/// thread. Failing to write to it is ignored: losing a copy for the user must
/// not fail the connection.
///
/// Because it is written to from another thread, it must not need anything the
/// calling thread holds while it waits in here. Rust's `io::stderr()` is the
/// case that bites: a caller that holds `io::stderr().lock()` makes every write
/// through `io::stderr()` on another thread wait for it, forever.
pub fn run(
    program: &Path,
    args: &SshArgs,
    mut tee: impl Write + Send + 'static,
) -> io::Result<Outcome> {
    interrupt::arm()?;
    // A stale flag would look like a Ctrl-C during this connection.
    interrupt::take();
    let modes = SavedModes::capture();

    let mut child = ChildGuard::spawn(
        Command::new(program)
            .args(args.as_slice())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped()),
    )?;
    let mut stderr = child.take_stderr()?;

    let tail = Arc::new(Mutex::new(Tail::default()));
    let (ended, stderr_ended) = mpsc::channel();
    let reader_tail = Arc::clone(&tail);
    thread::Builder::new()
        .name("ssh-stderr".to_string())
        .spawn(move || {
            let mut buffer = [0; 4096];
            loop {
                match stderr.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = tee.write_all(&buffer[..n]).and_then(|()| tee.flush());
                        reader_tail
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(&buffer[..n]);
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = ended.send(());
        })?;

    let status = child.wait();
    // Before anything else: the terminal must be usable again whatever happened.
    modes.restore();
    let status = status?;

    // Normally the end of stderr is already here. If another process kept the
    // pipe open, stop waiting; the reader thread is left behind and ends with
    // that process.
    let _ = stderr_ended.recv_timeout(STDERR_GRACE);
    let stderr = tail
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .bytes
        .clone();

    Ok(Outcome {
        exit: exit_of(status),
        stderr,
        interrupted: interrupt::take(),
    })
}

fn exit_of(status: ExitStatus) -> Exit {
    if let Some(code) = status.code() {
        return Exit::Code(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return Exit::Signal(signal);
        }
    }
    // Not reachable on Unix without job-control stops, which `wait` does not
    // report, and Windows always has a code.
    Exit::Code(255)
}

/// The last [`RETAINED`] bytes written.
#[derive(Debug, Default)]
struct Tail {
    bytes: Vec<u8>,
}

impl Tail {
    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() > RETAINED {
            let excess = self.bytes.len() - RETAINED;
            self.bytes.drain(..excess);
        }
    }
}

/// A running child that is killed and reaped if it is dropped while still
/// running: an error or a panic in Bifrost must not leave ssh alive, reading
/// the terminal that the shell has taken back.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        command.spawn().map(|child| ChildGuard(Some(child)))
    }

    fn take_stderr(&mut self) -> io::Result<std::process::ChildStderr> {
        self.0
            .as_mut()
            .and_then(|child| child.stderr.take())
            .ok_or_else(|| io::Error::other("the child's stderr was not captured"))
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let child = self
            .0
            .as_mut()
            .ok_or_else(|| io::Error::other("the child was already waited for"))?;
        let status = child.wait()?;
        self.0 = None;
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tail_keeps_everything_while_it_fits() {
        let mut tail = Tail::default();
        tail.push(b"one ");
        tail.push(b"two");
        assert_eq!(tail.bytes, b"one two");
    }

    #[test]
    fn the_tail_keeps_only_the_last_bytes() {
        let mut tail = Tail::default();
        tail.push(&vec![b'a'; RETAINED]);
        tail.push(b"end");
        assert_eq!(tail.bytes.len(), RETAINED);
        assert!(tail.bytes.ends_with(b"aend"));
        assert!(tail.bytes.starts_with(b"aaaa"));
    }

    #[test]
    fn one_chunk_larger_than_the_limit_is_cut_from_the_front() {
        let mut tail = Tail::default();
        let mut chunk = vec![b'x'; RETAINED + 10];
        chunk.extend_from_slice(b"tail");
        tail.push(&chunk);
        assert_eq!(tail.bytes.len(), RETAINED);
        assert!(tail.bytes.ends_with(b"xtail"));
    }

    #[test]
    fn interrupted_by_flag_or_by_signal() {
        let outcome = |exit, interrupted| Outcome {
            exit,
            stderr: Vec::new(),
            interrupted,
        };
        assert!(outcome(Exit::Code(255), true).was_interrupted());
        assert!(outcome(Exit::Signal(SIGINT), false).was_interrupted());
        assert!(!outcome(Exit::Signal(9), false).was_interrupted());
        assert!(!outcome(Exit::Code(255), false).was_interrupted());
        assert!(!outcome(Exit::Code(0), false).was_interrupted());
    }

    /// A dropped guard must take the child with it. The child is `sleep`, and
    /// the proof is its stdout pipe: it closes only when the process is gone.
    #[cfg(unix)]
    #[test]
    fn dropping_the_guard_kills_a_running_child() {
        let mut command = Command::new("sleep");
        command.arg("30").stdout(Stdio::piped());
        let mut guard = ChildGuard::spawn(&mut command).unwrap();
        let mut stdout = guard.0.as_mut().unwrap().stdout.take().unwrap();

        // A panic unwinding through the guard is the case that matters.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = guard;
            panic!("Bifrost failed while ssh was running");
        }));
        assert!(result.is_err());

        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).unwrap(); // returns only once sleep is gone
        assert!(rest.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_finished_child_is_not_killed_again() {
        let mut command = Command::new("true");
        let mut guard = ChildGuard::spawn(&mut command).unwrap();
        assert!(guard.wait().unwrap().success());
        assert!(guard.0.is_none());
        assert!(guard.wait().is_err(), "waiting twice is refused, not hung");
    }

    #[cfg(unix)]
    #[test]
    fn exit_status_and_signal_are_told_apart() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_of(ExitStatus::from_raw(0)), Exit::Code(0));
        assert_eq!(exit_of(ExitStatus::from_raw(255 << 8)), Exit::Code(255));
        assert_eq!(exit_of(ExitStatus::from_raw(2)), Exit::Signal(2));
        assert_eq!(exit_of(ExitStatus::from_raw(9)), Exit::Signal(9));
    }
}
