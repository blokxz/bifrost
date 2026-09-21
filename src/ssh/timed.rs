//! Running a program that is given a deadline.
//!
//! Two things Bifrost asks of ssh's tools are not allowed to wait for good: `ssh-add
//! -l` (a forwarded agent whose connection died) and `ssh -G` (which runs the
//! `Match exec` commands of the user's config, and one of those can hang). The
//! screen is waiting for the answer, and it has no way to be interrupted, so the
//! wait has to end by itself.
//!
//! [`output_within`] runs the program with no input and its output captured. If it
//! has not finished by the deadline it is killed **with everything it started**: on
//! Unix the program is put in a process group of its own and the whole group is
//! killed, because what hangs is usually a command that the program started (a
//! `Match exec`), and killing only the program would leave that command running,
//! holding the output open, one more each time. On Windows only the program itself
//! is killed.
//!
//! The output is read on other threads, so a command that keeps a pipe open after
//! the program has gone cannot keep this waiting: a moment is given for the rest
//! of the output and then what there is, is used.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// How often to look at whether the program has finished.
const POLL: Duration = Duration::from_millis(10);

/// How long to wait for the end of the output once the program itself has ended.
/// It arrives at once unless something else still holds the pipe.
const OUTPUT_GRACE: Duration = Duration::from_millis(300);

/// A program that ended by itself.
#[derive(Debug)]
pub struct Finished {
    pub status: ExitStatus,
    /// At most the limit given, raw.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// How running it went.
#[derive(Debug)]
pub enum Timed {
    Finished(Finished),
    /// It had not finished by the deadline and was killed.
    TimedOut,
}

/// Runs `command` with no input and its output captured (at most `limit` bytes of
/// each stream), and waits for it for at most `timeout`.
///
/// An error is only for a program that could not be started or waited for.
pub fn output_within(command: &mut Command, timeout: Duration, limit: u64) -> io::Result<Timed> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own group, so that a timeout can end what it started as well.
        command.process_group(0);
    }
    let mut child = command.spawn()?;

    let (ended, receiver) = mpsc::channel::<()>();
    let mut streams = Vec::new();
    if let Some(pipe) = child.stdout.take() {
        streams.push(read_in_background(pipe, limit, ended.clone()));
    }
    if let Some(pipe) = child.stderr.take() {
        streams.push(read_in_background(pipe, limit, ended.clone()));
    }
    drop(ended);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
            Ok(None) => {
                kill_with_everything_it_started(&mut child);
                return Ok(Timed::TimedOut);
            }
            Err(err) => {
                kill_with_everything_it_started(&mut child);
                return Err(err);
            }
        }
    };

    // Normally both streams have ended already. If something still holds a pipe,
    // stop waiting for it after a moment and use what has arrived.
    let grace_ends = Instant::now() + OUTPUT_GRACE;
    for _ in 0..streams.len() {
        let left = grace_ends.saturating_duration_since(Instant::now());
        if receiver.recv_timeout(left).is_err() {
            break;
        }
    }
    let mut collected = streams
        .iter()
        .map(|bytes| bytes.lock().unwrap_or_else(PoisonError::into_inner).clone());
    // The streams were pushed in order: standard output, then standard error.
    let stdout = collected.next().unwrap_or_default();
    let stderr = collected.next().unwrap_or_default();
    Ok(Timed::Finished(Finished {
        status,
        stdout,
        stderr,
    }))
}

/// Ends the program and, on Unix, its whole process group, then reaps it. What
/// went wrong in doing so is ignored: the program is not going to answer anyway.
fn kill_with_everything_it_started(child: &mut Child) {
    #[cfg(unix)]
    {
        use rustix::process::{Pid, Signal, kill_process_group};
        if let Some(group) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) {
            let _ = kill_process_group(group, Signal::KILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Reads `pipe` on another thread, at most `limit` bytes, into what is returned as
/// it arrives, and says on `ended` when the stream is over.
fn read_in_background(
    pipe: impl Read + Send + 'static,
    limit: u64,
    ended: mpsc::Sender<()>,
) -> Arc<Mutex<Vec<u8>>> {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&bytes);
    thread::spawn(move || {
        let mut pipe = pipe.take(limit);
        let mut chunk = [0; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => shared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(&chunk[..n]),
            }
        }
        let _ = ended.send(());
    });
    bytes
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::Path;

    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        command
    }

    fn finished(timed: Timed) -> Finished {
        match timed {
            Timed::Finished(finished) => finished,
            Timed::TimedOut => panic!("it timed out"),
        }
    }

    fn alive(pid: &str) -> bool {
        Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn what_a_program_prints_and_how_it_ended_come_back() {
        let done = finished(
            output_within(
                &mut sh("echo out; echo err >&2; exit 3"),
                Duration::from_secs(5),
                1024,
            )
            .unwrap(),
        );
        assert_eq!(done.status.code(), Some(3));
        assert_eq!(done.stdout, b"out\n");
        assert_eq!(done.stderr, b"err\n");
    }

    #[test]
    fn a_program_that_never_finishes_is_killed_at_the_deadline_and_says_so() {
        let started = Instant::now();
        let timed = output_within(&mut sh("sleep 30"), Duration::from_millis(300), 1024).unwrap();
        assert!(matches!(timed, Timed::TimedOut));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(300),
            "gave up early: {waited:?}"
        );
        assert!(waited < Duration::from_secs(5), "took too long: {waited:?}");
    }

    #[test]
    fn what_the_program_started_is_killed_with_it() {
        // The shape of a Match exec: the program starts a command, and it is the
        // command that hangs. Killing only the program would leave it running.
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 30 & echo $! > '{}'; wait", pid_file.display());
        let timed = output_within(&mut sh(&script), Duration::from_millis(500), 1024).unwrap();
        assert!(matches!(timed, Timed::TimedOut));
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .to_string();
        assert!(!pid.is_empty());
        // Given a moment to be reaped.
        let gone = (0..50).any(|_| {
            thread::sleep(Duration::from_millis(20));
            !alive(&pid)
        });
        assert!(
            gone,
            "the command the program started (pid {pid}) is still running"
        );
    }

    #[test]
    fn a_command_that_keeps_the_output_open_does_not_keep_the_wait_going() {
        // The program is done at once, but what it started holds its output.
        let started = Instant::now();
        let done = finished(
            output_within(
                &mut sh("echo hello; sleep 3 & exit 0"),
                Duration::from_secs(10),
                1024,
            )
            .unwrap(),
        );
        assert_eq!(done.status.code(), Some(0));
        assert_eq!(done.stdout, b"hello\n");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited for the pipe: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_program_gets_no_input_and_cannot_wait_for_any() {
        let done = finished(
            output_within(&mut sh("cat; echo done"), Duration::from_secs(5), 1024).unwrap(),
        );
        assert_eq!(done.stdout, b"done\n");
    }

    #[test]
    fn only_the_limit_of_each_stream_is_kept() {
        let done = finished(
            output_within(
                &mut sh("head -c 100000 /dev/zero | tr '\\0' x; echo done >&2"),
                Duration::from_secs(5),
                100,
            )
            .unwrap(),
        );
        assert_eq!(done.stdout.len(), 100);
        assert_eq!(done.stderr, b"done\n");
    }

    #[test]
    fn a_program_that_cannot_be_started_is_an_error_not_a_timeout() {
        let mut command = Command::new(Path::new("/nonexistent/program"));
        assert!(output_within(&mut command, Duration::from_secs(1), 10).is_err());
    }
}
