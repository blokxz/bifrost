//! `ssh::connect::run` with fake programs: what it reports and what it passes on.
//!
//! No terminal is involved (the fakes' stdin and stdout are whatever the test
//! harness gives them) and no real ssh: the "ssh" is a shell script. Unix only
//! for now; the Windows equivalent needs a compiled fake `ssh.exe`.

#![cfg(unix)]

mod support;

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bifrost_ssh::domain::{Host, Hosts};
use bifrost_ssh::ssh::command::{SshArgs, build_args};
use bifrost_ssh::ssh::connect::{Exit, RETAINED, run};

/// A writer whose contents the test can read back after `run` took ownership.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

/// Every call to `run` goes through here: even one that fails to start forks
/// first, and the child of that fork can briefly hold another test's half-written
/// script open, which makes executing it fail with "text file busy".
fn run_locked(
    program: &std::path::Path,
    args: &SshArgs,
    tee: impl Write + Send + 'static,
) -> io::Result<bifrost_ssh::ssh::connect::Outcome> {
    run_locked_timed(program, args, tee).map(|(outcome, _)| outcome)
}

/// [`run_locked`], and how long `run` itself took. The clock starts once the lock
/// is held: waiting for another test's turn is not the run's time.
fn run_locked_timed(
    program: &std::path::Path,
    args: &SshArgs,
    tee: impl Write + Send + 'static,
) -> io::Result<(bifrost_ssh::ssh::connect::Outcome, Duration)> {
    let _serialized = support::serialize_spawns();
    let started = Instant::now();
    let outcome = run(program, args, tee)?;
    Ok((outcome, started.elapsed()))
}

fn args() -> SshArgs {
    let host = Host::new("web", "192.0.2.1");
    build_args(&host, &Hosts::from_vec(vec![host.clone()]).unwrap()).unwrap()
}

/// A script that stands in for ssh.
fn fake(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("ssh");
    support::write_script(&path, &format!("#!/bin/sh\n{body}\n"), 0o755);
    path
}

fn run_fake(body: &str) -> (bifrost_ssh::ssh::connect::Outcome, Vec<u8>) {
    let (outcome, tee, _) = run_fake_timed(body);
    (outcome, tee)
}

/// [`run_fake`], and how long the run took, not counting writing the fake or
/// waiting for the spawn lock.
fn run_fake_timed(body: &str) -> (bifrost_ssh::ssh::connect::Outcome, Vec<u8>, Duration) {
    let dir = tempfile::tempdir().unwrap();
    let program = fake(&dir, body);
    let tee = Capture::default();
    let (outcome, took) =
        run_locked_timed(&program, &args(), tee.clone()).expect("the fake should run");
    (outcome, tee.bytes(), took)
}

#[test]
fn the_exit_code_is_reported_as_it_is() {
    for code in [0, 1, 2, 130, 255] {
        let (outcome, _) = run_fake(&format!("exit {code}"));
        assert_eq!(outcome.exit, Exit::Code(code));
        assert!(!outcome.was_interrupted());
    }
}

#[test]
fn a_signal_is_told_apart_from_an_exit_code() {
    let (outcome, _) = run_fake("kill -9 $$");
    assert_eq!(outcome.exit, Exit::Signal(9));
    assert!(!outcome.was_interrupted());

    let (outcome, _) = run_fake("kill -INT $$");
    assert_eq!(outcome.exit, Exit::Signal(2));
    assert!(outcome.was_interrupted());
}

#[test]
fn stderr_is_kept_and_passed_on_unaltered() {
    let (outcome, tee) = run_fake(
        r#"printf 'first line\n' >&2
printf '\033[31mred\033[0m and \342\200\256bidi\n' >&2
exit 255"#,
    );
    let expected = b"first line\n\x1b[31mred\x1b[0m and \xe2\x80\xaebidi\n";
    assert_eq!(outcome.stderr, expected, "kept for the explanation, raw");
    assert_eq!(tee, expected, "the copy for the user is byte for byte");
}

#[test]
fn stdout_is_not_captured() {
    let (outcome, tee) = run_fake("echo to-the-terminal\nexit 0");
    assert!(outcome.stderr.is_empty());
    assert!(tee.is_empty());
}

#[test]
fn only_the_end_of_a_very_long_stderr_is_kept() {
    // Well over the limit, ending with a line that has to survive.
    let (outcome, tee) = run_fake(
        r#"i=0
while [ $i -lt 3000 ]; do
  printf 'noise noise noise noise noise noise noise noise noise noise\n' >&2
  i=$((i + 1))
done
printf 'the reason ssh gave up\n' >&2
exit 255"#,
    );
    assert_eq!(outcome.stderr.len(), RETAINED);
    assert!(outcome.stderr.ends_with(b"the reason ssh gave up\n"));
    assert!(tee.len() > RETAINED, "the user still got all of it");
    assert!(tee.ends_with(b"the reason ssh gave up\n"));
}

#[test]
fn stderr_that_is_not_utf8_is_kept_as_bytes() {
    let (outcome, _) = run_fake("printf '\\377\\376 not utf-8\\n' >&2\nexit 255");
    assert_eq!(outcome.stderr, b"\xff\xfe not utf-8\n");
}

#[test]
fn a_process_that_outlives_ssh_with_the_pipe_open_does_not_hold_run_up() {
    let (outcome, _, took) =
        run_fake_timed("sleep 5 >/dev/null </dev/null &\nprintf 'done\\n' >&2\nexit 0");
    assert_eq!(outcome.exit, Exit::Code(0));
    assert_eq!(outcome.stderr, b"done\n");
    assert!(took < Duration::from_secs(3), "took {took:?}");
}

#[test]
fn the_arguments_reach_the_program_as_they_are_with_the_destination_last() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("argv");
    let program = fake(
        &dir,
        &format!(
            "for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'",
            log.display()
        ),
    );
    let mut host = Host::new("web", "192.0.2.1");
    host.user = Some("deploy".to_string());
    host.port = Some(2222);
    let args = build_args(&host, &Hosts::from_vec(vec![host.clone()]).unwrap()).unwrap();

    run_locked(&program, &args, Capture::default()).unwrap();

    assert_eq!(
        std::fs::read_to_string(log).unwrap(),
        "-l\ndeploy\n-p\n2222\n--\n192.0.2.1\n"
    );
}

#[test]
fn a_program_that_cannot_start_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-ssh");
    let err = run_locked(&missing, &args(), Capture::default()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn a_program_that_is_not_executable_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh");
    support::write_script(&path, "#!/bin/sh\nexit 0\n", 0o644);
    let err = run_locked(&path, &args(), Capture::default()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
}
