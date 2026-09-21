//! Handing the terminal to a program and taking it back: ssh for a connection,
//! and the tools that ask for a passphrase themselves (`ssh-keygen`, `ssh-add`),
//! so that Bifrost never sees one.
//!
//! The sequence, for every program and every way it can end:
//!
//! 1. Leave TUI mode ([`TerminalGuard::suspend`]): cursor shown, alternate
//!    screen left, raw mode off. Everything ssh writes lands on the user's
//!    normal screen and stays in their scrollback.
//! 2. Say what is about to happen in one line, so ssh's output does not run
//!    into whatever was on the screen before.
//! 3. Run ssh. Bifrost is blocked in `wait`: it draws nothing and reads no
//!    input, so every key typed goes to ssh.
//! 4. Take TUI mode back ([`TerminalGuard::resume`]), whatever happened in 3.
//! 5. Throw away input typed while ssh ran that ssh did not read. It would
//!    otherwise arrive as commands: a `q` typed as ssh exited would quit.
//!
//! A panic in step 3 unwinds with the terminal already in its normal state (the
//! guard is suspended), and the child is killed by its own guard, so the shell
//! gets a working terminal and no stray ssh.

use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use ratatui::crossterm::event;

use super::app::{ConnectRequest, HandoverResult};
use super::terminal::{TerminalGuard, TerminalOps};
use crate::sanitize::sanitize;
use crate::ssh::connect::{self, Outcome};

/// The most pending events thrown away after a connection. A bound, so that a
/// terminal that never stops sending cannot keep Bifrost here.
const MAX_DISCARDED_EVENTS: usize = 10_000;

/// Runs one connection on the real terminal, with the real ssh at `ssh`.
///
/// An error means the terminal could not be taken back, so the TUI cannot go on.
/// Anything wrong with the connection itself is a [`HandoverResult`].
pub fn connect<O: TerminalOps>(
    guard: &mut TerminalGuard<O>,
    ssh: &Path,
    request: &ConnectRequest,
) -> io::Result<HandoverResult> {
    hand_over(
        guard,
        &mut io::stdout(),
        &format!("Bifrost: connecting to {}...", request.name),
        "ssh",
        || connect::run(ssh, &request.args, io::stderr()),
        discard_pending_input,
    )
}

/// Sends a public key to a server: ssh on the real terminal, so that it can ask
/// for a password and for a new host's key, with `input` (the key) on its stdin.
///
/// The arguments must be those of `build_copy_args`, which is checked here: with
/// any others the key could reach a shell on the server as commands. A refusal
/// is a [`HandoverResult::Failed`] and nothing is run.
pub fn copy_key<O: TerminalOps>(
    guard: &mut TerminalGuard<O>,
    ssh: &Path,
    request: &ConnectRequest,
    key_name: &str,
    input: Vec<u8>,
) -> io::Result<HandoverResult> {
    if !request.args.is_key_copy() {
        return Ok(HandoverResult::Failed(
            "Internal error: the key was not sent, because the ssh command was not the one \
             for copying a key."
                .to_string(),
        ));
    }
    hand_over(
        guard,
        &mut io::stdout(),
        &format!(
            "Bifrost: sending the public key '{key_name}' to {}...",
            request.name
        ),
        "ssh",
        || connect::run_with_input(ssh, request.args.as_slice(), input, io::stderr()),
        discard_pending_input,
    )
}

/// Runs `program` with `args` on the real terminal, the same way, saying `banner`
/// first. The program is named in the message if it cannot be started.
///
/// Nothing is passed to it through the arguments that it should ask for itself:
/// a passphrase is typed straight into `ssh-keygen` or `ssh-add`.
pub fn run_tool<O: TerminalOps>(
    guard: &mut TerminalGuard<O>,
    program: &Path,
    label: &str,
    args: &[String],
    banner: &str,
) -> io::Result<HandoverResult> {
    hand_over(
        guard,
        &mut io::stdout(),
        banner,
        label,
        || connect::run_program(program, args, io::stderr()),
        discard_pending_input,
    )
}

/// The handover sequence with its steps supplied, so that its order and its
/// failure paths can be tested without a terminal or a real program.
pub fn hand_over<O: TerminalOps>(
    guard: &mut TerminalGuard<O>,
    out: &mut impl Write,
    banner: &str,
    program: &str,
    run: impl FnOnce() -> io::Result<Outcome>,
    discard_input: impl FnOnce(),
) -> io::Result<HandoverResult> {
    if let Err(err) = guard.suspend() {
        // Still in TUI mode, so nothing is broken; just do not start the program.
        return Ok(HandoverResult::Failed(format!(
            "Could not leave the interface to run {program}: {err}"
        )));
    }

    // The banner is a courtesy: a failure to print it must not stop the
    // program. It can hold a host name, so it is sanitized.
    let _ = writeln!(out, "{}", sanitize(banner)).and_then(|()| out.flush());

    let ran = run();

    guard.resume()?;
    discard_input();

    Ok(match ran {
        Ok(outcome) => HandoverResult::Ran(outcome),
        Err(err) => HandoverResult::Failed(format!("Could not start {program}: {err}")),
    })
}

/// Drops events that are already waiting.
fn discard_pending_input() {
    for _ in 0..MAX_DISCARDED_EVENTS {
        match event::poll(Duration::ZERO) {
            Ok(true) if event::read().is_ok() => {}
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::connect::Exit;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    type Log = Rc<RefCell<Vec<&'static str>>>;

    /// Clones share the log and the failure switches, so a test can flip them
    /// after the guard owns its copy.
    #[derive(Debug, Clone, Default)]
    struct Ops {
        log: Log,
        fail_enter: Rc<Cell<bool>>,
        fail_leave: Rc<Cell<bool>>,
    }

    impl TerminalOps for Ops {
        fn enter(&mut self) -> io::Result<()> {
            self.log.borrow_mut().push("enter");
            if self.fail_enter.get() {
                return Err(io::Error::other("enter failed"));
            }
            Ok(())
        }

        fn leave(&mut self) -> io::Result<()> {
            self.log.borrow_mut().push("leave");
            if self.fail_leave.get() {
                return Err(io::Error::other("leave failed"));
            }
            Ok(())
        }
    }

    fn outcome(code: i32) -> Outcome {
        Outcome {
            exit: Exit::Code(code),
            stderr: b"some output".to_vec(),
            interrupted: false,
        }
    }

    fn logged(log: &Log) -> Vec<&'static str> {
        log.borrow().clone()
    }

    #[test]
    fn the_terminal_is_given_away_before_ssh_and_taken_back_after_it() {
        let ops = Ops::default();
        let log = Rc::clone(&ops.log);
        let mut guard = TerminalGuard::enter(ops).unwrap();
        let mut out = Vec::new();

        let result = hand_over(
            &mut guard,
            &mut out,
            "Bifrost: connecting to web...",
            "ssh",
            || {
                log.borrow_mut().push("ssh");
                Ok(outcome(0))
            },
            || log.borrow_mut().push("discard input"),
        )
        .unwrap();

        assert_eq!(
            logged(&log),
            ["enter", "leave", "ssh", "enter", "discard input"]
        );
        assert!(guard.is_active());
        assert!(matches!(result, HandoverResult::Ran(o) if o == outcome(0)));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Bifrost: connecting to web...\n"
        );
    }

    #[test]
    fn a_failing_connection_still_gets_the_terminal_back() {
        let ops = Ops::default();
        let log = Rc::clone(&ops.log);
        let mut guard = TerminalGuard::enter(ops).unwrap();

        let result = hand_over(
            &mut guard,
            &mut Vec::new(),
            "Bifrost: connecting to web...",
            "ssh",
            || Err(io::Error::other("permission denied")),
            || log.borrow_mut().push("discard input"),
        )
        .unwrap();

        assert!(guard.is_active());
        assert_eq!(logged(&log), ["enter", "leave", "enter", "discard input"]);
        assert!(
            matches!(result, HandoverResult::Failed(text) if text == "Could not start ssh: permission denied")
        );
    }

    #[test]
    fn a_terminal_that_cannot_be_left_never_starts_ssh() {
        let ops = Ops::default();
        let log = Rc::clone(&ops.log);
        let fail_leave = Rc::clone(&ops.fail_leave);
        let mut guard = TerminalGuard::enter(ops).unwrap();
        fail_leave.set(true);

        let result = hand_over(
            &mut guard,
            &mut Vec::new(),
            "Bifrost: connecting to web...",
            "ssh",
            || {
                log.borrow_mut().push("ssh");
                Ok(outcome(0))
            },
            || log.borrow_mut().push("discard input"),
        )
        .unwrap();

        assert!(!logged(&log).contains(&"ssh"));
        assert!(guard.is_active(), "the TUI carries on");
        assert!(matches!(result, HandoverResult::Failed(text) if text.contains("leave failed")));
    }

    #[test]
    fn a_terminal_that_cannot_be_taken_back_is_fatal_and_discards_nothing() {
        let ops = Ops::default();
        let log = Rc::clone(&ops.log);
        let fail_enter = Rc::clone(&ops.fail_enter);
        let mut guard = TerminalGuard::enter(ops).unwrap();
        fail_enter.set(true);

        let err = hand_over(
            &mut guard,
            &mut Vec::new(),
            "Bifrost: connecting to web...",
            "ssh",
            || Ok(outcome(0)),
            || log.borrow_mut().push("discard input"),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "enter failed");
        assert!(!guard.is_active());
        assert!(!logged(&log).contains(&"discard input"));
    }

    #[test]
    fn a_panic_while_ssh_runs_leaves_the_terminal_normal_and_leaves_it_once() {
        let ops = Ops::default();
        let log = Rc::clone(&ops.log);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = TerminalGuard::enter(ops).unwrap();
            let _ = hand_over(
                &mut guard,
                &mut Vec::new(),
                "Bifrost: connecting to web...",
                "ssh",
                || panic!("Bifrost failed while ssh was running"),
                || {},
            );
        }));

        assert!(result.is_err());
        // Left for the handover; the guard's drop must not leave again, and no
        // enter happened: the terminal stays as ssh had it, which is normal.
        assert_eq!(logged(&log), ["enter", "leave"]);
    }

    #[test]
    fn the_banner_cannot_carry_escape_sequences() {
        let ops = Ops::default();
        let mut guard = TerminalGuard::enter(ops).unwrap();
        let mut out = Vec::new();
        hand_over(
            &mut guard,
            &mut out,
            "Bifrost: connecting to evil\x1b[2Jname\u{202e}...",
            "ssh",
            || Ok(outcome(0)),
            || {},
        )
        .unwrap();
        let banner = String::from_utf8(out).unwrap();
        assert!(!banner.contains('\x1b'));
        assert!(!banner.contains('\u{202e}'));
        assert_eq!(banner.matches('\n').count(), 1);
    }

    #[test]
    fn a_banner_that_cannot_be_written_does_not_stop_the_connection() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut guard = TerminalGuard::enter(Ops::default()).unwrap();
        let result = hand_over(
            &mut guard,
            &mut Broken,
            "Bifrost: connecting to web...",
            "ssh",
            || Ok(outcome(0)),
            || {},
        )
        .unwrap();
        assert!(matches!(result, HandoverResult::Ran(_)));
    }

    #[test]
    fn a_failure_names_the_program_that_could_not_be_started() {
        for program in ["ssh", "ssh-keygen", "ssh-add"] {
            let mut guard = TerminalGuard::enter(Ops::default()).unwrap();
            let result = hand_over(
                &mut guard,
                &mut Vec::new(),
                "banner",
                program,
                || Err(io::Error::other("no such file")),
                || {},
            )
            .unwrap();
            assert!(
                matches!(&result, HandoverResult::Failed(text)
                    if *text == format!("Could not start {program}: no such file")),
                "{result:?}"
            );
        }
    }

    #[test]
    fn a_terminal_that_cannot_be_left_names_the_program_too() {
        let ops = Ops::default();
        let fail_leave = Rc::clone(&ops.fail_leave);
        let mut guard = TerminalGuard::enter(ops).unwrap();
        fail_leave.set(true);
        let result = hand_over(
            &mut guard,
            &mut Vec::new(),
            "banner",
            "ssh-keygen",
            || Ok(outcome(0)),
            || {},
        )
        .unwrap();
        assert!(
            matches!(&result, HandoverResult::Failed(text) if text.contains("run ssh-keygen")),
            "{result:?}"
        );
    }

    #[test]
    fn a_key_is_not_sent_with_arguments_that_are_not_the_copy_ones() {
        // With the arguments of a session, ssh would open a shell on the server
        // and read the key as commands. Nothing must run, and the terminal must
        // not even be touched.
        let ops = Ops::default();
        let log = Rc::clone(&ops.log);
        let mut guard = TerminalGuard::enter(ops).unwrap();
        let host = crate::domain::Host::new("web", "web.example.com");
        let hosts = crate::domain::Hosts::from_vec(vec![host.clone()]).unwrap();
        let request = ConnectRequest {
            name: "web".to_string(),
            args: crate::ssh::command::build_args(&host, &hosts).unwrap(),
            known_hosts: Vec::new(),
        };
        let result = copy_key(
            &mut guard,
            Path::new("/nonexistent/ssh"),
            &request,
            "id_ed25519",
            b"ssh-ed25519 AAAA\n".to_vec(),
        )
        .unwrap();
        let HandoverResult::Failed(why) = result else {
            panic!("{result:?}");
        };
        assert!(why.contains("not the one for copying a key"), "{why}");
        assert_eq!(logged(&log), ["enter"], "the terminal was never left");
    }
}
