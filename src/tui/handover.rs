//! Handing the terminal to ssh and taking it back.
//!
//! The sequence, for every connection and every way it can end:
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

use super::app::{ConnectRequest, ConnectResult};
use super::terminal::{TerminalGuard, TerminalOps};
use crate::sanitize::sanitize;
use crate::ssh::connect::{self, Outcome};

/// The most pending events thrown away after a connection. A bound, so that a
/// terminal that never stops sending cannot keep Bifrost here.
const MAX_DISCARDED_EVENTS: usize = 10_000;

/// Runs one connection on the real terminal, with the real ssh at `ssh`.
///
/// An error means the terminal could not be taken back, so the TUI cannot go on.
/// Anything wrong with the connection itself is a [`ConnectResult`].
pub fn connect<O: TerminalOps>(
    guard: &mut TerminalGuard<O>,
    ssh: &Path,
    request: &ConnectRequest,
) -> io::Result<ConnectResult> {
    hand_over(
        guard,
        &mut io::stdout(),
        &request.name,
        || connect::run(ssh, &request.args, io::stderr()),
        discard_pending_input,
    )
}

/// The handover sequence with its steps supplied, so that its order and its
/// failure paths can be tested without a terminal or a real ssh.
pub fn hand_over<O: TerminalOps>(
    guard: &mut TerminalGuard<O>,
    out: &mut impl Write,
    name: &str,
    run: impl FnOnce() -> io::Result<Outcome>,
    discard_input: impl FnOnce(),
) -> io::Result<ConnectResult> {
    if let Err(err) = guard.suspend() {
        // Still in TUI mode, so nothing is broken; just do not start ssh.
        return Ok(ConnectResult::Failed(format!(
            "Could not leave the interface to run ssh: {err}"
        )));
    }

    // The banner is a courtesy: a failure to print it must not stop the
    // connection.
    let _ =
        writeln!(out, "Bifrost: connecting to {}...", sanitize(name)).and_then(|()| out.flush());

    let ran = run();

    guard.resume()?;
    discard_input();

    Ok(match ran {
        Ok(outcome) => ConnectResult::Ran(outcome),
        Err(err) => ConnectResult::Failed(format!("Could not start ssh: {err}")),
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
            "web",
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
        assert!(matches!(result, ConnectResult::Ran(o) if o == outcome(0)));
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
            "web",
            || Err(io::Error::other("permission denied")),
            || log.borrow_mut().push("discard input"),
        )
        .unwrap();

        assert!(guard.is_active());
        assert_eq!(logged(&log), ["enter", "leave", "enter", "discard input"]);
        assert!(
            matches!(result, ConnectResult::Failed(text) if text == "Could not start ssh: permission denied")
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
            "web",
            || {
                log.borrow_mut().push("ssh");
                Ok(outcome(0))
            },
            || log.borrow_mut().push("discard input"),
        )
        .unwrap();

        assert!(!logged(&log).contains(&"ssh"));
        assert!(guard.is_active(), "the TUI carries on");
        assert!(matches!(result, ConnectResult::Failed(text) if text.contains("leave failed")));
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
            "web",
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
                "web",
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
            "evil\x1b[2Jname\u{202e}",
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
        let result = hand_over(&mut guard, &mut Broken, "web", || Ok(outcome(0)), || {}).unwrap();
        assert!(matches!(result, ConnectResult::Ran(_)));
    }
}
