//! Owning the terminal: raw mode, alternate screen and cursor.
//!
//! [`TerminalGuard`] switches the terminal into TUI mode and puts it back when
//! it is dropped, on every exit path including `?` and unwinding. It can also
//! hand the terminal over temporarily ([`TerminalGuard::suspend`] and
//! [`TerminalGuard::resume`]) so that another program, such as `ssh`, can use it.
//!
//! [`install_panic_hook`] covers the one case a guard cannot: a panic message
//! printed while the alternate screen is still active would be lost when the
//! screen is left.

use std::io::{self, stdout};
use std::panic;

use ratatui::crossterm::cursor::{Hide, Show};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

/// The two terminal state changes the guard needs, abstracted so that the
/// guard's own logic can be tested without a real terminal.
pub trait TerminalOps {
    /// Enters TUI mode: raw mode, alternate screen, hidden cursor.
    ///
    /// If this fails, nothing may be left half applied.
    fn enter(&mut self) -> io::Result<()>;

    /// Leaves TUI mode. Every step is attempted even if an earlier one fails,
    /// and the first error is returned. Calling it when TUI mode is not active
    /// must be harmless.
    fn leave(&mut self) -> io::Result<()>;
}

/// [`TerminalOps`] for the real terminal, through crossterm.
#[derive(Debug, Default, Clone, Copy)]
pub struct CrosstermOps;

impl TerminalOps for CrosstermOps {
    fn enter(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        if let Err(err) = execute!(stdout(), EnterAlternateScreen, Hide) {
            let _ = self.leave();
            return Err(err);
        }
        Ok(())
    }

    fn leave(&mut self) -> io::Result<()> {
        let screen = execute!(stdout(), Show, LeaveAlternateScreen);
        let raw = disable_raw_mode();
        screen.and(raw)
    }
}

/// RAII owner of the terminal's TUI mode.
///
/// Create it before the ratatui `Terminal` so that it is dropped after it.
#[derive(Debug)]
pub struct TerminalGuard<O: TerminalOps = CrosstermOps> {
    ops: O,
    active: bool,
}

impl<O: TerminalOps> TerminalGuard<O> {
    /// Enters TUI mode. The mode is left again when the guard is dropped.
    pub fn enter(mut ops: O) -> io::Result<Self> {
        ops.enter()?;
        Ok(TerminalGuard { ops, active: true })
    }

    /// Whether the terminal is currently in TUI mode.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Gives the terminal back to the shell, for example to run `ssh`.
    ///
    /// Does nothing if already suspended. If restoring fails, the guard stays
    /// active so that dropping it tries again.
    pub fn suspend(&mut self) -> io::Result<()> {
        if self.active {
            self.ops.leave()?;
            self.active = false;
        }
        Ok(())
    }

    /// Takes the terminal back after [`TerminalGuard::suspend`].
    ///
    /// Does nothing if already active. The screen content is gone after a
    /// suspension, so the caller must clear the ratatui `Terminal` to force a
    /// full redraw.
    pub fn resume(&mut self) -> io::Result<()> {
        if !self.active {
            self.ops.enter()?;
            self.active = true;
        }
        Ok(())
    }
}

impl<O: TerminalOps> Drop for TerminalGuard<O> {
    fn drop(&mut self) {
        if self.active {
            // Nothing sensible can be done about a failure while dropping.
            let _ = self.ops.leave();
        }
    }
}

/// Makes a panic leave TUI mode before its message is printed.
///
/// The previous hook still runs afterwards, so the message and any backtrace
/// appear on the normal screen, readable. Call this once, before the guard is
/// created.
pub fn install_panic_hook() {
    install_panic_hook_with(|| {
        let _ = CrosstermOps.leave();
    });
}

/// [`install_panic_hook`] with the restoration step supplied by the caller.
pub fn install_panic_hook_with(restore: impl Fn() + Send + Sync + 'static) {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        restore();
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Debug, Clone, Default)]
    struct Fake {
        calls: Rc<RefCell<Vec<&'static str>>>,
        fail_enter: bool,
        fail_leave: bool,
    }

    impl Fake {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl TerminalOps for Fake {
        fn enter(&mut self) -> io::Result<()> {
            self.calls.borrow_mut().push("enter");
            if self.fail_enter {
                return Err(io::Error::other("enter failed"));
            }
            Ok(())
        }

        fn leave(&mut self) -> io::Result<()> {
            self.calls.borrow_mut().push("leave");
            if self.fail_leave {
                return Err(io::Error::other("leave failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn enters_on_creation_and_leaves_on_drop() {
        let fake = Fake::default();
        let guard = TerminalGuard::enter(fake.clone()).unwrap();
        assert!(guard.is_active());
        assert_eq!(fake.calls(), ["enter"]);
        drop(guard);
        assert_eq!(fake.calls(), ["enter", "leave"]);
    }

    #[test]
    fn leaves_when_unwinding() {
        let fake = Fake::default();
        let for_thread = fake.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = TerminalGuard::enter(for_thread).unwrap();
            std::panic::resume_unwind(Box::new("unwind"));
        }));
        assert!(result.is_err());
        assert_eq!(fake.calls(), ["enter", "leave"]);
    }

    #[test]
    fn a_failed_enter_creates_no_guard_and_does_not_leave() {
        let fake = Fake {
            fail_enter: true,
            ..Fake::default()
        };
        let err = TerminalGuard::enter(fake.clone()).unwrap_err();
        assert_eq!(err.to_string(), "enter failed");
        assert_eq!(fake.calls(), ["enter"]);
    }

    #[test]
    fn suspend_leaves_and_resume_enters_again() {
        let fake = Fake::default();
        let mut guard = TerminalGuard::enter(fake.clone()).unwrap();
        guard.suspend().unwrap();
        assert!(!guard.is_active());
        guard.resume().unwrap();
        assert!(guard.is_active());
        assert_eq!(fake.calls(), ["enter", "leave", "enter"]);
        drop(guard);
        assert_eq!(fake.calls(), ["enter", "leave", "enter", "leave"]);
    }

    #[test]
    fn dropping_while_suspended_does_not_leave_twice() {
        let fake = Fake::default();
        let mut guard = TerminalGuard::enter(fake.clone()).unwrap();
        guard.suspend().unwrap();
        drop(guard);
        assert_eq!(fake.calls(), ["enter", "leave"]);
    }

    #[test]
    fn repeated_suspend_and_resume_are_no_ops() {
        let fake = Fake::default();
        let mut guard = TerminalGuard::enter(fake.clone()).unwrap();
        guard.resume().unwrap();
        guard.suspend().unwrap();
        guard.suspend().unwrap();
        guard.resume().unwrap();
        guard.resume().unwrap();
        assert_eq!(fake.calls(), ["enter", "leave", "enter"]);
    }

    #[test]
    fn failed_suspend_stays_active_so_drop_retries() {
        let fake = Fake::default();
        let mut guard = TerminalGuard::enter(fake.clone()).unwrap();
        guard.ops.fail_leave = true;
        assert!(guard.suspend().is_err());
        assert!(guard.is_active());
        drop(guard);
        assert_eq!(fake.calls(), ["enter", "leave", "leave"]);
    }

    #[test]
    fn failed_resume_stays_suspended() {
        let fake = Fake::default();
        let mut guard = TerminalGuard::enter(fake.clone()).unwrap();
        guard.suspend().unwrap();
        guard.ops.fail_enter = true;
        assert!(guard.resume().is_err());
        assert!(!guard.is_active());
        drop(guard);
        assert_eq!(fake.calls(), ["enter", "leave", "enter"]);
    }
}
