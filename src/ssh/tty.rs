//! Putting the terminal's modes back after ssh.
//!
//! ssh switches the terminal to raw mode for a session and restores it when it
//! exits. If it is killed (SIGKILL, the out-of-memory killer) it cannot, and the
//! terminal stays raw. crossterm makes that worse: `enable_raw_mode` records the
//! modes it finds as "the original ones" each time, so a Bifrost that took the
//! terminal back from a killed ssh would later "restore" raw mode at exit.
//!
//! [`SavedModes::capture`] is taken just before ssh starts (the terminal is in
//! its normal state then) and [`SavedModes::restore`] just after it ends, the
//! way a shell does after a foreground job.
//!
//! Windows has the same problem in its own terms, and it is worse there.
//! `ssh.exe` changes the console's input and output modes for a session; killed
//! from the Task Manager it restores neither, and Bifrost then draws on top of
//! them. crossterm cannot put that right: unlike on Unix it saves no original
//! mode on Windows at all, and its `disable_raw_mode` only sets three input bits
//! (`ENABLE_LINE_INPUT`, `ENABLE_ECHO_INPUT`, `ENABLE_PROCESSED_INPUT`) back.
//! Everything else ssh touched — virtual-terminal input, mouse and window
//! input, and the whole output mode — stays as ssh left it, which is how a
//! console ends up taking some keys and not others, with no way to quit. So
//! both handles are saved here and put back whole.

#[cfg(unix)]
mod imp {
    use std::io;

    use rustix::termios::{OptionalActions, Termios, tcgetattr, tcsetattr};

    #[derive(Debug, Clone)]
    pub struct SavedModes(Option<Termios>);

    impl SavedModes {
        /// `None` inside when stdin is not a terminal, which is not an error.
        pub fn capture() -> Self {
            SavedModes(tcgetattr(io::stdin()).ok())
        }

        /// Waits for pending output first but keeps pending input: whatever the
        /// user typed ahead is theirs to keep (a shell gets it back too).
        pub fn restore(&self) {
            if let Some(modes) = &self.0 {
                // Nothing sensible can be done if the terminal refuses.
                let _ = tcsetattr(io::stdin(), OptionalActions::Drain, modes);
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use crossterm_winapi::{ConsoleMode, Handle};

    /// The console's input and output modes as they were before the handover.
    ///
    /// The values are kept, not the handles: a handle to `CONIN$` or `CONOUT$`
    /// is opened for the moment it is needed and closed again, so nothing of
    /// the console is held open for as long as ssh runs.
    #[derive(Debug, Clone, Default)]
    pub struct SavedModes {
        input: Option<u32>,
        output: Option<u32>,
    }

    /// The console's input buffer (`CONIN$`), which is what crossterm's raw mode
    /// uses too, rather than this process's stdin: a redirected stdin is not the
    /// console whose modes ssh changed.
    fn input() -> Option<ConsoleMode> {
        Handle::current_in_handle().ok().map(ConsoleMode::from)
    }

    /// The active screen buffer (`CONOUT$`), for the same reason.
    fn output() -> Option<ConsoleMode> {
        Handle::current_out_handle().ok().map(ConsoleMode::from)
    }

    impl SavedModes {
        /// `None` inside for a handle that is not a console, which is not an
        /// error: a piped Bifrost has no modes to put back.
        pub fn capture() -> Self {
            SavedModes {
                input: input().and_then(|console| console.mode().ok()),
                output: output().and_then(|console| console.mode().ok()),
            }
        }

        /// Puts both modes back exactly as they were. Nothing sensible can be
        /// done if the console refuses, and a mode that was never read is left
        /// alone rather than guessed at.
        pub fn restore(&self) {
            if let (Some(mode), Some(console)) = (self.input, input()) {
                let _ = console.set_mode(mode);
            }
            if let (Some(mode), Some(console)) = (self.output, output()) {
                let _ = console.set_mode(mode);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    #[derive(Debug, Clone)]
    pub struct SavedModes;

    impl SavedModes {
        pub fn capture() -> Self {
            SavedModes
        }

        pub fn restore(&self) {}
    }
}

pub use imp::SavedModes;

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading the modes must not change them, and putting back what was just
    /// read must leave them alone. Runs wherever the tests do: where there is no
    /// terminal (a piped test runner, a console-less CI job) both steps are
    /// no-ops, which is the other thing worth knowing they do not panic at.
    #[test]
    fn capturing_changes_nothing_and_restoring_what_was_captured_changes_nothing() {
        let before = SavedModes::capture();
        let again = SavedModes::capture();
        assert_eq!(format!("{before:?}"), format!("{again:?}"));

        before.restore();
        let after = SavedModes::capture();
        assert_eq!(format!("{before:?}"), format!("{after:?}"));
    }

    /// The case this exists for, which needs a real console: a program changes
    /// the modes and dies without putting them back. Only Windows can run it,
    /// and only attached to a console, so it is run by hand.
    ///
    /// On Unix the same property is covered by `pty_connect.rs`
    /// (`an_ssh_killed_in_raw_mode_cannot_leave_the_terminal_raw`), which can
    /// drive a pseudo-terminal; Windows has no such harness.
    #[cfg(windows)]
    #[ignore = "needs a real console"]
    #[test]
    fn modes_a_program_changed_are_put_back() {
        use crossterm_winapi::{ConsoleMode, Handle};

        let console = ConsoleMode::from(Handle::current_in_handle().expect("a console"));
        let original = console.mode().expect("a mode");
        let saved = SavedModes::capture();

        // What ssh.exe leaves behind when it is killed: a mode that is not the
        // one Bifrost handed it.
        console.set_mode(original ^ 0x0200).expect("set");
        assert_ne!(console.mode().unwrap(), original);

        saved.restore();
        assert_eq!(console.mode().unwrap(), original);
    }
}
