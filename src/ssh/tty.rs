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
//! Unix only. The Windows console has its own modes; restoring them needs
//! `unsafe` calls that this crate forbids, so there this does nothing.

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

#[cfg(not(unix))]
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
