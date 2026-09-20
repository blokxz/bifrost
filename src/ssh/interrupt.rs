//! Surviving Ctrl-C while ssh has the terminal.
//!
//! While ssh runs, the terminal is in its normal (cooked) mode, so Ctrl-C at a
//! password prompt or during a hanging connection sends SIGINT to the whole
//! foreground process group: ssh *and* Bifrost. ssh should die, Bifrost should
//! not, so that it can take the terminal back and carry on.
//!
//! A handler that only sets a flag does that. It must be a handler and not
//! `SIG_IGN`: an ignored signal stays ignored across `exec`, so ssh would ignore
//! Ctrl-C too, while a caught signal is reset to its default in the child.
//!
//! The handler stays installed once armed: the signal handling library cannot
//! put the default action back, and after the last action is removed a signal is
//! ignored. So the flag is consumed with [`take`] instead, and a SIGINT that
//! arrives outside a connection (`kill -INT`) is turned into a quit by the TUI.
//!
//! Windows has no signals. Its console sends Ctrl-C to every process attached to
//! it and Bifrost has no safe way to survive that: on Windows this module does
//! nothing and Ctrl-C during a connection ends Bifrost with ssh. A documented
//! 0.1.0 limitation.

use std::io;

#[cfg(unix)]
mod imp {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    static FLAG: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

    pub fn arm() -> io::Result<()> {
        let mut flag = FLAG.lock().unwrap_or_else(PoisonError::into_inner);
        if flag.is_none() {
            let new = Arc::new(AtomicBool::new(false));
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&new))?;
            *flag = Some(new);
        }
        Ok(())
    }

    pub fn take() -> bool {
        FLAG.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|flag| flag.swap(false, Ordering::SeqCst))
    }
}

#[cfg(not(unix))]
mod imp {
    use std::io;

    pub fn arm() -> io::Result<()> {
        Ok(())
    }

    pub fn take() -> bool {
        false
    }
}

/// Starts catching SIGINT instead of dying from it. Safe to call again; the
/// handler lasts as long as the process.
pub fn arm() -> io::Result<()> {
    imp::arm()
}

/// Whether SIGINT arrived since the last call. Clears the flag.
pub fn take() -> bool {
    imp::take()
}
