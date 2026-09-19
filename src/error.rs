//! Application error type.

use std::error::Error;
use std::fmt;
use std::io;

use crate::store::StoreError;

/// Everything that can make a Bifrost command fail.
#[derive(Debug)]
pub enum AppError {
    /// Talking to the terminal or writing to stdout failed (for example a
    /// closed pipe).
    Io(io::Error),
    /// The store could not be located, read or written. The message already
    /// names the file and says how to recover.
    Store(StoreError),
    /// The TUI was started without an interactive terminal.
    NotATerminal,
}

pub type Result<T> = std::result::Result<T, AppError>;

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(err) => write!(f, "I/O error: {err}"),
            AppError::Store(err) => err.fmt(f),
            AppError::NotATerminal => f.write_str(
                "The interface needs an interactive terminal. \
                 Use `bifrost list` to print your saved hosts in scripts.",
            ),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AppError::Io(err) => Some(err),
            AppError::Store(err) => Some(err),
            AppError::NotATerminal => None,
        }
    }
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::Io(err)
    }
}

impl From<StoreError> for AppError {
    fn from(err: StoreError) -> Self {
        AppError::Store(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_converts_and_displays() {
        let err: AppError = io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed").into();
        assert_eq!(err.to_string(), "I/O error: pipe closed");
        assert!(err.source().is_some());
    }

    #[test]
    fn store_error_converts_and_keeps_its_message() {
        let store_err = StoreError::RelativeConfigDir("relative/dir".into());
        let expected = store_err.to_string();
        let err: AppError = store_err.into();
        assert_eq!(err.to_string(), expected);
        assert!(err.to_string().contains("absolute path"));
        assert!(err.source().is_some());
    }

    #[test]
    fn not_a_terminal_points_to_the_script_friendly_command() {
        let err = AppError::NotATerminal;
        assert!(err.to_string().contains("interactive terminal"));
        assert!(err.to_string().contains("bifrost list"));
        assert!(err.source().is_none());
    }
}
