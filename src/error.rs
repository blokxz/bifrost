//! Application error type.

use std::error::Error;
use std::fmt;
use std::io;

/// Everything that can make a Bifrost command fail.
#[derive(Debug)]
pub enum AppError {
    /// Writing to stdout failed (for example a closed pipe).
    Io(io::Error),
}

pub type Result<T> = std::result::Result<T, AppError>;

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AppError::Io(err) => Some(err),
        }
    }
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::Io(err)
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
}
