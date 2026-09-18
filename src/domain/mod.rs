//! The host model and its validation rules.
//!
//! [`Hosts`] is the only way to build a collection of hosts: every mutation is
//! validated as a whole, so a `Hosts` value is always internally consistent
//! (unique names, valid fields, jump hosts that exist and form no loops).

use std::fmt;

pub mod host;
pub mod jump;
pub mod validate;

pub use host::{Forward, Host, Hosts, HostsError};
pub use validate::{Field, ValidationError};

/// A problem that does not stop an operation but that the user should hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    message: String,
}

impl Warning {
    pub fn new(message: impl Into<String>) -> Self {
        Warning {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
