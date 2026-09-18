//! Bifrost: a beginner-friendly SSH TUI.
//!
//! The library holds everything except the process entry point: the CLI
//! definition, the host model and its validation, the TOML store, and the
//! import/export bridge to the user's OpenSSH configuration.

#![forbid(unsafe_code)]

pub mod cli;
pub mod domain;
pub mod error;
pub mod ssh;
pub mod store;
pub mod sysenv;
pub mod text;
