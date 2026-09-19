//! Bifrost: a beginner-friendly SSH TUI.
//!
//! The library holds everything except the process entry point: the CLI
//! definition, the host model and its validation, the TOML store, the
//! import/export bridge to the user's OpenSSH configuration, the terminal
//! interface and the non-interactive commands.

#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
pub mod domain;
pub mod error;
pub mod sanitize;
pub mod ssh;
pub mod store;
pub mod sysenv;
pub mod text;
pub mod tui;
