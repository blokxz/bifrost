//! The bridge to OpenSSH: locating the `ssh` binary, importing hosts from the
//! user's ssh config, exporting Bifrost hosts as an ssh config file, building
//! the ssh command for a saved host, and running it on the user's terminal.

pub mod agent;
pub mod authorize;
pub mod binary;
pub mod command;
pub mod connect;
pub mod diagnose;
pub mod export;
pub mod import;
pub mod interrupt;
pub mod keygen;
pub mod keys;
pub mod scan;
pub mod tty;
