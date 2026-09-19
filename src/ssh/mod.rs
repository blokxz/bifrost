//! The bridge to OpenSSH: locating the `ssh` binary, importing hosts from the
//! user's ssh config, exporting Bifrost hosts as an ssh config file, and building
//! the ssh command for a saved host.

pub mod binary;
pub mod command;
pub mod export;
pub mod import;
pub mod scan;
