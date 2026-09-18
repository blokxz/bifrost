//! The bridge to OpenSSH: locating the `ssh` binary, importing hosts from the
//! user's ssh config, and exporting Bifrost hosts as an ssh config file.

pub mod binary;
pub mod export;
pub mod import;
pub mod scan;
