//! What the interface asks the outside world to do, and what came of it.
//!
//! [`super::app::App`] does no I/O. When a key means "copy this", "connect to
//! that" or "remove this key", it queues a [`Request`]; the event loop hands each
//! one to a single `execute` function and gives the [`Response`] back to the app.
//! One pair of types instead of one hook per action keeps the loop the same size
//! however many actions there are, and lets tests script the outside world with
//! one closure.
//!
//! [`System`] is the real `execute`: it owns what has to be resolved once (the
//! `ssh` and `ssh-keygen` programs) and the terminal guard that is handed over.

use std::io;
use std::path::PathBuf;

use super::app::{ConnectRequest, ConnectResult};
use super::clipboard;
use super::handover;
use super::terminal::{TerminalGuard, TerminalOps};
use crate::ssh::binary::{KeygenNotFound, SshNotFound};
use crate::ssh::command::KnownHostsTarget;
use crate::ssh::keygen::{Removal, remove_known_host};

/// Something the app wants done outside itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Ask the terminal to put this text on the clipboard.
    Copy(String),
    /// Hand the terminal to ssh and connect.
    Connect(ConnectRequest),
    /// Remove an old host key with `ssh-keygen -R`.
    RemoveKey(KnownHostsTarget),
}

impl Request {
    /// Whether carrying it out takes the terminal from the interface, so that
    /// nothing of the screen can be trusted afterwards and everything must be
    /// repainted.
    pub fn gives_away_terminal(&self) -> bool {
        matches!(self, Request::Connect(_))
    }
}

/// What came of a [`Request`]. Each request has its own kind of response.
#[derive(Debug)]
pub enum Response {
    /// The terminal was asked to copy. It cannot say whether it did.
    Copied,
    /// ssh ran, or could not be started.
    Connected(ConnectResult),
    /// What `ssh-keygen -R` did.
    KeyRemoved(Removal),
}

/// The real world: the programs found at startup and the terminal.
#[derive(Debug)]
pub struct System<'a, O: TerminalOps> {
    guard: &'a mut TerminalGuard<O>,
    ssh: Result<PathBuf, SshNotFound>,
    keygen: Result<PathBuf, KeygenNotFound>,
}

impl<'a, O: TerminalOps> System<'a, O> {
    /// `ssh` and `keygen` are what was found at startup. Not finding one is not
    /// fatal: the request that needs it is answered with what to install.
    pub fn new(
        guard: &'a mut TerminalGuard<O>,
        ssh: Result<PathBuf, SshNotFound>,
        keygen: Result<PathBuf, KeygenNotFound>,
    ) -> Self {
        System { guard, ssh, keygen }
    }

    /// Carries out `request`. An error means the terminal could not be
    /// recovered, so the interface cannot go on; anything wrong with the action
    /// itself is part of the [`Response`].
    pub fn execute(&mut self, request: &Request) -> io::Result<Response> {
        match request {
            Request::Copy(text) => {
                clipboard::copy_to_terminal(&mut io::stdout().lock(), text)?;
                Ok(Response::Copied)
            }
            Request::Connect(connect) => match &self.ssh {
                Ok(path) => handover::connect(self.guard, path, connect).map(Response::Connected),
                Err(missing) => Ok(Response::Connected(ConnectResult::Failed(
                    missing.to_string(),
                ))),
            },
            Request::RemoveKey(target) => Ok(Response::KeyRemoved(match &self.keygen {
                Ok(path) => remove_known_host(path, &target.entry).unwrap_or_else(|err| {
                    Removal::Failed(format!("Could not run ssh-keygen: {err}"))
                }),
                Err(missing) => Removal::Failed(missing.to_string()),
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Host, Hosts};
    use crate::ssh::command::build_args;

    fn connect_request() -> ConnectRequest {
        let host = Host::new("web", "web.example.com");
        let hosts = Hosts::from_vec(vec![host.clone()]).unwrap();
        ConnectRequest {
            name: "web".to_string(),
            args: build_args(&host, &hosts).unwrap(),
            known_hosts: Vec::new(),
        }
    }

    #[test]
    fn only_a_connection_takes_the_terminal_from_the_interface() {
        assert!(Request::Connect(connect_request()).gives_away_terminal());
        assert!(!Request::Copy("ssh -- web".to_string()).gives_away_terminal());
        assert!(
            !Request::RemoveKey(KnownHostsTarget {
                entry: "web.example.com".to_string(),
                saved_name: "web".to_string(),
            })
            .gives_away_terminal()
        );
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Reading the app's queue of requests in tests, one kind at a time. Each
    //! returns `None` when nothing is queued and fails the test when something
    //! of another kind is, so a test that expects a copy cannot pass over a
    //! connection.

    use super::*;
    use crate::tui::app::App;

    pub fn take_copy_request(app: &mut App) -> Option<String> {
        match app.take_request() {
            Some(Request::Copy(text)) => Some(text),
            Some(other) => panic!("expected a copy request, got {other:?}"),
            None => None,
        }
    }

    pub fn take_connect_request(app: &mut App) -> Option<ConnectRequest> {
        match app.take_request() {
            Some(Request::Connect(request)) => Some(request),
            Some(other) => panic!("expected a connect request, got {other:?}"),
            None => None,
        }
    }

    pub fn take_removal_request(app: &mut App) -> Option<KnownHostsTarget> {
        match app.take_request() {
            Some(Request::RemoveKey(target)) => Some(target),
            Some(other) => panic!("expected a key removal request, got {other:?}"),
            None => None,
        }
    }
}
