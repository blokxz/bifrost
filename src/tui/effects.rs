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

use super::app::{ConnectRequest, HandoverResult};
use super::clipboard;
use super::handover;
use super::terminal::{TerminalGuard, TerminalOps};
use crate::ssh::authorize::read_public_key;
use crate::ssh::binary::{KeygenNotFound, SshAddNotFound, SshNotFound};
use crate::ssh::command::KnownHostsTarget;
use crate::ssh::keygen::{Removal, remove_known_host};
use crate::ssh::keys::{
    KeysSnapshot, SystemKeyTools, add_args, ensure_name_is_free, fix_permissions, generate_args,
    load_keys,
};
use crate::store::fsutil::ensure_private_dir;

const NO_HOME: &str = "Could not find your home directory, so the ssh folder cannot be located.";

/// Something the app wants done outside itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Ask the terminal to put this text on the clipboard.
    Copy(String),
    /// Hand the terminal to ssh and connect.
    Connect(ConnectRequest),
    /// Remove an old host key with `ssh-keygen -R`.
    RemoveKey(KnownHostsTarget),
    /// Read the keys in the ssh directory and ask the agent what it holds.
    LoadKeys,
    /// Set a private key's permissions to 0600. Only the file's name is given:
    /// the directory is the one the app was started with, so nothing outside it
    /// can be named.
    FixKeyPermissions { file_name: String },
    /// Make an ed25519 key in the ssh directory with `ssh-keygen`, on the real
    /// terminal, where it asks for the passphrase itself. The comment is left
    /// out when `None`.
    GenerateKey {
        file_name: String,
        comment: Option<String>,
    },
    /// Add a key of the ssh directory to the agent with `ssh-add`, on the real
    /// terminal, where it asks for the passphrase itself.
    AddKeyToAgent { file_name: String },
    /// Send the public key of a key of the ssh directory to a saved host, with
    /// ssh on the real terminal. `connect` holds the arguments of
    /// `build_copy_args`. Only the key's file name is given: the key itself is
    /// read and checked when this is carried out.
    CopyKey {
        file_name: String,
        connect: ConnectRequest,
    },
}

impl Request {
    /// Whether carrying it out takes the terminal from the interface, so that
    /// nothing of the screen can be trusted afterwards and everything must be
    /// repainted.
    pub fn gives_away_terminal(&self) -> bool {
        matches!(
            self,
            Request::Connect(_)
                | Request::GenerateKey { .. }
                | Request::AddKeyToAgent { .. }
                | Request::CopyKey { .. }
        )
    }
}

/// What came of a [`Request`]. Each request has its own kind of response.
#[derive(Debug)]
pub enum Response {
    /// The terminal was asked to copy. It cannot say whether it did.
    Copied,
    /// ssh ran, or could not be started.
    Connected(HandoverResult),
    /// What `ssh-keygen -R` did.
    KeyRemoved(Removal),
    /// The keys found, and the agent's state.
    Keys(KeysSnapshot),
    /// Whether the permissions were changed; if not, why, in plain English.
    PermissionsFixed(Result<(), String>),
    /// What came of `ssh-keygen`, or why it was not run.
    KeyGenerated(HandoverResult),
    /// What came of `ssh-add`, or why it was not run.
    KeyAdded(HandoverResult),
    /// What came of ssh sending a public key, or why it was not run.
    KeyCopied(HandoverResult),
}

/// The OpenSSH programs, as found at startup. A program that was not found is
/// not fatal: the request that needs it is answered with what to install.
#[derive(Debug)]
pub struct Programs {
    pub ssh: Result<PathBuf, SshNotFound>,
    pub keygen: Result<PathBuf, KeygenNotFound>,
    pub ssh_add: Result<PathBuf, SshAddNotFound>,
}

/// The real world: the programs found at startup, the ssh directory and the
/// terminal.
#[derive(Debug)]
pub struct System<'a, O: TerminalOps> {
    guard: &'a mut TerminalGuard<O>,
    programs: Programs,
    /// `~/.ssh`, when the home directory is known.
    ssh_dir: Option<PathBuf>,
}

impl<'a, O: TerminalOps> System<'a, O> {
    pub fn new(
        guard: &'a mut TerminalGuard<O>,
        programs: Programs,
        ssh_dir: Option<PathBuf>,
    ) -> Self {
        System {
            guard,
            programs,
            ssh_dir,
        }
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
            Request::Connect(connect) => match &self.programs.ssh {
                Ok(path) => handover::connect(self.guard, path, connect).map(Response::Connected),
                Err(missing) => Ok(Response::Connected(HandoverResult::Failed(
                    missing.to_string(),
                ))),
            },
            Request::RemoveKey(target) => Ok(Response::KeyRemoved(match &self.programs.keygen {
                Ok(path) => remove_known_host(path, &target.entry).unwrap_or_else(|err| {
                    Removal::Failed(format!("Could not run ssh-keygen: {err}"))
                }),
                Err(missing) => Removal::Failed(missing.to_string()),
            })),
            Request::LoadKeys => Ok(Response::Keys(match &self.ssh_dir {
                Some(dir) => load_keys(
                    &SystemKeyTools {
                        keygen: self.programs.keygen.as_deref().ok(),
                        ssh_add: self.programs.ssh_add.as_deref().ok(),
                    },
                    dir,
                ),
                None => KeysSnapshot::unavailable(NO_HOME),
            })),
            Request::GenerateKey { file_name, comment } => self
                .generate(file_name, comment.as_deref())
                .map(Response::KeyGenerated),
            Request::AddKeyToAgent { file_name } => {
                self.add_to_agent(file_name).map(Response::KeyAdded)
            }
            Request::CopyKey { file_name, connect } => {
                self.copy_key(file_name, connect).map(Response::KeyCopied)
            }
            Request::FixKeyPermissions { file_name } => {
                Ok(Response::PermissionsFixed(match &self.ssh_dir {
                    Some(dir) => fix_permissions(dir, file_name).map_err(|err| err.to_string()),
                    None => Err(NO_HOME.to_string()),
                }))
            }
        }
    }
}

impl<O: TerminalOps> System<'_, O> {
    /// Makes the key with `ssh-keygen`. Everything that can be refused is refused
    /// before the terminal is given away.
    fn generate(&mut self, name: &str, comment: Option<&str>) -> io::Result<HandoverResult> {
        let Some(dir) = self.ssh_dir.clone() else {
            return Ok(HandoverResult::Failed(NO_HOME.to_string()));
        };
        let keygen = match &self.programs.keygen {
            Ok(path) => path.clone(),
            Err(missing) => return Ok(HandoverResult::Failed(missing.to_string())),
        };
        let args = match generate_args(&dir, name, comment) {
            Ok(args) => args,
            Err(why) => return Ok(HandoverResult::Failed(why)),
        };
        if let Err(why) = ensure_name_is_free(&dir, name) {
            return Ok(HandoverResult::Failed(why));
        }
        // ssh-keygen does not make the folder itself; a fresh account has none.
        if let Err(err) = ensure_private_dir(&dir) {
            return Ok(HandoverResult::Failed(format!(
                "Could not create the folder {}: {err}",
                dir.display()
            )));
        }
        handover::run_tool(
            self.guard,
            &keygen,
            "ssh-keygen",
            &args,
            &format!("Bifrost: making the key '{name}' with ssh-keygen..."),
        )
    }

    /// Sends the public key of `file_name` with ssh. Everything that can be
    /// refused is refused before the terminal is given away: no ssh, no home, a
    /// file that is not exactly one public key.
    fn copy_key(
        &mut self,
        file_name: &str,
        request: &ConnectRequest,
    ) -> io::Result<HandoverResult> {
        let ssh = match &self.programs.ssh {
            Ok(path) => path.clone(),
            Err(missing) => return Ok(HandoverResult::Failed(missing.to_string())),
        };
        let Some(dir) = self.ssh_dir.clone() else {
            return Ok(HandoverResult::Failed(NO_HOME.to_string()));
        };
        let input = match read_public_key(&dir, file_name).and_then(|key| key.to_stdin()) {
            Ok(input) => input,
            Err(why) => return Ok(HandoverResult::Failed(why.to_string())),
        };
        handover::copy_key(self.guard, &ssh, request, file_name, input)
    }

    /// Adds the key to the agent with `ssh-add`.
    fn add_to_agent(&mut self, name: &str) -> io::Result<HandoverResult> {
        let Some(dir) = self.ssh_dir.clone() else {
            return Ok(HandoverResult::Failed(NO_HOME.to_string()));
        };
        let ssh_add = match &self.programs.ssh_add {
            Ok(path) => path.clone(),
            Err(missing) => return Ok(HandoverResult::Failed(missing.to_string())),
        };
        let args = match add_args(&dir, name) {
            Ok(args) => args,
            Err(why) => return Ok(HandoverResult::Failed(why)),
        };
        handover::run_tool(
            self.guard,
            &ssh_add,
            "ssh-add",
            &args,
            &format!("Bifrost: adding the key '{name}' to the agent with ssh-add..."),
        )
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
    fn making_a_key_and_adding_one_take_the_terminal_because_the_tools_ask_for_a_passphrase() {
        assert!(
            Request::GenerateKey {
                file_name: "k".to_string(),
                comment: None
            }
            .gives_away_terminal()
        );
        assert!(
            Request::AddKeyToAgent {
                file_name: "k".to_string()
            }
            .gives_away_terminal()
        );
    }

    #[test]
    fn sending_a_key_takes_the_terminal_because_ssh_asks_for_the_password() {
        let host = Host::new("web", "web.example.com");
        let hosts = Hosts::from_vec(vec![host.clone()]).unwrap();
        let request = Request::CopyKey {
            file_name: "id_ed25519".to_string(),
            connect: ConnectRequest {
                name: "web".to_string(),
                args: crate::ssh::command::build_copy_args(&host, &hosts).unwrap(),
                known_hosts: Vec::new(),
            },
        };
        assert!(request.gives_away_terminal());
    }

    #[test]
    fn loading_keys_and_fixing_permissions_leave_the_terminal_alone() {
        assert!(!Request::LoadKeys.gives_away_terminal());
        assert!(
            !Request::FixKeyPermissions {
                file_name: "id_ed25519".to_string()
            }
            .gives_away_terminal()
        );
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
