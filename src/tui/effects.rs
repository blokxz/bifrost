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
use std::path::{Path, PathBuf};

use super::app::{ConnectRequest, HandoverResult};
use super::clipboard;
use super::handover;
use super::terminal::{TerminalGuard, TerminalOps};
use crate::domain::Hosts;
use crate::ssh::authorize::read_public_key;
use crate::ssh::binary::{KeygenNotFound, SshAddNotFound, SshNotFound};
use crate::ssh::command::KnownHostsTarget;
use crate::ssh::export::{EXPORT_FILE_NAME, TargetState, export_to, render, target_state};
use crate::ssh::import::{
    ImportReport, ImportSource, SshResolver, SystemSshResolver, import_hosts,
};
use crate::ssh::keygen::{Removal, remove_known_host};
use crate::ssh::keys::{
    Deleted, KeysSnapshot, SystemKeyTools, WithoutAgent, add_args, delete_key, ensure_name_is_free,
    fix_permissions, generate_args, load_keys,
};
use crate::ssh::scan::{IncludeStatus, find_include};
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
    /// Read the keys in the ssh directory for choosing one as a host's identity
    /// file: what they are, without asking the agent.
    ListKeys,
    /// Delete a key pair of the ssh directory: the private file and its `.pub`.
    /// Only the file's name is given, as for the permissions: the directory is the
    /// one the app was started with, so nothing outside it can be named.
    DeleteKey { file_name: String },
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
    /// Read the user's ssh config and work out what importing it would do, given
    /// the hosts saved now. Nothing is saved: this only looks, though it runs
    /// `ssh -G` once for each host it finds, which takes a moment.
    PreviewImport { existing: Hosts },
    /// Look at where exporting would write, and check that `hosts` can be
    /// exported, without writing anything.
    PlanExport { hosts: Hosts },
    /// Write `hosts` to the export file, and look at whether the user's ssh
    /// config includes it. The ssh config itself is never changed.
    Export { hosts: Hosts },
}

/// What reading the ssh config found, ready to show and, once confirmed, to save.
#[derive(Debug)]
pub struct ImportPreview {
    /// The config file that was read.
    pub config: PathBuf,
    /// Whether it exists. One that does not is not an error, it has no hosts.
    pub config_exists: bool,
    /// What importing would do. `report.hosts` is what is saved on confirming.
    pub report: ImportReport,
}

/// Where an export would write and what is there now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportPlan {
    pub target: PathBuf,
    pub state: TargetState,
}

/// What an export did, and what the user still has to do about it.
#[derive(Debug)]
pub struct ExportDone {
    pub target: PathBuf,
    /// Whether `~/.ssh/config` includes the file, or why that could not be told.
    pub include: Result<IncludeStatus, String>,
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
    /// The keys found, for choosing one. The agent was not asked.
    KeyList(KeysSnapshot),
    /// Whether the permissions were changed; if not, why, in plain English.
    PermissionsFixed(Result<(), String>),
    /// What was deleted; or why not, in plain English, which says what is left.
    KeyDeleted(Result<Deleted, String>),
    /// What came of `ssh-keygen`, or why it was not run.
    KeyGenerated(HandoverResult),
    /// What came of `ssh-add`, or why it was not run.
    KeyAdded(HandoverResult),
    /// What came of ssh sending a public key, or why it was not run.
    KeyCopied(HandoverResult),
    /// What importing would do, or why the ssh config could not be read.
    ImportPreview(Result<ImportPreview, String>),
    /// Where the export would write, or why it cannot be done.
    ExportPlan(Result<ExportPlan, String>),
    /// What the export did, or why it failed.
    Exported(Result<ExportDone, String>),
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
            Request::ListKeys => Ok(Response::KeyList(match &self.ssh_dir {
                Some(dir) => load_keys(
                    &WithoutAgent(&SystemKeyTools {
                        keygen: self.programs.keygen.as_deref().ok(),
                        ssh_add: None,
                    }),
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
            Request::PreviewImport { existing } => {
                Ok(Response::ImportPreview(self.preview_import(existing)))
            }
            Request::PlanExport { hosts } => Ok(Response::ExportPlan(self.plan_export(hosts))),
            Request::Export { hosts } => Ok(Response::Exported(self.export(hosts))),
            Request::DeleteKey { file_name } => Ok(Response::KeyDeleted(match &self.ssh_dir {
                Some(dir) => delete_key(dir, file_name).map_err(|err| err.to_string()),
                None => Err(NO_HOME.to_string()),
            })),
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

    /// `~/.ssh` and the file exported into it, or why they cannot be named.
    fn export_target(&self) -> Result<(&Path, PathBuf), String> {
        let dir = self.ssh_dir.as_deref().ok_or_else(|| NO_HOME.to_string())?;
        Ok((dir, dir.join(EXPORT_FILE_NAME)))
    }

    /// Works out what importing the user's ssh config would do.
    fn preview_import(&self, existing: &Hosts) -> Result<ImportPreview, String> {
        let ssh = match &self.programs.ssh {
            Ok(path) => path.clone(),
            Err(missing) => return Err(missing.to_string()),
        };
        let dir = self.ssh_dir.clone().ok_or_else(|| NO_HOME.to_string())?;
        let source = ImportSource {
            config: dir.join("config"),
            home: dir.parent().map(Path::to_path_buf),
            ssh_dir: dir,
        };
        preview_with(&SystemSshResolver::new(ssh), &source, existing)
    }

    /// Looks at the export target, and renders the hosts to see that they can be
    /// exported, which is what would fail before anything is written.
    fn plan_export(&self, hosts: &Hosts) -> Result<ExportPlan, String> {
        let (_, target) = self.export_target()?;
        render(hosts).map_err(|err| err.to_string())?;
        let state = target_state(&target).map_err(|err| err.to_string())?;
        Ok(ExportPlan { target, state })
    }

    /// Writes the export, then looks (read-only) at whether the ssh config
    /// includes it.
    fn export(&self, hosts: &Hosts) -> Result<ExportDone, String> {
        let (dir, target) = self.export_target()?;
        export_to(hosts, &target).map_err(|err| err.to_string())?;
        let include = find_include(&dir.join("config"), dir, dir.parent(), &target)
            .map_err(|err| format!("Could not read {}: {err}", dir.join("config").display()));
        Ok(ExportDone { target, include })
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

/// What importing `source` would do, with `resolver` to ask what ssh makes of
/// each host. Free of the terminal so that it can be tested with a fake ssh.
pub fn preview_with(
    resolver: &dyn SshResolver,
    source: &ImportSource,
    existing: &Hosts,
) -> Result<ImportPreview, String> {
    let report = import_hosts(existing, source, resolver).map_err(|err| err.to_string())?;
    Ok(ImportPreview {
        config_exists: source.config.exists(),
        config: source.config.clone(),
        report,
    })
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

    // ---- the ssh config ---------------------------------------------------------

    use crate::ssh::agent::AgentState;
    use crate::ssh::export::{GENERATED_HEADER, INCLUDE_LINE};
    use crate::ssh::import::ResolveError;
    use std::fs;

    #[derive(Debug, Clone, Copy)]
    struct NoTerminal;

    impl TerminalOps for NoTerminal {
        fn enter(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn leave(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn programs(ssh: Result<PathBuf, SshNotFound>) -> Programs {
        Programs {
            ssh,
            keygen: Err(KeygenNotFound),
            ssh_add: Err(SshAddNotFound),
        }
    }

    /// A home with a `.ssh` in it, and a `System` for it.
    fn with_system<T>(
        ssh: Result<PathBuf, SshNotFound>,
        files: &[(&str, &str)],
        test: impl FnOnce(&mut System<'_, NoTerminal>, &Path) -> T,
    ) -> T {
        let home = tempfile::tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir(&ssh_dir).unwrap();
        for (name, text) in files {
            fs::write(ssh_dir.join(name), text).unwrap();
        }
        let mut guard = TerminalGuard::enter(NoTerminal).unwrap();
        let mut system = System::new(&mut guard, programs(ssh), Some(ssh_dir.clone()));
        test(&mut system, &ssh_dir)
    }

    fn two_hosts() -> Hosts {
        Hosts::from_vec(vec![
            Host::new("web", "web.example.com"),
            Host::new("db", "db.example.com"),
        ])
        .unwrap()
    }

    #[test]
    fn the_ssh_config_requests_do_not_take_the_terminal() {
        for request in [
            Request::PreviewImport {
                existing: two_hosts(),
            },
            Request::PlanExport { hosts: two_hosts() },
            Request::Export { hosts: two_hosts() },
        ] {
            assert!(!request.gives_away_terminal(), "{request:?}");
        }
    }

    #[test]
    fn planning_an_export_says_where_and_what_is_there_and_writes_nothing() {
        with_system(Err(SshNotFound), &[], |system, dir| {
            let target = dir.join(EXPORT_FILE_NAME);
            let plan = system.plan_export(&two_hosts()).unwrap();
            assert_eq!(
                plan,
                ExportPlan {
                    target: target.clone(),
                    state: TargetState::Missing
                }
            );
            assert!(!target.exists(), "planning writes nothing");

            fs::write(&target, format!("{GENERATED_HEADER}\n")).unwrap();
            assert_eq!(
                system.plan_export(&two_hosts()).unwrap().state,
                TargetState::Generated
            );
            fs::write(&target, "Host mine\n").unwrap();
            assert_eq!(
                system.plan_export(&two_hosts()).unwrap().state,
                TargetState::NotGenerated
            );
            assert_eq!(fs::read_to_string(&target).unwrap(), "Host mine\n");
        });
    }

    #[test]
    fn an_export_writes_the_file_and_never_touches_the_ssh_config() {
        let config = "# mine\nHost web\n  User me\n";
        with_system(Err(SshNotFound), &[("config", config)], |system, dir| {
            let done = system.export(&two_hosts()).unwrap();
            let target = dir.join(EXPORT_FILE_NAME);
            assert_eq!(done.target, target);
            let written = fs::read_to_string(&target).unwrap();
            assert!(written.starts_with(GENERATED_HEADER), "{written}");
            assert!(written.contains("Host web") && written.contains("Host db"));
            // Nothing in the user's config was written, not even the include.
            assert_eq!(fs::read_to_string(dir.join("config")).unwrap(), config);
            assert!(
                !fs::read_to_string(dir.join("config"))
                    .unwrap()
                    .contains(INCLUDE_LINE)
            );
            assert_eq!(done.include, Ok(IncludeStatus::Missing));
        });
    }

    #[test]
    fn an_export_says_whether_the_ssh_config_includes_it() {
        let cases = [
            (None, IncludeStatus::NoConfigFile),
            (
                Some("Include ~/.ssh/bifrost_config\n"),
                IncludeStatus::Found,
            ),
            (
                Some("Host x\nInclude ~/.ssh/bifrost_config\n"),
                IncludeStatus::FoundInsideBlock,
            ),
            (Some("Host x\n  User y\n"), IncludeStatus::Missing),
        ];
        for (config, expected) in cases {
            let files: Vec<(&str, &str)> = config.map(|c| ("config", c)).into_iter().collect();
            with_system(Err(SshNotFound), &files, |system, _| {
                let done = system.export(&two_hosts()).unwrap();
                assert_eq!(done.include, Ok(expected), "{config:?}");
            });
        }
    }

    #[test]
    fn an_export_refuses_a_file_it_did_not_make_and_leaves_it_alone() {
        with_system(
            Err(SshNotFound),
            &[(EXPORT_FILE_NAME, "Host precious\n")],
            |system, dir| {
                let why = system.export(&two_hosts()).unwrap_err();
                assert!(
                    why.contains("was not generated by Bifrost") && why.contains("left alone"),
                    "{why}"
                );
                assert_eq!(
                    fs::read_to_string(dir.join(EXPORT_FILE_NAME)).unwrap(),
                    "Host precious\n"
                );
            },
        );
    }

    #[test]
    fn without_a_home_none_of_it_can_be_done_and_it_says_so() {
        let mut guard = TerminalGuard::enter(NoTerminal).unwrap();
        // ssh is found, so that what is missing is only the home directory.
        let system = System::new(
            &mut guard,
            programs(Ok(PathBuf::from("/usr/bin/ssh"))),
            None,
        );
        for result in [
            system.plan_export(&two_hosts()).map(|_| ()),
            system.export(&two_hosts()).map(|_| ()),
            system.preview_import(&two_hosts()).map(|_| ()),
        ] {
            assert!(result.unwrap_err().contains("home directory"));
        }
    }

    #[test]
    fn importing_without_ssh_says_what_to_install() {
        with_system(Err(SshNotFound), &[], |system, _| {
            let why = system.preview_import(&two_hosts()).map(|_| ()).unwrap_err();
            assert_eq!(why, SshNotFound.to_string());
        });
    }

    /// A resolver that answers `ssh -G` for names in a list and fails for others.
    struct FakeSsh(Vec<(&'static str, &'static str)>);

    impl SshResolver for FakeSsh {
        fn resolve(&self, name: &str) -> Result<String, ResolveError> {
            match self.0.iter().find(|(known, _)| *known == name) {
                Some((_, output)) => Ok((*output).to_string()),
                None => Err(ResolveError::Failed(format!("no such host {name}"))),
            }
        }
    }

    fn source_in(dir: &Path) -> ImportSource {
        ImportSource {
            config: dir.join("config"),
            ssh_dir: dir.to_path_buf(),
            home: dir.parent().map(Path::to_path_buf),
        }
    }

    #[test]
    fn a_preview_holds_what_importing_would_do_and_saves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("config"),
            "Host web\nHost app\nHost broken\n",
        )
        .unwrap();
        let resolver = FakeSsh(vec![
            ("web", "hostname web.example.com\nuser me\nport 22\n"),
            ("app", "hostname app.example.com\nuser deploy\nport 2222\n"),
        ]);
        let existing = two_hosts();
        let preview = preview_with(&resolver, &source_in(dir.path()), &existing).unwrap();
        assert!(preview.config_exists);
        assert_eq!(preview.config, dir.path().join("config"));
        assert_eq!(preview.report.imported, ["app"]);
        assert_eq!(preview.report.conflicts, ["web"]);
        assert_eq!(preview.report.skipped.len(), 1);
        assert_eq!(preview.report.skipped[0].name, "broken");
        // The saved hosts are what they were; the report holds the new set.
        assert_eq!(existing, two_hosts());
        assert_eq!(preview.report.hosts.len(), 3);
    }

    #[test]
    fn a_missing_config_is_an_empty_preview_and_a_broken_ssh_is_an_error_in_words() {
        let dir = tempfile::tempdir().unwrap();
        let empty =
            preview_with(&FakeSsh(Vec::new()), &source_in(dir.path()), &two_hosts()).unwrap();
        assert!(!empty.config_exists);
        assert!(empty.report.imported.is_empty() && empty.report.skipped.is_empty());

        struct Unavailable;
        impl SshResolver for Unavailable {
            fn resolve(&self, _: &str) -> Result<String, ResolveError> {
                Err(ResolveError::Unavailable("it is not there".to_string()))
            }
        }
        fs::write(dir.path().join("config"), "Host app\n").unwrap();
        let why = preview_with(&Unavailable, &source_in(dir.path()), &two_hosts())
            .map(|_| ())
            .unwrap_err();
        assert_eq!(why, "Could not run ssh: it is not there");
    }

    #[test]
    fn reading_the_keys_to_choose_one_does_not_take_the_terminal() {
        assert!(!Request::ListKeys.gives_away_terminal());
    }

    #[test]
    fn the_list_of_keys_is_read_without_the_agent_and_says_when_it_cannot_be() {
        with_system(
            Err(SshNotFound),
            &[("id_ed25519", "x"), ("id_ed25519.pub", "x")],
            |system, dir| {
                let Response::KeyList(snapshot) = system.execute(&Request::ListKeys).unwrap()
                else {
                    panic!("a list of keys");
                };
                assert_eq!(snapshot.dir, dir);
                assert_eq!(snapshot.keys.len(), 1);
                assert_eq!(snapshot.keys[0].name, "id_ed25519");
                // ssh-keygen is not found here, and that is said per key, not fatal.
                assert!(snapshot.keys[0].fingerprint.is_err());
                assert!(snapshot.keys.iter().all(|key| key.loaded.is_none()));
                assert!(matches!(snapshot.agent, AgentState::Unavailable(_)));
            },
        );

        let mut guard = TerminalGuard::enter(NoTerminal).unwrap();
        let mut system = System::new(&mut guard, programs(Err(SshNotFound)), None);
        let Response::KeyList(snapshot) = system.execute(&Request::ListKeys).unwrap() else {
            panic!("a list of keys");
        };
        assert!(snapshot.keys.is_empty());
        assert!(
            snapshot
                .problem
                .as_deref()
                .is_some_and(|p| p.contains("home directory"))
        );
    }

    #[test]
    fn deleting_a_key_does_not_take_the_terminal() {
        assert!(
            !Request::DeleteKey {
                file_name: "k".to_string()
            }
            .gives_away_terminal()
        );
    }

    #[test]
    fn deleting_a_key_removes_the_pair_and_only_the_pair() {
        with_system(
            Err(SshNotFound),
            &[
                ("k", "s"),
                ("k.pub", "p"),
                ("other", "o"),
                ("other.pub", "p"),
                ("config", "c"),
            ],
            |system, dir| {
                let request = Request::DeleteKey {
                    file_name: "k".to_string(),
                };
                let Response::KeyDeleted(Ok(done)) = system.execute(&request).unwrap() else {
                    panic!("it was deleted");
                };
                assert_eq!(done.private, dir.join("k"));
                assert_eq!(done.public, dir.join("k.pub"));
                assert!(!dir.join("k").exists() && !dir.join("k.pub").exists());
                for kept in ["other", "other.pub", "config"] {
                    assert!(dir.join(kept).exists(), "{kept}");
                }
            },
        );
    }

    #[test]
    fn deleting_what_is_not_a_key_pair_is_refused_in_words_and_touches_nothing() {
        with_system(
            Err(SshNotFound),
            &[("config", "c"), ("config.pub", "p"), ("alone", "a")],
            |system, dir| {
                for name in ["config", "alone", "../x", "missing"] {
                    let request = Request::DeleteKey {
                        file_name: name.to_string(),
                    };
                    let Response::KeyDeleted(Err(why)) = system.execute(&request).unwrap() else {
                        panic!("{name} was refused");
                    };
                    assert!(why.contains("nothing was deleted"), "{name}: {why}");
                }
                assert!(
                    dir.join("config").exists()
                        && dir.join("config.pub").exists()
                        && dir.join("alone").exists()
                );
            },
        );
    }

    #[test]
    fn deleting_a_key_without_a_home_says_so() {
        let mut guard = TerminalGuard::enter(NoTerminal).unwrap();
        let mut system = System::new(&mut guard, programs(Err(SshNotFound)), None);
        let request = Request::DeleteKey {
            file_name: "k".to_string(),
        };
        let Response::KeyDeleted(Err(why)) = system.execute(&request).unwrap() else {
            panic!("refused");
        };
        assert!(why.contains("home directory"), "{why}");
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
