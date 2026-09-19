//! What the TUI needs to know about the store when it opens.
//!
//! The store may fail to load, and the TUI must still open and explain why. This
//! module turns the load result into plain data: the hosts with the store that
//! saves them, or, when loading failed, only a notice explaining what is wrong.
//! [`super::app::App`] and the rendering code never depend on store types.

use super::persist::HostStore;
use crate::domain::Hosts;
use crate::store::{Loaded, StoreError};

/// How serious a [`Notice`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Something is broken and the user has to act.
    Error,
    /// Something is off but Bifrost keeps working.
    Warning,
}

/// A problem to explain to the user, in plain English.
///
/// The text may be several lines and may contain external content (paths, file
/// excerpts). It is sanitized when rendered, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub severity: Severity,
    pub text: String,
}

impl Notice {
    pub fn error(text: impl Into<String>) -> Self {
        Notice {
            severity: Severity::Error,
            text: text.into(),
        }
    }

    pub fn warning(text: impl Into<String>) -> Self {
        Notice {
            severity: Severity::Warning,
            text: text.into(),
        }
    }
}

/// The hosts, together with the store that saves them.
#[derive(Debug)]
pub struct Library {
    pub hosts: Hosts,
    pub store: Box<dyn HostStore>,
}

/// The outcome of loading the store, as the TUI starts with it.
#[derive(Debug)]
pub struct Startup {
    /// `None` when the store could not be read. Without it hosts cannot be
    /// shown or changed, which also means a damaged file is never overwritten.
    pub library: Option<Library>,
    pub notices: Vec<Notice>,
}

impl Startup {
    /// Hosts that loaded, with the store to save them to.
    pub fn loaded(hosts: Hosts, store: impl HostStore + 'static, notices: Vec<Notice>) -> Self {
        Startup {
            library: Some(Library {
                hosts,
                store: Box::new(store),
            }),
            notices,
        }
    }

    /// Converts the result of locating and loading the store.
    pub fn from_load<S: HostStore + 'static>(result: Result<(S, Loaded), StoreError>) -> Self {
        match result {
            Ok((store, loaded)) => {
                let notices = loaded
                    .warnings
                    .iter()
                    .map(|warning| Notice::warning(warning.message()))
                    .collect();
                Startup::loaded(loaded.hosts, store, notices)
            }
            Err(err) => Startup {
                library: None,
                notices: vec![Notice::error(format!(
                    "Bifrost could not read your saved hosts.\n{err}"
                ))],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Host, Warning};
    use crate::store::{HOSTS_FILE, Store};
    use crate::tui::persist::testing::FakeStore;

    fn loaded(hosts: Hosts, warnings: Vec<Warning>) -> Result<(FakeStore, Loaded), StoreError> {
        Ok((FakeStore::default(), Loaded { hosts, warnings }))
    }

    #[test]
    fn a_clean_load_has_the_hosts_and_no_notices() {
        let mut hosts = Hosts::new();
        hosts.add(Host::new("web", "192.0.2.1")).unwrap();
        hosts.add(Host::new("db", "192.0.2.2")).unwrap();
        let startup = Startup::from_load(loaded(hosts, Vec::new()));
        assert_eq!(startup.library.unwrap().hosts.len(), 2);
        assert!(startup.notices.is_empty());
    }

    #[test]
    fn load_warnings_become_warning_notices() {
        let startup = Startup::from_load(loaded(
            Hosts::new(),
            vec![Warning::new("file is readable by others")],
        ));
        assert!(startup.library.is_some());
        assert_eq!(
            startup.notices,
            [Notice::warning("file is readable by others")]
        );
    }

    #[test]
    fn an_unreadable_store_becomes_an_error_that_explains_recovery() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(HOSTS_FILE),
            "version = 1\n\n[[hosts]]\nname = \"bad name\"\nhostname = \"192.0.2.1\"\n",
        )
        .unwrap();
        let store = Store::at(dir.path()).with_home(None);

        let startup = Startup::from_load(store.load().map(|loaded| (store, loaded)));

        assert!(
            startup.library.is_none(),
            "no hosts, so nothing can be saved"
        );
        let [notice] = startup.notices.as_slice() else {
            panic!("expected exactly one notice: {:?}", startup.notices);
        };
        assert_eq!(notice.severity, Severity::Error);
        assert!(
            notice
                .text
                .starts_with("Bifrost could not read your saved hosts.")
        );
        assert!(notice.text.contains(HOSTS_FILE), "{}", notice.text);
        assert!(notice.text.contains("line 3"), "{}", notice.text);
        assert!(notice.text.contains("hosts.toml.bak"), "{}", notice.text);
    }

    #[test]
    fn a_failure_to_locate_the_store_is_also_an_error_notice() {
        let err = StoreError::RelativeConfigDir("relative/dir".into());
        let startup = Startup::from_load::<FakeStore>(Err(err));
        assert!(startup.library.is_none());
        assert_eq!(startup.notices[0].severity, Severity::Error);
        assert!(startup.notices[0].text.contains("absolute path"));
    }
}
