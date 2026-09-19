//! What the TUI needs to know about the store when it opens.
//!
//! The store may fail to load, and the TUI must still open and explain why. This
//! module turns the load result into plain data, so that [`super::app::App`]
//! and the rendering code never depend on store types.

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

/// The outcome of loading the store, as the home screen shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Startup {
    /// `None` when the store could not be read.
    pub host_count: Option<usize>,
    pub notices: Vec<Notice>,
}

impl Startup {
    /// Converts the result of locating and loading the store.
    pub fn from_load(result: Result<Loaded, StoreError>) -> Self {
        match result {
            Ok(loaded) => Startup {
                host_count: Some(loaded.hosts.len()),
                notices: loaded
                    .warnings
                    .iter()
                    .map(|warning| Notice::warning(warning.message()))
                    .collect(),
            },
            Err(err) => Startup {
                host_count: None,
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
    use crate::domain::{Host, Hosts, Warning};
    use crate::store::{HOSTS_FILE, Store};

    #[test]
    fn a_clean_load_has_a_count_and_no_notices() {
        let mut hosts = Hosts::new();
        hosts.add(Host::new("web", "192.0.2.1")).unwrap();
        hosts.add(Host::new("db", "192.0.2.2")).unwrap();
        let startup = Startup::from_load(Ok(Loaded {
            hosts,
            warnings: Vec::new(),
        }));
        assert_eq!(startup.host_count, Some(2));
        assert!(startup.notices.is_empty());
    }

    #[test]
    fn load_warnings_become_warning_notices() {
        let startup = Startup::from_load(Ok(Loaded {
            hosts: Hosts::new(),
            warnings: vec![Warning::new("file is readable by others")],
        }));
        assert_eq!(startup.host_count, Some(0));
        assert_eq!(
            startup.notices,
            [Notice::warning("file is readable by others")]
        );
    }

    #[test]
    fn an_unreadable_store_becomes_an_error_that_explains_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(HOSTS_FILE);
        std::fs::write(
            &file,
            "version = 1\n\n[[hosts]]\nname = \"bad name\"\nhostname = \"192.0.2.1\"\n",
        )
        .unwrap();
        let store = Store::at(dir.path()).with_home(None);

        let startup = Startup::from_load(store.load());

        assert_eq!(startup.host_count, None);
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
        let startup = Startup::from_load(Err(err));
        assert_eq!(startup.host_count, None);
        assert_eq!(startup.notices[0].severity, Severity::Error);
        assert!(startup.notices[0].text.contains("absolute path"));
    }
}
