//! Saving hosts, behind a trait.
//!
//! The TUI never touches the file system itself: it asks a [`HostStore`] to save
//! the whole collection. The real store is [`crate::store::Store`] (atomic
//! writes, backup, refusal to overwrite a file it cannot read); tests plug in a
//! fake to check what would be saved and how failures are handled.

use std::fmt::Debug;
use std::path::Path;

use crate::domain::{Hosts, Warning};
use crate::store::{Store, StoreError};

pub trait HostStore: Debug {
    /// Saves the whole collection.
    fn save(&self, hosts: &Hosts) -> Result<(), StoreError>;

    /// The home directory used to expand `~` in identity file paths, if known.
    fn home(&self) -> Option<&Path>;

    /// What is worth warning about now: the same things the load reported, read
    /// from the disk again. The interface asks for these after every change that
    /// can make one appear or go away, so a warning never outlives its cause.
    fn warnings(&self, hosts: &Hosts) -> Vec<Warning>;
}

impl HostStore for Store {
    fn save(&self, hosts: &Hosts) -> Result<(), StoreError> {
        Store::save(self, hosts)
    }

    fn home(&self) -> Option<&Path> {
        Store::home(self)
    }

    fn warnings(&self, hosts: &Hosts) -> Vec<Warning> {
        Store::warnings(self, hosts)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;
    use std::rc::Rc;

    use super::*;

    /// A store that records what is saved and can be told to fail. Clones share
    /// their state, so a test keeps one and hands another to the app.
    #[derive(Debug, Clone, Default)]
    pub struct FakeStore {
        saved: Rc<RefCell<Vec<Hosts>>>,
        failing: Rc<Cell<bool>>,
        home: Option<PathBuf>,
        /// What the next [`HostStore::warnings`] answers, and how many times it
        /// has been asked. Shared, so a test can change the answer the way the
        /// disk would change under a running Bifrost.
        warnings: Rc<RefCell<Vec<Warning>>>,
        asked: Rc<Cell<usize>>,
    }

    impl FakeStore {
        pub fn with_home(home: PathBuf) -> Self {
            FakeStore {
                home: Some(home),
                ..FakeStore::default()
            }
        }

        pub fn fail_saves(&self, failing: bool) {
            self.failing.set(failing);
        }

        pub fn save_count(&self) -> usize {
            self.saved.borrow().len()
        }

        pub fn last_saved(&self) -> Option<Hosts> {
            self.saved.borrow().last().cloned()
        }

        /// What the store will report from now on.
        pub fn set_warnings(&self, warnings: Vec<Warning>) {
            *self.warnings.borrow_mut() = warnings;
        }

        /// How many times the app has asked for the warnings.
        pub fn warnings_asked(&self) -> usize {
            self.asked.get()
        }
    }

    impl HostStore for FakeStore {
        fn save(&self, hosts: &Hosts) -> Result<(), StoreError> {
            if self.failing.get() {
                return Err(StoreError::Io {
                    action: "write",
                    path: PathBuf::from("/fake/hosts.toml"),
                    source: std::io::Error::other("disk is full"),
                });
            }
            self.saved.borrow_mut().push(hosts.clone());
            Ok(())
        }

        fn home(&self) -> Option<&Path> {
            self.home.as_deref()
        }

        fn warnings(&self, _hosts: &Hosts) -> Vec<Warning> {
            self.asked.set(self.asked.get() + 1);
            self.warnings.borrow().clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Host;

    #[test]
    fn the_real_store_reads_its_warnings_again_each_time_it_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let store = Store::at(dir.path().join("bifrost")).with_home(Some(home.clone()));
        let mut host = Host::new("web", "192.0.2.1");
        host.identity_file = Some("~/.ssh/id_missing".to_string());
        let mut hosts = Hosts::new();
        hosts.add(host).unwrap();
        HostStore::save(&store, &hosts).unwrap();

        // The key is not there: one warning names the host.
        let warnings = HostStore::warnings(&store, &hosts);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].message().contains("web"), "{warnings:?}");

        // Making the key is all it takes for the warning to go: nothing is
        // cached, so the next question gets the new answer.
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_missing"), "key").unwrap();
        assert!(HostStore::warnings(&store, &hosts).is_empty());
    }

    #[test]
    fn the_real_store_saves_and_reports_its_home() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path().join("bifrost")).with_home(Some(dir.path().to_path_buf()));
        let mut hosts = Hosts::new();
        hosts.add(Host::new("web", "192.0.2.1")).unwrap();

        HostStore::save(&store, &hosts).unwrap();

        assert_eq!(store.load().unwrap().hosts, hosts);
        assert_eq!(HostStore::home(&store), Some(dir.path()));
    }
}
