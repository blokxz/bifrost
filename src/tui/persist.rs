//! Saving hosts, behind a trait.
//!
//! The TUI never touches the file system itself: it asks a [`HostStore`] to save
//! the whole collection. The real store is [`crate::store::Store`] (atomic
//! writes, backup, refusal to overwrite a file it cannot read); tests plug in a
//! fake to check what would be saved and how failures are handled.

use std::fmt::Debug;
use std::path::Path;

use crate::domain::Hosts;
use crate::store::{Store, StoreError};

pub trait HostStore: Debug {
    /// Saves the whole collection.
    fn save(&self, hosts: &Hosts) -> Result<(), StoreError>;

    /// The home directory used to expand `~` in identity file paths, if known.
    fn home(&self) -> Option<&Path>;
}

impl HostStore for Store {
    fn save(&self, hosts: &Hosts) -> Result<(), StoreError> {
        Store::save(self, hosts)
    }

    fn home(&self) -> Option<&Path> {
        Store::home(self)
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Host;

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
