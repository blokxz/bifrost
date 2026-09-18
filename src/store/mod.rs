//! The Bifrost store: one TOML file (`hosts.toml`) that Bifrost owns.
//!
//! - Location: see [`paths::config_dir_for`]; `BIFROST_CONFIG_DIR` overrides it.
//! - Writes are atomic (temporary file + rename) and the previous version is
//!   kept as `hosts.toml.bak`.
//! - On Unix the directory is created 0700 and the files 0600; a broader mode
//!   found on load is reported as a warning. On Windows 0.1.0 relies on the ACLs
//!   inherited from `%APPDATA%` and does not verify them.
//! - A file that is invalid, or written by a newer Bifrost, is reported with its
//!   location and is never overwritten: [`Store::save`] refuses to replace a
//!   file that [`Store::load`] cannot read.
//! - The file holds no secrets: only paths to key files, never key material,
//!   passwords or passphrases.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::domain::{Hosts, ValidationError, Warning};
use crate::sysenv::{self, Env, Platform};

mod format;
pub(crate) mod fsutil;
pub mod paths;

pub use format::CURRENT_VERSION;

/// File name of the store inside the config directory.
pub const HOSTS_FILE: &str = "hosts.toml";

/// What [`Store::load`] returns.
#[derive(Debug)]
pub struct Loaded {
    pub hosts: Hosts,
    /// Non-fatal problems: broad file permissions, missing identity files.
    pub warnings: Vec<Warning>,
}

/// Everything that can go wrong reading or writing the store.
#[derive(Debug)]
pub enum StoreError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The file is not valid TOML or does not match the schema.
    Parse {
        path: PathBuf,
        backup: PathBuf,
        message: String,
    },
    /// The file parses but contains an invalid host.
    Invalid {
        path: PathBuf,
        backup: PathBuf,
        error: Box<ValidationError>,
        line: Option<usize>,
    },
    MissingVersion {
        path: PathBuf,
        backup: PathBuf,
    },
    BadVersion {
        path: PathBuf,
        backup: PathBuf,
        found: i64,
    },
    /// The file was written by a newer Bifrost.
    NewerVersion {
        path: PathBuf,
        found: i64,
        supported: u32,
    },
    /// `save` found an existing file it cannot load and left it untouched.
    RefuseOverwrite {
        path: PathBuf,
        reason: Box<StoreError>,
    },
    Serialize(String),
    RelativeConfigDir(PathBuf),
    NoConfigDir(String),
}

impl StoreError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        StoreError::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

fn recovery_hint(backup: &Path) -> String {
    format!(
        "Fix the reported line in the file, or restore the previous version from {}. \
         Bifrost has not changed the file.",
        backup.display()
    )
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io {
                action,
                path,
                source,
            } => write!(f, "Could not {action} {}: {source}", path.display()),
            StoreError::Parse {
                path,
                backup,
                message,
            } => write!(
                f,
                "{} is not valid: {}\n{}",
                path.display(),
                message.trim_end(),
                recovery_hint(backup)
            ),
            StoreError::Invalid {
                path,
                backup,
                error,
                line,
            } => {
                let at = line.map(|n| format!(" (line {n})")).unwrap_or_default();
                write!(
                    f,
                    "{} contains an invalid host{at}: {error}\n{}",
                    path.display(),
                    recovery_hint(backup)
                )
            }
            StoreError::MissingVersion { path, backup } => write!(
                f,
                "{} has no `version = 1` line at the top.\n{}",
                path.display(),
                recovery_hint(backup)
            ),
            StoreError::BadVersion {
                path,
                backup,
                found,
            } => write!(
                f,
                "{} has an invalid version ({found}); expected version {CURRENT_VERSION}.\n{}",
                path.display(),
                recovery_hint(backup)
            ),
            StoreError::NewerVersion {
                path,
                found,
                supported,
            } => write!(
                f,
                "{} was written by a newer version of Bifrost (file format version {found}; \
                 this version understands up to {supported}). Upgrade Bifrost to open it. \
                 Bifrost has not changed the file.",
                path.display()
            ),
            StoreError::RefuseOverwrite { path, reason } => write!(
                f,
                "Refusing to overwrite {} because Bifrost cannot read it. {reason}",
                path.display()
            ),
            StoreError::Serialize(message) => {
                write!(f, "Could not encode the hosts as TOML: {message}")
            }
            StoreError::RelativeConfigDir(path) => write!(
                f,
                "{} is set to '{}', which is a relative path; it must be an absolute path.",
                paths::CONFIG_DIR_VAR,
                path.display()
            ),
            StoreError::NoConfigDir(reason) => write!(
                f,
                "Could not determine the Bifrost config directory: {reason}. \
                 Set {} to an absolute path to choose one.",
                paths::CONFIG_DIR_VAR
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io { source, .. } => Some(source),
            StoreError::Invalid { error, .. } => Some(error.as_ref()),
            StoreError::RefuseOverwrite { reason, .. } => Some(reason.as_ref()),
            _ => None,
        }
    }
}

/// Handle to a Bifrost config directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    /// Used to expand `~` when checking that identity files exist.
    home: Option<PathBuf>,
}

impl Store {
    /// A store in an explicit directory. Nothing is created until `save`.
    ///
    /// It has no home directory, so identity files written as `~/...` are not
    /// checked for existence; see [`Store::with_home`].
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Store {
            dir: dir.into(),
            home: None,
        }
    }

    /// Sets the home directory used to expand `~` in identity file paths.
    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    /// A store in the platform's config directory, honoring `BIFROST_CONFIG_DIR`.
    /// The home directory is taken from the same environment.
    pub fn from_env(env: Env<'_>) -> Result<Self, StoreError> {
        let home = sysenv::home_dir(Platform::current(), env);
        paths::config_dir(env).map(|dir| Store::at(dir).with_home(home))
    }

    /// A store in the real config directory of the running process.
    pub fn from_process_env() -> Result<Self, StoreError> {
        Store::from_env(&sysenv::process_env)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn hosts_path(&self) -> PathBuf {
        self.dir.join(HOSTS_FILE)
    }

    pub fn backup_path(&self) -> PathBuf {
        fsutil::backup_path(&self.hosts_path())
    }

    /// Reads the store. A missing file is an empty store.
    ///
    /// A file that is invalid or newer than this build is an error naming the
    /// file; it is never modified.
    pub fn load(&self) -> Result<Loaded, StoreError> {
        let path = self.hosts_path();
        let Some(bytes) = read_optional(&path)? else {
            return Ok(Loaded {
                hosts: Hosts::new(),
                warnings: Vec::new(),
            });
        };
        let hosts = self.parse(&bytes)?;
        let mut warnings = fsutil::permission_warnings(&[
            (self.dir.as_path(), fsutil::Kind::Dir),
            (path.as_path(), fsutil::Kind::File),
        ]);
        warnings.extend(hosts.warnings(self.home.as_deref()));
        Ok(Loaded { hosts, warnings })
    }

    /// Writes the store atomically, keeping the previous version as
    /// `hosts.toml.bak`.
    ///
    /// If a file already exists that [`Store::load`] could not read (invalid or
    /// from a newer Bifrost), nothing is written and
    /// [`StoreError::RefuseOverwrite`] is returned.
    pub fn save(&self, hosts: &Hosts) -> Result<(), StoreError> {
        let path = self.hosts_path();
        let backup = self.backup_path();

        fsutil::ensure_private_dir(&self.dir)
            .map_err(|err| StoreError::io("create the directory", &self.dir, err))?;

        let previous = read_optional(&path)?;
        if let Some(bytes) = &previous {
            self.parse(bytes)
                .map_err(|reason| StoreError::RefuseOverwrite {
                    path: path.clone(),
                    reason: Box::new(reason),
                })?;
        }

        let text = format::serialize(hosts)?;

        if let Some(bytes) = previous {
            fsutil::atomic_write(&backup, &bytes)
                .map_err(|err| StoreError::io("write the backup", &backup, err))?;
        }
        fsutil::atomic_write(&path, text.as_bytes())
            .map_err(|err| StoreError::io("write", &path, err))
    }

    fn parse(&self, bytes: &[u8]) -> Result<Hosts, StoreError> {
        let path = self.hosts_path();
        let backup = self.backup_path();
        let text = std::str::from_utf8(bytes).map_err(|_| StoreError::Parse {
            path: path.clone(),
            backup: backup.clone(),
            message: "the file is not valid UTF-8 text".to_string(),
        })?;
        format::parse(text, &path, &backup)
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(StoreError::io("read", path, err)),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::domain::{Forward, Host};
    use crate::sysenv::testing::{abs, fake_env};

    fn host(name: &str) -> Host {
        Host::new(name, format!("{name}.example.com"))
    }

    fn sample_hosts() -> Hosts {
        let mut web = host("web");
        web.user = Some("deploy".into());
        web.port = Some(2222);
        web.proxy_jump = Some("bastion".into());
        web.favorite = true;
        web.tags = vec!["prod".into()];
        web.notes = Some("line one\nline two".into());
        web.local_forwards = vec![Forward {
            listen_port: 8080,
            dest_host: "localhost".into(),
            dest_port: 80,
        }];
        Hosts::from_vec(vec![host("bastion"), web]).unwrap()
    }

    fn store_in(dir: &tempfile::TempDir) -> Store {
        // A directory that does not exist yet, to cover directory creation.
        Store::at(dir.path().join("bifrost"))
    }

    #[test]
    fn missing_file_loads_as_an_empty_store_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let loaded = store.load().unwrap();
        assert!(loaded.hosts.is_empty());
        assert!(loaded.warnings.is_empty());
        assert!(!store.dir().exists());
    }

    #[test]
    fn roundtrip_preserves_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let hosts = sample_hosts();
        store.save(&hosts).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.hosts, hosts);

        let text = fs::read_to_string(store.hosts_path()).unwrap();
        assert!(text.starts_with("version = 1\n"), "{text}");
    }

    #[test]
    fn saving_twice_keeps_the_previous_version_as_backup() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        assert!(
            !store.backup_path().exists(),
            "no backup before the first save"
        );

        let mut hosts = sample_hosts();
        store.save(&hosts).unwrap();
        assert!(!store.backup_path().exists(), "nothing to back up yet");
        let first = fs::read(store.hosts_path()).unwrap();

        hosts.add(host("extra")).unwrap();
        store.save(&hosts).unwrap();
        assert_eq!(fs::read(store.backup_path()).unwrap(), first);
        assert_eq!(store.load().unwrap().hosts, hosts);

        // The backup is itself a loadable store from the previous state.
        let restored = Store::at(dir.path().join("restored"));
        fs::create_dir(restored.dir()).unwrap();
        fs::copy(store.backup_path(), restored.hosts_path()).unwrap();
        assert_eq!(restored.load().unwrap().hosts, sample_hosts());
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        store.save(&sample_hosts()).unwrap();
        store.save(&sample_hosts()).unwrap();
        let mut names: Vec<String> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["hosts.toml", "hosts.toml.bak"]);
    }

    #[test]
    fn renames_persist_with_updated_references() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let mut hosts = sample_hosts();
        store.save(&hosts).unwrap();

        hosts.rename("bastion", "gateway").unwrap();
        store.save(&hosts).unwrap();
        let loaded = store.load().unwrap().hosts;
        assert_eq!(
            loaded.get("web").unwrap().proxy_jump.as_deref(),
            Some("gateway")
        );
    }

    fn write_raw(store: &Store, contents: &[u8]) {
        fs::create_dir_all(store.dir()).unwrap();
        fs::write(store.hosts_path(), contents).unwrap();
    }

    fn assert_untouched_after_refused_save(store: &Store, original: &[u8]) {
        let err = store.save(&sample_hosts()).unwrap_err();
        assert!(matches!(err, StoreError::RefuseOverwrite { .. }), "{err:?}");
        assert!(err.to_string().contains("Refusing to overwrite"), "{err}");
        assert_eq!(fs::read(store.hosts_path()).unwrap(), original);
        assert!(!store.backup_path().exists(), "no backup of a broken file");
    }

    #[test]
    fn corrupt_files_are_reported_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let original = b"version = 1\n[[hosts]\nthis is not toml";
        write_raw(&store, original);

        let err = store.load().unwrap_err();
        assert!(matches!(err, StoreError::Parse { .. }), "{err:?}");
        let message = err.to_string();
        assert!(
            message.contains(&store.hosts_path().display().to_string()),
            "{message}"
        );
        assert!(message.contains("line 2"), "{message}");
        assert_untouched_after_refused_save(&store, original);
    }

    #[test]
    fn binary_garbage_is_reported_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let original: &[u8] = &[0xff, 0xfe, 0x00, 0x9f, 0x92];
        write_raw(&store, original);
        let err = store.load().unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
        assert_untouched_after_refused_save(&store, original);
    }

    #[test]
    fn empty_file_is_reported_as_missing_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        write_raw(&store, b"");
        assert!(matches!(
            store.load().unwrap_err(),
            StoreError::MissingVersion { .. }
        ));
        assert_untouched_after_refused_save(&store, b"");
    }

    #[test]
    fn newer_versions_are_reported_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let original = b"version = 2\n[[hosts]]\nname = \"a\"\nfuture_field = true\n";
        write_raw(&store, original);

        let err = store.load().unwrap_err();
        assert!(
            matches!(err, StoreError::NewerVersion { found: 2, .. }),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(message.contains("newer version of Bifrost"), "{message}");
        assert!(
            message.contains(&store.hosts_path().display().to_string()),
            "{message}"
        );
        assert_untouched_after_refused_save(&store, original);
    }

    #[test]
    fn invalid_hosts_point_at_the_line_and_at_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let original =
            b"version = 1\n\n[[hosts]]\nname = \"web\"\nhostname = \"-oProxyCommand=id\"\n";
        write_raw(&store, original);

        let err = store.load().unwrap_err();
        assert!(
            matches!(err, StoreError::Invalid { line: Some(3), .. }),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(message.contains("(line 3)"), "{message}");
        assert!(message.contains("Host 'web'"), "{message}");
        assert!(
            message.contains("Hostname must not start with '-'"),
            "{message}"
        );
        assert!(message.contains("Fix the reported line"), "{message}");
        assert!(
            message.contains("restore the previous version from"),
            "{message}"
        );
        assert!(message.contains("hosts.toml.bak"), "{message}");
        assert_untouched_after_refused_save(&store, original);
    }

    #[test]
    fn every_load_failure_mentions_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        for original in [
            &b"version = 1\n[[hosts]\n"[..],
            b"[[hosts]]\nname = \"a\"\nhostname = \"a.example.com\"\n",
            b"version = 0\n",
            b"version = 1\n[[hosts]]\nname = \"a\"\nhostname = \"a.example.com\"\nport = 0\n",
        ] {
            write_raw(&store, original);
            let message = store.load().unwrap_err().to_string();
            assert!(message.contains("hosts.toml.bak"), "{message}");
            assert!(message.contains("Fix the reported line"), "{message}");
        }
    }

    #[test]
    fn a_fixed_file_can_be_saved_again() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        write_raw(&store, b"garbage");
        assert!(store.save(&sample_hosts()).is_err());
        write_raw(&store, b"version = 1\n");
        store.save(&sample_hosts()).unwrap();
        assert_eq!(store.load().unwrap().hosts, sample_hosts());
    }

    #[test]
    fn config_directory_override_must_be_absolute() {
        let env = fake_env(&[(paths::CONFIG_DIR_VAR, OsString::from("relative/bifrost"))]);
        let err = Store::from_env(&env).unwrap_err();
        assert!(matches!(err, StoreError::RelativeConfigDir(_)));
        assert!(err.to_string().contains("BIFROST_CONFIG_DIR"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let env = fake_env(&[(paths::CONFIG_DIR_VAR, dir.path().as_os_str().to_owned())]);
        assert_eq!(Store::from_env(&env).unwrap().dir(), dir.path());
    }

    #[test]
    fn from_env_uses_the_platform_default_without_an_override() {
        let env = fake_env(&[
            ("HOME", abs("home/rein").into_os_string()),
            ("APPDATA", abs("appdata").into_os_string()),
        ]);
        let store = Store::from_env(&env).unwrap();
        assert!(store.dir().ends_with("bifrost"));
        assert!(store.hosts_path().ends_with("bifrost/hosts.toml"));
    }

    #[cfg(unix)]
    mod unix {
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        #[test]
        fn save_creates_a_user_only_directory_and_files() {
            let dir = tempfile::tempdir().unwrap();
            let store = store_in(&dir);
            store.save(&sample_hosts()).unwrap();
            store.save(&sample_hosts()).unwrap();
            assert_eq!(mode(store.dir()), 0o700);
            assert_eq!(mode(&store.hosts_path()), 0o600);
            assert_eq!(mode(&store.backup_path()), 0o600);
        }

        #[test]
        fn load_warns_about_broad_permissions_and_does_not_change_them() {
            let dir = tempfile::tempdir().unwrap();
            let store = store_in(&dir);
            store.save(&sample_hosts()).unwrap();
            assert!(store.load().unwrap().warnings.is_empty());

            fs::set_permissions(store.hosts_path(), fs::Permissions::from_mode(0o644)).unwrap();
            fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o755)).unwrap();
            let warnings = store.load().unwrap().warnings;
            assert_eq!(warnings.len(), 2, "{warnings:?}");
            assert!(warnings.iter().any(|w| w.message().contains("chmod 700")));
            assert!(warnings.iter().any(|w| w.message().contains("chmod 600")));
            assert_eq!(mode(&store.hosts_path()), 0o644);
            assert_eq!(mode(store.dir()), 0o755);
        }

        #[test]
        fn saving_over_a_broad_file_makes_it_user_only_again() {
            let dir = tempfile::tempdir().unwrap();
            let store = store_in(&dir);
            store.save(&sample_hosts()).unwrap();
            fs::set_permissions(store.hosts_path(), fs::Permissions::from_mode(0o644)).unwrap();
            store.save(&sample_hosts()).unwrap();
            assert_eq!(mode(&store.hosts_path()), 0o600);
        }
    }

    #[test]
    fn missing_identity_files_surface_as_load_warnings() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let mut hosts = Hosts::new();
        let mut web = host("web");
        web.identity_file = Some(dir.path().join("absent_key").to_string_lossy().into_owned());
        hosts.add(web).unwrap();
        assert_eq!(hosts.warnings(None).len(), 1);
        store.save(&hosts).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.hosts, hosts);
        assert!(
            loaded
                .warnings
                .iter()
                .any(|w| w.message().contains("does not exist")),
            "{:?}",
            loaded.warnings
        );
    }

    #[test]
    fn tilde_identity_files_are_checked_against_the_injected_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::write(home.join("present_key"), "x").unwrap();

        let mut hosts = Hosts::new();
        let mut present = host("present");
        present.identity_file = Some("~/present_key".into());
        let mut absent = host("absent");
        absent.identity_file = Some("~/absent_key".into());
        hosts.add(present).unwrap();
        hosts.add(absent).unwrap();

        let without_home = store_in(&dir);
        without_home.save(&hosts).unwrap();
        assert!(
            without_home.load().unwrap().warnings.is_empty(),
            "`~` paths cannot be checked without a home directory"
        );

        let with_home = store_in(&dir).with_home(Some(home));
        let warnings = with_home.load().unwrap().warnings;
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].message().contains("Host 'absent'"));
    }

    #[test]
    fn from_env_takes_the_home_directory_from_the_given_environment() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        let config = dir.path().join("config");
        let env = fake_env(&[
            (paths::CONFIG_DIR_VAR, config.as_os_str().to_owned()),
            ("HOME", home.as_os_str().to_owned()),
            ("USERPROFILE", home.as_os_str().to_owned()),
        ]);

        let mut hosts = Hosts::new();
        let mut web = host("web");
        web.identity_file = Some("~/missing_key".into());
        hosts.add(web).unwrap();

        let store = Store::from_env(&env).unwrap();
        store.save(&hosts).unwrap();
        assert_eq!(store.load().unwrap().warnings.len(), 1);
    }
}
