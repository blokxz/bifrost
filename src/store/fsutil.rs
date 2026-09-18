//! File-system helpers: atomic writes and user-only permissions.
//!
//! On Unix, files are created 0600 and directories 0700. On Windows,
//! 0.1.0 relies on the ACLs inherited from `%APPDATA%` (or `~/.ssh`) and does
//! not verify them.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::domain::Warning;

/// Writes `contents` to `path` atomically: the data goes to a temporary file
/// in the same directory, is flushed to disk, and then renamed over `path`.
/// Readers see either the old file or the new one, never a partial write.
///
/// The temporary file is created user-only and removed if anything fails.
pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let result = write_then_rename(&tmp, path, contents);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_then_rename(tmp: &Path, target: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = create_private_file(tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, target)?;
    sync_parent_dir(target);
    Ok(())
}

fn create_private_file(path: &Path) -> io::Result<File> {
    match open_new(path) {
        // A leftover from a crashed run with the same process id.
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(path)?;
            open_new(path)
        }
        other => other,
    }
}

#[cfg(unix)]
fn open_new(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_new(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Makes the rename itself durable. Best effort: not every file system
/// supports syncing a directory.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {}

/// Creates `dir` (and missing parents) user-only if it does not exist.
/// An existing directory is left as it is.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Warnings for a Bifrost directory or file that other users can access.
/// Always empty on Windows.
pub(crate) fn permission_warnings(paths: &[(&Path, Kind)]) -> Vec<Warning> {
    paths
        .iter()
        .filter_map(|(path, kind)| permission_warning(path, *kind))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
}

#[cfg(unix)]
fn permission_warning(path: &Path, kind: Kind) -> Option<Warning> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path).ok()?.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        return None;
    }
    let (what, wanted) = match kind {
        Kind::Dir => ("directory", "700"),
        Kind::File => ("file", "600"),
    };
    Some(Warning::new(format!(
        "The Bifrost {what} {} can be accessed by other users (mode {mode:03o}). \
         Restrict it with: chmod {wanted} {}",
        path.display(),
        path.display()
    )))
}

#[cfg(not(unix))]
fn permission_warning(_path: &Path, _kind: Kind) -> Option<Warning> {
    None
}

/// Where the backup of `path` lives: the same name with `.bak` appended.
pub(crate) fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn atomic_write_creates_and_replaces_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data.toml");
        atomic_write(&target, b"first").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        atomic_write(&target, b"second, longer than the first").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second, longer than the first");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn failed_atomic_write_keeps_the_original_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        // Renaming a file over a directory fails on every platform.
        let target = dir.path().join("occupied");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("inner"), "keep me").unwrap();

        assert!(atomic_write(&target, b"new").is_err());
        assert_eq!(fs::read(target.join("inner")).unwrap(), b"keep me");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn stale_temporary_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data.toml");
        let stale = dir
            .path()
            .join(format!(".data.toml.{}.tmp", std::process::id()));
        fs::write(&stale, "leftover").unwrap();
        atomic_write(&target, b"fresh").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"fresh");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn backup_path_appends_bak() {
        assert_eq!(
            backup_path(Path::new("/x/hosts.toml")),
            PathBuf::from("/x/hosts.toml.bak")
        );
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        #[test]
        fn atomic_write_creates_user_only_files() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("secret.toml");
            atomic_write(&target, b"x").unwrap();
            assert_eq!(mode(&target), 0o600);
            // Replacing keeps the file user-only even if the old one was open.
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
            atomic_write(&target, b"y").unwrap();
            assert_eq!(mode(&target), 0o600);
        }

        #[test]
        fn ensure_private_dir_creates_0700_and_leaves_existing_alone() {
            let dir = tempfile::tempdir().unwrap();
            let new_dir = dir.path().join("a").join("bifrost");
            ensure_private_dir(&new_dir).unwrap();
            assert_eq!(mode(&new_dir), 0o700);

            let existing = dir.path().join("existing");
            fs::create_dir(&existing).unwrap();
            fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
            ensure_private_dir(&existing).unwrap();
            assert_eq!(mode(&existing), 0o755);
        }

        #[test]
        fn broad_permissions_produce_warnings() {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("hosts.toml");
            fs::write(&file, "x").unwrap();

            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(
                permission_warnings(&[(dir.path(), Kind::Dir), (&file, Kind::File)]).is_empty()
            );

            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let warnings = permission_warnings(&[(dir.path(), Kind::Dir), (&file, Kind::File)]);
            assert_eq!(warnings.len(), 2);
            assert!(warnings[0].message().contains("mode 755"));
            assert!(warnings[0].message().contains("chmod 700"));
            assert!(warnings[1].message().contains("mode 644"));
            assert!(warnings[1].message().contains("chmod 600"));

            // Group-only access counts as broader than user-only.
            fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(permission_warnings(&[(&file, Kind::File)]).len(), 1);
        }
    }
}
