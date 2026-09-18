//! Locating the `ssh` binary.
//!
//! The binary is resolved once to an absolute path and then spawned directly
//! with an argument vector, never through a shell. Relative and empty `PATH`
//! entries are ignored and so is the current directory, so a hostile `ssh`
//! dropped next to the user's files is never picked up. On Windows the system
//! OpenSSH install is preferred over anything found in `PATH`.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::sysenv::{self, Env, Platform};

/// `ssh` could not be found in a trustworthy location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshNotFound;

impl fmt::Display for SshNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "Could not find the 'ssh' program. Install OpenSSH: on Debian/Ubuntu run \
             'sudo apt install openssh-client'; on Windows enable the 'OpenSSH Client' \
             optional feature.",
        )
    }
}

impl std::error::Error for SshNotFound {}

/// Resolves `ssh` for the running process.
pub fn resolve_ssh() -> Result<PathBuf, SshNotFound> {
    let cwd = std::env::current_dir().ok();
    find_ssh(
        Platform::current(),
        &sysenv::process_env,
        cwd.as_deref(),
        &is_executable_file,
    )
}

/// Resolves `ssh` using injected inputs. `is_executable` decides whether a
/// candidate path is a usable program.
pub fn find_ssh(
    platform: Platform,
    env: Env<'_>,
    cwd: Option<&Path>,
    is_executable: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf, SshNotFound> {
    if platform == Platform::Windows
        && let Some(root) = sysenv::non_empty(env, "SystemRoot")
    {
        let system = PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        if system.is_absolute() && is_executable(&system) {
            return Ok(system);
        }
    }

    let program = if platform == Platform::Windows {
        "ssh.exe"
    } else {
        "ssh"
    };
    let path_var = sysenv::non_empty(env, "PATH").ok_or(SshNotFound)?;
    for dir in std::env::split_paths(&path_var) {
        if !dir.is_absolute() || cwd.is_some_and(|cwd| same_dir(&dir, cwd)) {
            continue;
        }
        let candidate = dir.join(program);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    Err(SshNotFound)
}

fn same_dir(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    matches!(
        (std::fs::canonicalize(a), std::fs::canonicalize(b)),
        (Ok(a), Ok(b)) if a == b
    )
}

/// A regular file that can be executed.
pub fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ffi::OsString;

    use super::*;
    use crate::sysenv::testing::{abs, fake_env};

    fn path_var(dirs: &[PathBuf]) -> OsString {
        std::env::join_paths(dirs).unwrap()
    }

    fn program() -> &'static str {
        if cfg!(windows) { "ssh.exe" } else { "ssh" }
    }

    fn platform() -> Platform {
        Platform::current()
    }

    fn existing(paths: &[PathBuf]) -> impl Fn(&Path) -> bool + use<> {
        let set: HashSet<PathBuf> = paths.iter().cloned().collect();
        move |p| set.contains(p)
    }

    #[test]
    fn picks_the_first_absolute_match_in_path() {
        let env = fake_env(&[(
            "PATH",
            path_var(&[abs("opt/none"), abs("usr/local/bin"), abs("usr/bin")]),
        )]);
        let exists = existing(&[
            abs("usr/local/bin").join(program()),
            abs("usr/bin").join(program()),
        ]);
        let found = find_ssh(platform(), &env, None, &exists).unwrap();
        assert_eq!(found, abs("usr/local/bin").join(program()));
        assert!(found.is_absolute());
    }

    #[test]
    fn relative_and_empty_path_entries_are_ignored() {
        // Build the PATH by hand: join_paths would refuse an empty entry on some platforms.
        let sep = if cfg!(windows) { ";" } else { ":" };
        let raw = format!("{sep}.{sep}bin{sep}./bin{sep}{}", abs("usr/bin").display());
        let env = fake_env(&[("PATH", OsString::from(raw))]);
        let exists = existing(&[
            PathBuf::from(program()),
            PathBuf::from(".").join(program()),
            PathBuf::from("bin").join(program()),
            abs("usr/bin").join(program()),
        ]);
        let found = find_ssh(platform(), &env, None, &exists).unwrap();
        assert_eq!(found, abs("usr/bin").join(program()));
    }

    #[test]
    fn a_binary_in_the_current_directory_is_rejected_even_via_an_absolute_path_entry() {
        let cwd = abs("home/rein/project");
        let env = fake_env(&[("PATH", path_var(&[cwd.clone(), abs("usr/bin")]))]);
        let exists = existing(&[cwd.join(program()), abs("usr/bin").join(program())]);
        let found = find_ssh(platform(), &env, Some(&cwd), &exists).unwrap();
        assert_eq!(found, abs("usr/bin").join(program()));

        // If it is the only candidate, nothing is found.
        let exists = existing(&[cwd.join(program())]);
        assert_eq!(
            find_ssh(platform(), &env, Some(&cwd), &exists),
            Err(SshNotFound)
        );
    }

    #[test]
    fn missing_path_or_binary_is_an_error_with_install_help() {
        let exists = existing(&[]);
        assert_eq!(
            find_ssh(platform(), &fake_env(&[]), None, &exists),
            Err(SshNotFound)
        );
        let env = fake_env(&[("PATH", path_var(&[abs("usr/bin")]))]);
        assert_eq!(find_ssh(platform(), &env, None, &exists), Err(SshNotFound));
        assert!(SshNotFound.to_string().contains("Install OpenSSH"));
    }

    #[test]
    fn windows_prefers_the_system_openssh() {
        let system = abs("Windows/System32/OpenSSH/ssh.exe");
        let other = abs("tools/ssh.exe");
        let env = fake_env(&[
            ("SystemRoot", abs("Windows").into_os_string()),
            ("PATH", path_var(&[abs("tools")])),
        ]);
        let exists = existing(&[system.clone(), other.clone()]);
        assert_eq!(
            find_ssh(Platform::Windows, &env, None, &exists).unwrap(),
            system
        );

        // Falls back to PATH when the system install is missing.
        let exists = existing(std::slice::from_ref(&other));
        assert_eq!(
            find_ssh(Platform::Windows, &env, None, &exists).unwrap(),
            other
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_check_needs_a_regular_executable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ssh");
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(&file));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable_file(&file));
        assert!(
            !is_executable_file(dir.path()),
            "directories are not programs"
        );
        assert!(!is_executable_file(&dir.path().join("missing")));
    }

    #[cfg(unix)]
    #[test]
    fn a_real_path_lookup_skips_the_current_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("ssh");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let env = fake_env(&[("PATH", path_var(&[dir.path().to_path_buf()]))]);
        // Same directory as the cwd: refused.
        assert_eq!(
            find_ssh(Platform::Linux, &env, Some(dir.path()), &is_executable_file),
            Err(SshNotFound)
        );
        // Elsewhere: accepted.
        let other = tempfile::tempdir().unwrap();
        assert_eq!(
            find_ssh(
                Platform::Linux,
                &env,
                Some(other.path()),
                &is_executable_file
            )
            .unwrap(),
            fake
        );
    }
}
