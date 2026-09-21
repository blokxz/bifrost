//! Locating the `ssh` and `ssh-keygen` binaries.
//!
//! A binary is resolved once to an absolute path and then spawned directly
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

/// `ssh-keygen` could not be found in a trustworthy location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeygenNotFound;

impl fmt::Display for KeygenNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "Could not find the 'ssh-keygen' program, which comes with OpenSSH. Install it: \
             on Debian/Ubuntu run 'sudo apt install openssh-client'; on Windows enable the \
             'OpenSSH Client' optional feature.",
        )
    }
}

impl std::error::Error for KeygenNotFound {}

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

/// `ssh-add` could not be found in a trustworthy location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAddNotFound;

impl fmt::Display for SshAddNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "Could not find the 'ssh-add' program, which comes with OpenSSH. Install it: \
             on Debian/Ubuntu run 'sudo apt install openssh-client'; on Windows enable the \
             'OpenSSH Client' optional feature.",
        )
    }
}

impl std::error::Error for SshAddNotFound {}

/// Resolves `ssh-add` for the running process, the way [`resolve_ssh`] resolves
/// `ssh`.
pub fn resolve_ssh_add() -> Result<PathBuf, SshAddNotFound> {
    let cwd = std::env::current_dir().ok();
    find_program(
        "ssh-add",
        Platform::current(),
        &sysenv::process_env,
        cwd.as_deref(),
        &is_executable_file,
    )
    .ok_or(SshAddNotFound)
}

/// Resolves `ssh-keygen` for the running process, the way [`resolve_ssh`]
/// resolves `ssh`.
pub fn resolve_keygen() -> Result<PathBuf, KeygenNotFound> {
    let cwd = std::env::current_dir().ok();
    find_program(
        "ssh-keygen",
        Platform::current(),
        &sysenv::process_env,
        cwd.as_deref(),
        &is_executable_file,
    )
    .ok_or(KeygenNotFound)
}

/// Resolves `ssh` using injected inputs. `is_executable` decides whether a
/// candidate path is a usable program.
pub fn find_ssh(
    platform: Platform,
    env: Env<'_>,
    cwd: Option<&Path>,
    is_executable: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf, SshNotFound> {
    find_program("ssh", platform, env, cwd, is_executable).ok_or(SshNotFound)
}

/// Finds the OpenSSH program `name` (without `.exe`): in the system OpenSSH
/// directory on Windows, then in the absolute, non-current-directory entries of
/// `PATH`.
fn find_program(
    name: &str,
    platform: Platform,
    env: Env<'_>,
    cwd: Option<&Path>,
    is_executable: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let program = if platform == Platform::Windows {
        format!("{name}.exe")
    } else {
        name.to_string()
    };

    if platform == Platform::Windows
        && let Some(root) = sysenv::non_empty(env, "SystemRoot")
    {
        let system = PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join(&program);
        if system.is_absolute() && is_executable(&system) {
            return Some(system);
        }
    }

    let path_var = sysenv::non_empty(env, "PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if !dir.is_absolute() || cwd.is_some_and(|cwd| same_dir(&dir, cwd)) {
            continue;
        }
        let candidate = dir.join(&program);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
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

    #[test]
    fn ssh_keygen_is_found_the_same_way_and_never_in_the_current_directory() {
        let cwd = abs("home/rein/project");
        let env = fake_env(&[("PATH", path_var(&[cwd.clone(), abs("usr/bin")]))]);
        let name = if cfg!(windows) {
            "ssh-keygen.exe"
        } else {
            "ssh-keygen"
        };
        let exists = existing(&[cwd.join(name), abs("usr/bin").join(name)]);
        assert_eq!(
            find_program("ssh-keygen", platform(), &env, Some(&cwd), &exists),
            Some(abs("usr/bin").join(name))
        );
        let only_here = existing(&[cwd.join(name)]);
        assert_eq!(
            find_program("ssh-keygen", platform(), &env, Some(&cwd), &only_here),
            None
        );
        assert!(KeygenNotFound.to_string().contains("ssh-keygen"));
        assert!(KeygenNotFound.to_string().contains("Install"));
    }

    #[test]
    fn windows_finds_ssh_keygen_next_to_the_system_ssh() {
        let keygen = abs("Windows/System32/OpenSSH/ssh-keygen.exe");
        let env = fake_env(&[("SystemRoot", abs("Windows").into_os_string())]);
        let exists = existing(std::slice::from_ref(&keygen));
        assert_eq!(
            find_program("ssh-keygen", Platform::Windows, &env, None, &exists),
            Some(keygen)
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
