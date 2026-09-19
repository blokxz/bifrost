//! Non-interactive commands.

use std::io::Write;

use crate::error::Result;
use crate::sanitize::{sanitize, sanitize_lines};
use crate::store::Store;

/// `bifrost list`: prints the saved host names, one per line, on `out`.
///
/// `out` carries data only, so it is safe to pipe. Everything meant for a human
/// (load warnings, the message for an empty store) goes to `err`. A store that
/// cannot be read is returned as an error and nothing is printed.
pub fn list(store: &Store, out: &mut impl Write, err: &mut impl Write) -> Result<()> {
    let loaded = store.load()?;
    for warning in &loaded.warnings {
        writeln!(
            err,
            "bifrost: warning: {}",
            sanitize_lines(warning.message())
        )?;
    }
    if loaded.hosts.is_empty() {
        writeln!(
            err,
            "No saved hosts yet. Add one from the TUI (run `bifrost`)."
        )?;
    }
    for host in &loaded.hosts {
        writeln!(out, "{}", sanitize(&host.name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Host, Hosts};
    use crate::error::AppError;
    use crate::store::HOSTS_FILE;

    struct Output {
        out: String,
        err: String,
    }

    fn run(store: &Store) -> Result<Output> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        list(store, &mut out, &mut err)?;
        Ok(Output {
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        })
    }

    /// A store in a directory that Bifrost itself creates, so that it has the
    /// private permissions Bifrost expects and loads without warnings.
    fn store_with(names: &[&str]) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path().join("bifrost")).with_home(None);
        let mut hosts = Hosts::new();
        for name in names {
            hosts.add(Host::new(*name, "192.0.2.1")).unwrap();
        }
        store.save(&hosts).unwrap();
        (dir, store)
    }

    #[test]
    fn missing_store_prints_a_friendly_message_and_no_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path()).with_home(None);
        let output = run(&store).unwrap();
        assert_eq!(output.out, "");
        assert!(output.err.contains("No saved hosts yet"), "{}", output.err);
    }

    #[test]
    fn empty_store_prints_a_friendly_message_and_no_hosts() {
        let (_dir, store) = store_with(&[]);
        let output = run(&store).unwrap();
        assert_eq!(output.out, "");
        assert!(output.err.contains("No saved hosts yet"), "{}", output.err);
    }

    #[test]
    fn hosts_are_printed_one_per_line_on_stdout_only() {
        let (_dir, store) = store_with(&["web", "db"]);
        let output = run(&store).unwrap();
        let mut names: Vec<_> = output.out.lines().collect();
        names.sort_unstable();
        assert_eq!(names, ["db", "web"]);
        assert_eq!(output.err, "");
    }

    #[test]
    fn corrupt_store_is_an_error_that_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(HOSTS_FILE), "this is not toml").unwrap();
        let store = Store::at(dir.path()).with_home(None);
        let err = list(&store, &mut Vec::new(), &mut Vec::new()).unwrap_err();
        assert!(matches!(err, AppError::Store(_)), "{err:?}");
        let message = err.to_string();
        assert!(message.contains(HOSTS_FILE), "{message}");
        assert!(message.contains("hosts.toml.bak"), "{message}");
    }

    #[test]
    fn corrupt_store_prints_nothing_on_stdout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(HOSTS_FILE), "version = 1\nhosts = 5").unwrap();
        let store = Store::at(dir.path()).with_home(None);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(list(&store, &mut out, &mut err).is_err());
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn load_warnings_go_to_stderr_sanitized() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, store) = store_with(&["web"]);
        let file = dir.path().join("bifrost").join(HOSTS_FILE);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let output = run(&store).unwrap();
        assert_eq!(output.out, "web\n");
        assert!(
            output.err.starts_with("bifrost: warning: "),
            "{}",
            output.err
        );
        assert!(!output.err.contains('\x1b'));
    }

    #[test]
    fn write_failures_become_app_errors() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (_dir, store) = store_with(&["web"]);
        let err = list(&store, &mut Broken, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, AppError::Io(_)));
        assert!(err.to_string().contains("closed"));
    }
}
