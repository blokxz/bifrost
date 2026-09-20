//! Non-interactive commands.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::sanitize::{sanitize, sanitize_lines};
use crate::ssh::binary::SshNotFound;
use crate::ssh::command::{Shell, build_args, display_keygen_remove, known_hosts_targets};
use crate::ssh::connect::{self, Exit, Outcome};
use crate::ssh::diagnose::{FailureKind, Verdict, classify, host_key_change};
use crate::store::Store;

/// The exit status of `bifrost <host>` when Bifrost itself fails: the host is not
/// saved, the saved hosts cannot be read, ssh is not installed. Anything else is
/// what ssh, or the remote command, returned.
pub const OWN_ERROR: i32 = 2;

/// The exit status after Ctrl-C, as a shell reports a process ended by SIGINT.
const CANCELLED: i32 = 130;

/// How many close names are offered when a host is not saved.
const SUGGESTIONS: usize = 3;

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

/// `bifrost <host>`: connects to a saved host without opening the TUI, and returns
/// the exit status for Bifrost to exit with.
///
/// The status is ssh's, or the remote command's, unchanged, except that a
/// process ended by a signal is `128 + signal` and Ctrl-C is 130. When Bifrost
/// itself cannot connect it is [`OWN_ERROR`], so a script can tell it from a
/// remote status. Everything meant for a person goes to `err`; ssh's own stderr
/// goes to `tee`, live, as it is written.
///
/// `ssh` is resolved only after the host is known, so an unknown host is
/// reported first. `known_hosts_file` is the file `ssh-keygen -R` would edit; it
/// only decides whether the removal command is worth printing.
pub fn connect(
    name: &str,
    store: &Store,
    ssh: impl FnOnce() -> std::result::Result<PathBuf, SshNotFound>,
    known_hosts_file: Option<&Path>,
    err: &mut impl Write,
    tee: impl Write + Send + 'static,
) -> i32 {
    // A failure to write a message must not change the exit status: there is
    // nowhere left to report it.
    let mut say = |text: String| {
        let _ = writeln!(err, "{text}");
    };

    let loaded = match store.load() {
        Ok(loaded) => loaded,
        Err(problem) => {
            say(format!(
                "bifrost: error: {}",
                sanitize_lines(&problem.to_string())
            ));
            return OWN_ERROR;
        }
    };
    for warning in &loaded.warnings {
        say(format!(
            "bifrost: warning: {}",
            sanitize_lines(warning.message())
        ));
    }

    let Some(host) = loaded.hosts.get(name) else {
        say(format!(
            "bifrost: error: No saved host is named '{}'.",
            sanitize(name)
        ));
        if loaded.hosts.is_empty() {
            say("No hosts are saved yet. Run `bifrost` to add one.".to_string());
        } else {
            let names: Vec<&str> = loaded.hosts.iter().map(|host| host.name.as_str()).collect();
            let close = closest_names(&names, name, SUGGESTIONS);
            if !close.is_empty() {
                say(format!("Did you mean: {}?", close.join(", ")));
            }
            say("Run `bifrost list` to see the saved hosts.".to_string());
        }
        return OWN_ERROR;
    };

    let built = build_args(host, &loaded.hosts)
        .and_then(|args| known_hosts_targets(host, &loaded.hosts).map(|known| (args, known)));
    let (args, known_hosts) = match built {
        Ok(built) => built,
        Err(problem) => {
            say(format!(
                "bifrost: error: Cannot connect to '{}': {}",
                sanitize(&host.name),
                sanitize_lines(&problem.to_string())
            ));
            return OWN_ERROR;
        }
    };
    let ssh = match ssh() {
        Ok(path) => path,
        Err(missing) => {
            say(format!("bifrost: error: {missing}"));
            return OWN_ERROR;
        }
    };

    let outcome = match connect::run(&ssh, &args, tee) {
        Ok(outcome) => outcome,
        Err(problem) => {
            say(format!(
                "bifrost: error: Could not start ssh: {}",
                sanitize_lines(&problem.to_string())
            ));
            return OWN_ERROR;
        }
    };

    // ssh has already shown its own messages; what Bifrost adds is the plain
    // explanation of a failure, after them.
    if let Verdict::Failed(kind) = classify(&outcome) {
        let steps = if kind == FailureKind::HostKeyChanged {
            key_changed_steps(&outcome, &known_hosts, known_hosts_file)
        } else {
            kind.next_steps().iter().map(|s| (*s).to_string()).collect()
        };
        let owner = if kind == FailureKind::HostKeyChanged {
            key_owner(&outcome, &known_hosts, known_hosts_file).unwrap_or(&host.name)
        } else {
            &host.name
        };
        say(format!("bifrost: {}", kind.title()));
        say(format!("  {}", sanitize(&kind.explanation(owner))));
        say("  What you can try:".to_string());
        for step in steps {
            say(format!("    - {step}"));
        }
    }
    exit_status(&outcome)
}

/// The exit status for how ssh ended.
fn exit_status(outcome: &Outcome) -> i32 {
    if outcome.was_interrupted() {
        return CANCELLED;
    }
    match outcome.exit {
        Exit::Code(code) => code,
        Exit::Signal(signal) => 128 + signal,
    }
}

/// The saved host whose old key ssh reported, if it can be trusted: see
/// [`crate::ssh::diagnose::HostKeyChange::removal_target`].
fn key_owner<'a>(
    outcome: &Outcome,
    known: &'a [crate::ssh::command::KnownHostsTarget],
    known_hosts_file: Option<&Path>,
) -> Option<&'a str> {
    host_key_change(&outcome.stderr)
        .removal_target(known, known_hosts_file)
        .map(|target| target.saved_name.as_str())
}

/// What to do about a changed key, on the command line. Bifrost does not edit
/// `known_hosts` here either: it prints the command, only when it can tie it to
/// a host it connected through, and leaves running it to the person.
fn key_changed_steps(
    outcome: &Outcome,
    known: &[crate::ssh::command::KnownHostsTarget],
    known_hosts_file: Option<&Path>,
) -> Vec<String> {
    let mut steps: Vec<String> = FailureKind::HostKeyChanged
        .next_steps()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let read = host_key_change(&outcome.stderr);
    let removal = read
        .removal_target(known, known_hosts_file)
        .and_then(|target| display_keygen_remove(&target.entry, Shell::current()).ok());
    match removal {
        Some(command) => steps.push(format!(
            "Only if you are sure the change is expected, remove the old key yourself, then \
             connect again and check the new fingerprint: {command}"
        )),
        None => steps.push(
            "Bifrost cannot tell which entry of your known_hosts is affected, so it does not \
             suggest a command. Read ssh's message above."
                .to_string(),
        ),
    }
    steps
}

/// The saved names closest to `query`: those that contain it, and those a typo
/// or two away, nearest first. Case is ignored.
fn closest_names(names: &[&str], query: &str, limit: usize) -> Vec<String> {
    let query = query.to_lowercase();
    let allowed = (query.chars().count() / 3).max(1);
    let mut scored: Vec<(usize, &str)> = names
        .iter()
        .filter_map(|name| {
            let lower = name.to_lowercase();
            let distance = edit_distance(&lower, &query);
            let related = !query.is_empty() && (lower.contains(&query) || query.contains(&lower));
            (related || distance <= allowed).then_some((distance, *name))
        })
        .collect();
    scored.sort();
    scored
        .into_iter()
        .take(limit)
        .map(|(_, name)| sanitize(name).into_owned())
        .collect()
}

/// The number of insertions, deletions, substitutions and swaps of neighbouring
/// characters that turn `a` into `b` (optimal string alignment).
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    // `rows[i][j]`: the distance between the first i characters of `a` and the
    // first j of `b`. Turning a prefix into nothing takes one deletion each.
    let mut rows: Vec<Vec<usize>> = (0..=a.len())
        .map(|i| {
            let mut row = vec![0; b.len() + 1];
            row[0] = i;
            row
        })
        .collect();
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (rows[i - 1][j] + 1)
                .min(rows[i][j - 1] + 1)
                .min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = best;
        }
    }
    rows[a.len()][b.len()]
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

    // ---- bifrost <host> ------------------------------------------------------

    fn no_ssh() -> std::result::Result<PathBuf, SshNotFound> {
        panic!("ssh must not be looked for");
    }

    /// Runs `connect` where nothing can be started, so only Bifrost's own
    /// failures are reachable. Returns the status and what was said.
    fn try_connect(store: &Store, name: &str) -> (i32, String) {
        let mut err = Vec::new();
        let status = connect(name, store, no_ssh, None, &mut err, std::io::sink());
        (status, String::from_utf8(err).unwrap())
    }

    #[test]
    fn an_unknown_host_is_bifrost_s_own_error_with_the_closest_names() {
        let (_dir, store) = store_with(&["web", "web-db", "backup", "db"]);
        let (status, said) = try_connect(&store, "wbe");
        assert_eq!(status, OWN_ERROR);
        assert!(
            said.contains("bifrost: error: No saved host is named 'wbe'."),
            "{said}"
        );
        assert!(said.contains("Did you mean: web"), "{said}");
        assert!(said.contains("bifrost list"), "{said}");
        assert!(!said.contains("backup"), "not close: {said}");
    }

    #[test]
    fn a_host_with_no_close_names_still_points_to_the_list() {
        let (_dir, store) = store_with(&["web", "db"]);
        let (status, said) = try_connect(&store, "completely-different");
        assert_eq!(status, OWN_ERROR);
        assert!(!said.contains("Did you mean"), "{said}");
        assert!(said.contains("bifrost list"), "{said}");
    }

    #[test]
    fn with_no_saved_hosts_it_says_how_to_add_one() {
        let (_dir, store) = store_with(&[]);
        let (status, said) = try_connect(&store, "web");
        assert_eq!(status, OWN_ERROR);
        assert!(said.contains("No hosts are saved yet."), "{said}");
    }

    #[test]
    fn a_hostile_name_is_sanitized_in_the_message() {
        let (_dir, store) = store_with(&["web"]);
        let (_, said) = try_connect(&store, "evil\x1b[31m\u{202e}name");
        assert!(
            !said.contains('\x1b') && !said.contains('\u{202e}'),
            "{said:?}"
        );
    }

    #[test]
    fn a_store_that_cannot_be_read_is_bifrost_s_own_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(crate::store::HOSTS_FILE),
            "version = 1\n\n[[hosts]]\nname = \"bad name\"\nhostname = \"192.0.2.1\"\n",
        )
        .unwrap();
        let store = Store::at(dir.path()).with_home(None);
        let (status, said) = try_connect(&store, "web");
        assert_eq!(status, OWN_ERROR);
        assert!(said.contains("bifrost: error:"), "{said}");
        assert!(said.contains("hosts.toml"), "{said}");
    }

    #[test]
    fn ssh_that_is_not_installed_is_bifrost_s_own_error_and_only_asked_for_last() {
        let (_dir, store) = store_with(&["web"]);
        let mut err = Vec::new();
        let status = connect(
            "web",
            &store,
            || Err(SshNotFound),
            None,
            &mut err,
            std::io::sink(),
        );
        assert_eq!(status, OWN_ERROR);
        let said = String::from_utf8(err).unwrap();
        assert!(said.contains("Could not find the 'ssh' program"), "{said}");
    }

    #[test]
    fn the_exit_status_is_ssh_s_unchanged() {
        let outcome = |exit, interrupted| Outcome {
            exit,
            stderr: Vec::new(),
            interrupted,
        };
        for code in [0, 1, 2, 7, 127, 254, 255] {
            assert_eq!(exit_status(&outcome(Exit::Code(code), false)), code);
        }
        assert_eq!(exit_status(&outcome(Exit::Signal(9), false)), 137);
        assert_eq!(exit_status(&outcome(Exit::Signal(15), false)), 143);
        // Ctrl-C, as a shell reports it, however it reached us.
        assert_eq!(exit_status(&outcome(Exit::Signal(2), false)), 130);
        assert_eq!(exit_status(&outcome(Exit::Code(255), true)), 130);
    }

    #[test]
    fn close_names_tolerate_typos_swaps_and_case() {
        let names = ["web", "web-db", "backup", "db", "Production"];
        assert_eq!(closest_names(&names, "wbe", 3), ["web"]);
        assert_eq!(closest_names(&names, "web-d", 3), ["web-db", "web"]);
        assert_eq!(closest_names(&names, "WEB", 3)[0], "web");
        assert_eq!(closest_names(&names, "backpu", 3), ["backup"]);
        assert_eq!(closest_names(&names, "produtcion", 3), ["Production"]);
        assert_eq!(closest_names(&names, "prod", 3), ["Production"]);
        assert!(closest_names(&names, "zzzzzzzz", 3).is_empty());
        assert!(closest_names(&names, "", 3).len() <= 3);
    }

    #[test]
    fn close_names_are_limited_and_ordered_by_distance() {
        let names = ["app1", "app2", "app3", "app4", "app"];
        let close = closest_names(&names, "app", 3);
        assert_eq!(close.len(), 3);
        assert_eq!(close[0], "app", "the exact one first");
    }

    #[test]
    fn edit_distance_counts_a_swap_as_one() {
        assert_eq!(edit_distance("web", "wbe"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("same", "same"), 0);
    }
}
