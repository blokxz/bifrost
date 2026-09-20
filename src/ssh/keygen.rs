//! Removing an old host key with `ssh-keygen -R`.
//!
//! Bifrost never edits `known_hosts` itself. When a server's key has changed and
//! the user has confirmed, it runs `ssh-keygen -R <host>`, which is the tool that
//! knows the file's format (including hashed host names), and which keeps the
//! previous contents as `known_hosts.old`.
//!
//! `ssh-keygen -R` exits with status 0 even when it found nothing to remove, so
//! success is not read from the status: it is read from what the tool says it
//! did, and anything unexpected is reported as a failure, never as a removal.
//!
//! The entry is checked again here, at run time in release builds too: it is the
//! point where a value becomes an argument of a program that edits a file.

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

/// The longest entry accepted. Longer than any valid host name with a port.
const MAX_ENTRY_LEN: usize = 300;

/// How much of ssh-keygen's output is kept.
const MAX_OUTPUT: usize = 4096;

/// What `ssh-keygen -R` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removal {
    /// It removed the entry and kept a copy of the old file.
    Removed,
    /// It ran, and there was no entry with that name.
    NotFound,
    /// It failed, or said something unexpected. Holds what it printed, raw:
    /// it must be sanitized before it is shown.
    Failed(String),
}

/// Whether `entry` is a host name as it appears in `known_hosts`: a host name or
/// address, or `[host]:port`. Letters, digits and `. _ - : [ ]`, never starting
/// with `-`.
pub fn is_safe_entry(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= MAX_ENTRY_LEN
        && !entry.starts_with('-')
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '[' | ']'))
}

/// Runs `keygen -R entry` on the user's default `known_hosts`.
///
/// No shell and no terminal: the tool's output is captured, and it is given no
/// input.
pub fn remove_known_host(keygen: &Path, entry: &str) -> io::Result<Removal> {
    if !is_safe_entry(entry) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to run ssh-keygen with a host entry that is not a plain host name",
        ));
    }
    let output = Command::new(keygen)
        .arg("-R")
        .arg(entry)
        .stdin(Stdio::null())
        .output()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(interpret(output.status.success(), &text))
}

/// Reads what ssh-keygen printed.
fn interpret(exited_cleanly: bool, output: &str) -> Removal {
    if exited_cleanly {
        let found = output
            .lines()
            .any(|line| line.starts_with("# Host ") && line.contains(" found: line "));
        let updated = output.lines().any(|line| line.ends_with(" updated."));
        if found && updated {
            return Removal::Removed;
        }
        let not_found = output
            .lines()
            .any(|line| line.starts_with("Host ") && line.contains(" not found in "));
        if not_found && !found {
            return Removal::NotFound;
        }
    }
    let mut kept = output.trim().to_string();
    if kept.len() > MAX_OUTPUT {
        let mut end = MAX_OUTPUT;
        while !kept.is_char_boundary(end) {
            end -= 1;
        }
        kept.truncate(end);
    }
    Removal::Failed(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    // What OpenSSH 9.6's ssh-keygen printed for each case.
    const REMOVED: &str = "# Host 192.0.2.2 found: line 1\n\
                           known_hosts updated.\n\
                           Original contents retained as known_hosts.old\n";
    const REMOVED_BRACKETS: &str = "# Host [192.0.2.9]:2222 found: line 1\n\
                                    /home/dev/.ssh/known_hosts updated.\n\
                                    Original contents retained as /home/dev/.ssh/known_hosts.old\n";
    const NOT_FOUND: &str = "Host nothere.example not found in known_hosts\n";
    const NO_FILE: &str = "Cannot stat /tmp/kh/nofile: No such file or directory\n";

    #[test]
    fn a_removal_is_what_the_tool_says_it_did() {
        assert_eq!(interpret(true, REMOVED), Removal::Removed);
        assert_eq!(interpret(true, REMOVED_BRACKETS), Removal::Removed);
    }

    #[test]
    fn nothing_to_remove_is_not_reported_as_a_removal() {
        // Exit status 0, and still nothing was removed.
        assert_eq!(interpret(true, NOT_FOUND), Removal::NotFound);
    }

    #[test]
    fn a_failure_keeps_what_the_tool_printed() {
        assert_eq!(
            interpret(false, NO_FILE),
            Removal::Failed(NO_FILE.trim().to_string())
        );
    }

    #[test]
    fn a_clean_exit_with_unexpected_output_is_not_a_removal() {
        for output in [
            "",
            "done\n",
            "known_hosts updated.\n",
            "# Host x found: line 3\n",
        ] {
            assert!(
                matches!(interpret(true, output), Removal::Failed(_)),
                "{output:?}"
            );
        }
    }

    #[test]
    fn a_failure_status_is_a_failure_even_when_the_words_look_right() {
        assert!(matches!(interpret(false, REMOVED), Removal::Failed(_)));
    }

    #[test]
    fn long_output_is_cut_without_splitting_a_character() {
        let long = "é".repeat(MAX_OUTPUT);
        let Removal::Failed(kept) = interpret(false, &long) else {
            panic!("a failure");
        };
        assert!(kept.len() <= MAX_OUTPUT);
        assert!(kept.chars().all(|c| c == 'é'));
    }

    #[test]
    fn only_plain_host_entries_are_safe() {
        for entry in [
            "192.0.2.2",
            "web.example.com",
            "[192.0.2.9]:2222",
            "[2001:db8::1]:2222",
            "2001:db8::1",
            "host_1-a",
        ] {
            assert!(is_safe_entry(entry), "{entry}");
        }
        for entry in [
            "",
            "-foo",
            "-R",
            "host name",
            "host;rm",
            "host\n",
            "ho\u{202e}st",
            "*.example.com",
            "!host",
            "host'quote",
            "host/../x",
            "ho\tst",
            "ü.example",
        ] {
            assert!(!is_safe_entry(entry), "{entry:?}");
        }
        assert!(!is_safe_entry(&"a".repeat(MAX_ENTRY_LEN + 1)));
        assert!(is_safe_entry(&"a".repeat(MAX_ENTRY_LEN)));
    }

    #[test]
    fn an_unsafe_entry_is_refused_before_anything_runs() {
        // The program does not exist: had it been started, the error would be
        // NotFound, not InvalidInput.
        let missing = Path::new("/nonexistent/ssh-keygen");
        for entry in ["-f", "a b", "", "x\ny"] {
            let err = remove_known_host(missing, entry).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{entry:?}");
        }
        let err = remove_known_host(missing, "web.example.com").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
