//! The user's ssh keys: which key pairs are in `~/.ssh`, what they are, whether
//! ssh will accept their permissions and whether the agent holds them.
//!
//! Bifrost never reads a private key. What a key is (its type, size,
//! fingerprint and comment) comes from `ssh-keygen -l -f name.pub`, run on the
//! **public** file, and the private file is only ever looked at for its
//! permissions. Nothing here deletes or overwrites a key.
//!
//! What is a key: a file `name` with a file `name.pub` next to it. That leaves out
//! `config`, `known_hosts`, `authorized_keys` and any public key whose private
//! half lives elsewhere.
//!
//! The permission rule is ssh's own: a private key is refused when its group or
//! other permission bits are set (`mode & 0o077 != 0`). So 0600 and 0400 are
//! fine, and 0640 or 0644 are not. On Windows permissions are not checked:
//! access is decided by ACLs, which ssh.exe verifies for itself.
//!
//! Everything that touches a program or the agent is behind [`KeyTools`], so the
//! rest can be tested without either.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::agent::{self, AGENT_TIMEOUT, AgentState};
use super::diagnose::{is_key_type, is_sha256_fingerprint};

/// How many key pairs are read. Far more than anyone keeps; a bound so that a
/// directory with thousands of files cannot make the screen slow.
pub const MAX_KEYS: usize = 200;

/// What `ssh-keygen -l` reports about a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The size in bits: 256 for ed25519, 2048 or more for RSA.
    pub bits: u32,
    /// `SHA256:` and the hash.
    pub hash: String,
    /// The comment, when the key has one. **Raw**: whoever made the key chose
    /// it, so it can hold anything and must be sanitized before it is shown.
    pub comment: Option<String>,
    /// The type as ssh names it: `ED25519`, `RSA`, `ECDSA`, `ED25519-SK`.
    pub key_type: String,
}

impl Fingerprint {
    /// The type for a person: `ed25519`, or `rsa 3072` where the size is a
    /// choice and worth seeing.
    pub fn type_label(&self) -> String {
        let name = self.key_type.to_ascii_lowercase();
        if name.starts_with("ed25519") {
            name
        } else {
            format!("{name} {}", self.bits)
        }
    }
}

/// Reads one line of `ssh-keygen -l` (or `ssh-add -l`) output:
/// `<bits> <fingerprint> <comment> (<TYPE>)`.
///
/// The comment can hold spaces, parentheses and anything else, and is `no
/// comment` when the key has none, so the line is read from both ends: the two
/// fields at the start, the type in the last parentheses. `None` for anything
/// that is not such a line.
pub fn parse_fingerprint(line: &str) -> Option<Fingerprint> {
    let line = line.trim();
    let (bits, rest) = line.split_once(' ')?;
    if bits.is_empty() || bits.len() > 6 || !bits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let bits: u32 = bits.parse().ok()?;
    let (hash, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    if !is_sha256_fingerprint(hash) {
        return None;
    }
    let inner = rest.strip_suffix(')')?;
    let (comment, key_type) = match inner.rsplit_once(" (") {
        Some(parts) => parts,
        None => ("", inner.strip_prefix('(')?),
    };
    if !is_key_type(key_type) {
        return None;
    }
    let comment = comment.trim();
    Some(Fingerprint {
        bits,
        hash: hash.to_string(),
        comment: (!comment.is_empty() && comment != "no comment").then(|| comment.to_string()),
        key_type: key_type.to_string(),
    })
}

/// Whether ssh will accept a private key's permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    /// Only the owner can use the file.
    Fine,
    /// Others can read it: ssh refuses to use such a key.
    TooOpen { mode: u32 },
    /// Not checked: Windows, or the file could not be examined.
    Unchecked,
}

impl Permissions {
    pub fn is_too_open(self) -> bool {
        matches!(self, Permissions::TooOpen { .. })
    }
}

/// `mode` as ssh-keygen and `ls` show it: four octal digits.
pub fn mode_label(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// The permissions of the private key at `path`, following a symbolic link (ssh
/// does).
#[cfg(unix)]
pub fn check_permissions(path: &Path) -> Permissions {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                Permissions::TooOpen { mode }
            } else {
                Permissions::Fine
            }
        }
        Err(_) => Permissions::Unchecked,
    }
}

#[cfg(not(unix))]
pub fn check_permissions(_path: &Path) -> Permissions {
    Permissions::Unchecked
}

/// Whether `name` can be a key's file name in the ssh directory: one plain path
/// component, nothing that could reach another directory, no control characters.
pub fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(|c| c.is_control())
}

/// Sets the private key `name` in `ssh_dir` to 0600, so that only its owner can
/// read and write it.
///
/// Only a key pair's private file is touched: `name` must be a plain file name,
/// the file must exist as a regular file that is not a symbolic link (changing a
/// link would change what it points to, which Bifrost did not find as a key), and
/// `name.pub` must exist next to it.
#[cfg(unix)]
pub fn fix_permissions(ssh_dir: &Path, name: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !is_plain_file_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "that is not the name of a key file",
        ));
    }
    let private = ssh_dir.join(name);
    let metadata = fs::symlink_metadata(&private)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the key is a symbolic link; change the permissions of the file it points to",
        ));
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the key is not a regular file",
        ));
    }
    let public = ssh_dir.join(format!("{name}.pub"));
    if !fs::metadata(&public).is_ok_and(|m| m.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the key has no matching .pub file",
        ));
    }
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn fix_permissions(_ssh_dir: &Path, _name: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Bifrost does not change permissions on this system",
    ))
}

/// The longest file name accepted for a new key.
pub const MAX_KEY_NAME_LEN: usize = 64;

/// The longest comment accepted for a new key.
pub const MAX_COMMENT_LEN: usize = 100;

/// Files that ssh reads for other purposes. A private key with one of these
/// names would be read as something else (`config`) or would hide something
/// that is there already. Compared ignoring case.
const RESERVED_NAMES: [&str; 8] = [
    "config",
    "authorized_keys",
    "authorized_keys2",
    "known_hosts",
    "known_hosts2",
    "environment",
    "rc",
    "allowed_signers",
];

/// Whether `name` can be the file name of a new key. Plain English when it
/// cannot.
///
/// Letters, digits, `.`, `_` and `-`; 1 to 64 characters; not starting with `-`
/// (it would read as an option) or `.` (a hidden file, or `.` and `..`); not
/// ending in `.pub` (ssh-keygen adds that itself); not a file ssh reads for
/// something else.
pub fn validate_key_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Give the key a file name.".to_string());
    }
    if name.chars().count() > MAX_KEY_NAME_LEN {
        return Err(format!(
            "The file name can be at most {MAX_KEY_NAME_LEN} characters."
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(
            "The file name may only contain letters, digits, '.', '_' and '-'.".to_string(),
        );
    }
    if name.starts_with(['-', '.']) {
        return Err("The file name cannot start with '-' or '.'.".to_string());
    }
    if name.to_ascii_lowercase().ends_with(".pub") {
        return Err(
            "Do not end the name with .pub: ssh-keygen adds it to the public key itself."
                .to_string(),
        );
    }
    if RESERVED_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
    {
        return Err(format!(
            "'{name}' is a file that ssh reads for something else, so it cannot be a key's name."
        ));
    }
    Ok(())
}

/// Whether `comment` can be the comment of a new key. An empty one is fine: the
/// key then gets ssh-keygen's own (`user@host`).
pub fn validate_comment(comment: &str) -> Result<(), String> {
    if comment.chars().count() > MAX_COMMENT_LEN {
        return Err(format!(
            "The comment can be at most {MAX_COMMENT_LEN} characters."
        ));
    }
    if comment.chars().any(crate::sanitize::is_unsafe_char) {
        return Err("The comment cannot contain control characters.".to_string());
    }
    if comment != comment.trim() {
        return Err("The comment cannot start or end with a space.".to_string());
    }
    Ok(())
}

/// The name to offer for a new key: `id_ed25519`, or the first of
/// `id_ed25519_2`, `id_ed25519_3`... that is not in `taken` (ignoring case).
pub fn suggest_key_name(taken: &[&str]) -> String {
    let is_taken = |candidate: &str| taken.iter().any(|t| t.eq_ignore_ascii_case(candidate));
    let base = "id_ed25519";
    if !is_taken(base) {
        return base.to_string();
    }
    (2..100)
        .map(|n| format!("{base}_{n}"))
        .find(|candidate| !is_taken(candidate))
        .unwrap_or_else(|| format!("{base}_new"))
}

/// The arguments that make an ed25519 key called `name` in `dir`.
///
/// Never `-N`: the passphrase is asked for by ssh-keygen itself, on the terminal,
/// so it is never in a command line, an environment or this program's memory.
/// The comment is left out when empty, and ssh-keygen then uses its default.
///
/// Both values are checked again here, at run time in release builds too: this is
/// where they become arguments of a program that writes files.
pub fn generate_args(dir: &Path, name: &str, comment: Option<&str>) -> Result<Vec<String>, String> {
    validate_key_name(name)?;
    let comment = comment.filter(|comment| !comment.is_empty());
    if let Some(comment) = comment {
        validate_comment(comment)?;
    }
    if !dir.is_absolute() {
        return Err("The ssh folder is not an absolute path, so no key is made.".to_string());
    }
    let path = dir.join(name);
    let path = path
        .to_str()
        .ok_or_else(|| "The ssh folder's path is not text, so no key is made.".to_string())?;
    let mut args = vec![
        "-t".to_string(),
        "ed25519".to_string(),
        "-f".to_string(),
        path.to_string(),
    ];
    if let Some(comment) = comment {
        args.push("-C".to_string());
        args.push(comment.to_string());
    }
    Ok(args)
}

/// Makes sure that neither `name` nor `name.pub` exists in `dir`, as a file, a
/// directory or a link (even one that points nowhere). Bifrost never overwrites a
/// key, and ssh-keygen would otherwise ask whether to.
pub fn ensure_name_is_free(dir: &Path, name: &str) -> Result<(), String> {
    for taken in [name.to_string(), format!("{name}.pub")] {
        match fs::symlink_metadata(dir.join(&taken)) {
            Ok(_) => {
                return Err(format!(
                    "A file named '{taken}' already exists in {}. Bifrost never overwrites a \
                     key: choose another name.",
                    dir.display()
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "Could not check whether '{taken}' exists in {}: {err}",
                    dir.display()
                ));
            }
        }
    }
    Ok(())
}

/// The arguments that add the private key `name` in `dir` to the agent: its
/// absolute path, and nothing else. `ssh-add` asks for the passphrase itself.
///
/// The key must be a regular file (or a link to one) with its `.pub` beside it,
/// as when it was listed. Checked again here, at run time.
pub fn add_args(dir: &Path, name: &str) -> Result<Vec<String>, String> {
    if !is_plain_file_name(name) {
        return Err("That is not the name of a key file.".to_string());
    }
    if !dir.is_absolute() {
        return Err("The ssh folder is not an absolute path, so no key is added.".to_string());
    }
    let private = dir.join(name);
    let public = dir.join(format!("{name}.pub"));
    let is_file = |path: &Path| fs::metadata(path).is_ok_and(|m| m.is_file());
    if !is_file(&private) || !is_file(&public) {
        return Err(format!(
            "'{name}' is not a key pair in {} any more: its file or its .pub file is gone.",
            dir.display()
        ));
    }
    let path = private
        .to_str()
        .ok_or_else(|| "The key's path is not text, so it is not added.".to_string())?;
    Ok(vec![path.to_string()])
}

/// A key pair found in the ssh directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    /// The private file's name. Raw (lossy): sanitize before showing.
    pub name: String,
    pub private: PathBuf,
    pub public: PathBuf,
    /// The private file is a symbolic link.
    pub symlink: bool,
}

/// The key pairs found in a directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scan {
    pub files: Vec<KeyFile>,
    /// There were more than [`MAX_KEYS`]; the rest are not listed.
    pub truncated: bool,
    /// The directory does not exist.
    pub missing_dir: bool,
}

/// Finds the key pairs in `dir`, sorted by name ignoring case.
pub fn scan_ssh_dir(dir: &Path) -> io::Result<Scan> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(Scan {
                missing_dir: true,
                ..Scan::default()
            });
        }
        Err(err) => return Err(err),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        // A name that is not valid text cannot be a key Bifrost can show.
        if let Some(name) = entry?.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    names.sort_by_key(|name| name.to_lowercase());

    let is_file = |path: &Path| fs::metadata(path).is_ok_and(|m| m.is_file());
    let mut scan = Scan::default();
    for name in &names {
        let Some(base) = name.strip_suffix(".pub") else {
            continue;
        };
        if base.is_empty() {
            continue;
        }
        // Both must exist as files: a `.pub` whose private half is elsewhere, or
        // a directory of that name, is not a key.
        let (private, public) = (dir.join(base), dir.join(name));
        if !is_file(&private) || !is_file(&public) {
            continue;
        }
        if scan.files.len() == MAX_KEYS {
            scan.truncated = true;
            break;
        }
        scan.files.push(KeyFile {
            name: base.to_string(),
            symlink: fs::symlink_metadata(&private).is_ok_and(|m| m.file_type().is_symlink()),
            private,
            public,
        });
    }
    scan.files.sort_by_key(|file| file.name.to_lowercase());
    Ok(scan)
}

/// Everything about one key that the screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// The private file's name. Raw: sanitize before showing.
    pub name: String,
    pub private: PathBuf,
    pub public: PathBuf,
    /// What ssh-keygen says about the public file, or why it could not say.
    pub fingerprint: Result<Fingerprint, String>,
    pub permissions: Permissions,
    pub symlink: bool,
    /// Whether the agent holds it. `None` when that cannot be told: the agent
    /// did not answer, or the key could not be read.
    pub loaded: Option<bool>,
}

impl KeyEntry {
    /// Whether Bifrost can offer to fix this key's permissions.
    pub fn can_fix_permissions(&self) -> bool {
        self.permissions.is_too_open() && !self.symlink
    }
}

/// The keys screen's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysSnapshot {
    pub dir: PathBuf,
    pub keys: Vec<KeyEntry>,
    pub agent: AgentState,
    /// The directory does not exist.
    pub missing_dir: bool,
    pub truncated: bool,
    /// Why the directory could not be read, in plain English.
    pub problem: Option<String>,
}

impl KeysSnapshot {
    /// A snapshot with nothing in it, for when the directory cannot even be
    /// named.
    pub fn unavailable(problem: impl Into<String>) -> Self {
        KeysSnapshot {
            dir: PathBuf::new(),
            keys: Vec::new(),
            agent: AgentState::Unavailable("Not asked.".to_string()),
            missing_dir: false,
            truncated: false,
            problem: Some(problem.into()),
        }
    }
}

/// The two programs a snapshot is built with.
pub trait KeyTools {
    /// What `ssh-keygen -l -f` says about the public key file.
    fn fingerprint(&self, public: &Path) -> Result<Fingerprint, String>;

    /// What the agent holds.
    fn agent(&self) -> AgentState;
}

/// Reads the keys in `dir` with `tools`.
pub fn load_keys(tools: &dyn KeyTools, dir: &Path) -> KeysSnapshot {
    let agent = tools.agent();
    let (scan, problem) = match scan_ssh_dir(dir) {
        Ok(scan) => (scan, None),
        Err(err) => (
            Scan::default(),
            Some(format!(
                "Could not read the folder {}: {err}",
                dir.display()
            )),
        ),
    };
    let keys = scan
        .files
        .into_iter()
        .map(|file| {
            let fingerprint = tools.fingerprint(&file.public);
            let loaded = match (&fingerprint, agent.hashes()) {
                (Ok(key), Some(hashes)) => Some(hashes.contains(&key.hash)),
                _ => None,
            };
            KeyEntry {
                permissions: check_permissions(&file.private),
                name: file.name,
                private: file.private,
                public: file.public,
                fingerprint,
                symlink: file.symlink,
                loaded,
            }
        })
        .collect();
    KeysSnapshot {
        dir: dir.to_path_buf(),
        keys,
        agent,
        missing_dir: scan.missing_dir,
        truncated: scan.truncated,
        problem,
    }
}

/// The real programs. A program that was not found is `None`, and answering for
/// it says what to install.
#[derive(Debug, Clone, Copy)]
pub struct SystemKeyTools<'a> {
    pub keygen: Option<&'a Path>,
    pub ssh_add: Option<&'a Path>,
}

impl KeyTools for SystemKeyTools<'_> {
    fn fingerprint(&self, public: &Path) -> Result<Fingerprint, String> {
        let Some(keygen) = self.keygen else {
            return Err("ssh-keygen was not found, so this key cannot be read.".to_string());
        };
        let output = Command::new(keygen)
            .arg("-l")
            .arg("-f")
            .arg(public)
            .stdin(Stdio::null())
            .output()
            .map_err(|err| format!("Could not run ssh-keygen: {err}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success()
            && let Some(key) = stdout.lines().next().and_then(parse_fingerprint)
        {
            return Ok(key);
        }
        let said = String::from_utf8_lossy(&output.stderr);
        let first = said
            .lines()
            .chain(stdout.lines())
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("it printed nothing");
        Err(format!("ssh-keygen could not read it: {first}"))
    }

    fn agent(&self) -> AgentState {
        match self.ssh_add {
            Some(ssh_add) => agent::list(ssh_add, AGENT_TIMEOUT),
            None => AgentState::Unavailable(
                "ssh-add was not found, so Bifrost cannot tell what the agent holds.".to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw";
    const B: &str = "SHA256:Crv2UD7RjSr55ym7z5Nso5T9YwtVbduZ6xUVvnj9VtE";

    // ---- what ssh-keygen -l printed (OpenSSH 9.6) ----------------------------

    #[test]
    fn an_ed25519_key_with_a_comment_full_of_punctuation() {
        let key =
            parse_fingerprint(&format!("256 {A} dev laptop (work) <me@x> (ED25519)")).unwrap();
        assert_eq!(key.bits, 256);
        assert_eq!(key.hash, A);
        assert_eq!(key.comment.as_deref(), Some("dev laptop (work) <me@x>"));
        assert_eq!(key.key_type, "ED25519");
        assert_eq!(key.type_label(), "ed25519");
    }

    #[test]
    fn a_key_with_no_comment_says_so_and_the_comment_is_none() {
        let key = parse_fingerprint(&format!("2048 {B} no comment (RSA)")).unwrap();
        assert_eq!(key.comment, None);
        assert_eq!(key.type_label(), "rsa 2048");
        // And a comment that is empty in some other way.
        let bare = parse_fingerprint(&format!("256 {A} (ED25519)")).unwrap();
        assert_eq!(bare.comment, None);
    }

    #[test]
    fn the_type_is_the_last_parenthesized_word_whatever_the_comment_says() {
        let key = parse_fingerprint(&format!("256 {A} trick (RSA) (ED25519)")).unwrap();
        assert_eq!(key.key_type, "ED25519");
        assert_eq!(key.comment.as_deref(), Some("trick (RSA)"));
        let sk = parse_fingerprint(&format!("256 {A} token (ED25519-SK)")).unwrap();
        assert_eq!(sk.type_label(), "ed25519-sk");
        let ecdsa = parse_fingerprint(&format!("521 {A} c (ECDSA)")).unwrap();
        assert_eq!(ecdsa.type_label(), "ecdsa 521");
    }

    #[test]
    fn lines_that_are_not_keys_are_not_read() {
        for line in [
            "",
            "hello",
            "c.pub is not a public key file.",
            "The agent has no identities.",
            &format!("abc {A} c (ED25519)"),
            "256 MD5:aa:bb:cc c (ED25519)",
            &format!("256 {A} c ED25519"),
            &format!("256 {A} c (ed25519)"),
            &format!("256 {A} c (X; rm -rf /)"),
            &format!("-256 {A} c (ED25519)"),
            &format!("99999999999 {A} c (ED25519)"),
            "256 SHA256:short c (ED25519)",
        ] {
            assert_eq!(parse_fingerprint(line), None, "{line:?}");
        }
    }

    #[test]
    fn hostile_comments_are_kept_raw_for_the_screen_to_clean() {
        let key = parse_fingerprint(&format!(
            "256 {A} evil\x1b]0;pwned\x07 \u{202e}text (ED25519)"
        ))
        .unwrap();
        assert!(
            key.comment.unwrap().contains('\x1b'),
            "cleaning is the screen's job"
        );
        // Nothing hostile can end up in the fields that are validated.
        let key = parse_fingerprint(&format!("256 {A} c (ED25519)")).unwrap();
        assert!(key.hash.chars().all(|c| c.is_ascii_graphic()));
        assert!(key.key_type.chars().all(|c| c.is_ascii_graphic()));
    }

    #[test]
    fn a_huge_line_is_handled() {
        let line = format!("256 {A} {} (ED25519)", "x".repeat(500_000));
        assert_eq!(
            parse_fingerprint(&line).unwrap().comment.unwrap().len(),
            500_000
        );
        assert_eq!(parse_fingerprint(&"9".repeat(500_000)), None);
    }

    #[test]
    fn modes_are_shown_as_four_octal_digits() {
        assert_eq!(mode_label(0o600), "0600");
        assert_eq!(mode_label(0o644), "0644");
        assert_eq!(
            mode_label(0o100600),
            "0600",
            "file type bits are not part of it"
        );
        assert_eq!(mode_label(0o400), "0400");
    }

    #[test]
    fn plain_file_names_are_one_component_without_control_characters() {
        for name in ["id_ed25519", "id_rsa.old", "work key", "a"] {
            assert!(is_plain_file_name(name), "{name}");
        }
        for name in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "/etc/passwd",
            "a\nb",
            "a\x1bb",
        ] {
            assert!(!is_plain_file_name(name), "{name:?}");
        }
        assert!(!is_plain_file_name(&"a".repeat(256)));
    }

    // ---- the directory ----------------------------------------------------------

    fn touch(dir: &Path, name: &str) {
        fs::write(dir.join(name), "x").unwrap();
    }

    #[test]
    fn only_pairs_are_keys_and_they_are_sorted_ignoring_case() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "id_ed25519",
            "id_ed25519.pub",
            "Work",
            "Work.pub",
            "alpha",
            "alpha.pub",
            "orphan.pub",
            "lonely_private",
            "config",
            "known_hosts",
            "authorized_keys",
        ] {
            touch(dir.path(), name);
        }
        fs::create_dir(dir.path().join("dir")).unwrap();
        fs::create_dir(dir.path().join("dir.pub")).unwrap();

        let scan = scan_ssh_dir(dir.path()).unwrap();
        let names: Vec<&str> = scan.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["alpha", "id_ed25519", "Work"]);
        assert!(!scan.truncated && !scan.missing_dir);
        assert_eq!(scan.files[0].private, dir.path().join("alpha"));
        assert_eq!(scan.files[0].public, dir.path().join("alpha.pub"));
    }

    #[test]
    fn a_missing_directory_is_a_state_and_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let scan = scan_ssh_dir(&dir.path().join("nope")).unwrap();
        assert!(scan.missing_dir && scan.files.is_empty());
    }

    #[test]
    fn a_path_that_is_not_a_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "file");
        assert!(scan_ssh_dir(&dir.path().join("file")).is_err());
    }

    #[test]
    fn a_crowded_directory_lists_a_bounded_number() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..MAX_KEYS + 5 {
            touch(dir.path(), &format!("k{n:04}"));
            touch(dir.path(), &format!("k{n:04}.pub"));
        }
        let scan = scan_ssh_dir(dir.path()).unwrap();
        assert_eq!(scan.files.len(), MAX_KEYS);
        assert!(scan.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_a_key_and_is_marked() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        touch(elsewhere.path(), "real");
        std::os::unix::fs::symlink(elsewhere.path().join("real"), dir.path().join("linked"))
            .unwrap();
        touch(dir.path(), "linked.pub");
        touch(dir.path(), "plain");
        touch(dir.path(), "plain.pub");
        let scan = scan_ssh_dir(dir.path()).unwrap();
        let by_name = |n: &str| scan.files.iter().find(|f| f.name == n).unwrap();
        assert!(by_name("linked").symlink);
        assert!(!by_name("plain").symlink);
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_link_is_not_a_key() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("dangling")).unwrap();
        touch(dir.path(), "dangling.pub");
        assert!(scan_ssh_dir(dir.path()).unwrap().files.is_empty());
    }

    // ---- permissions ----------------------------------------------------------------

    #[cfg(unix)]
    fn with_mode(dir: &Path, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        touch(dir, name);
        let path = dir.join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn permissions_follow_sshs_own_rule() {
        let dir = tempfile::tempdir().unwrap();
        for (mode, too_open) in [
            (0o600, false),
            (0o400, false),
            (0o700, false),
            (0o640, true),
            (0o644, true),
            (0o604, true),
            (0o660, true),
            (0o666, true),
            (0o777, true),
        ] {
            let path = with_mode(dir.path(), &format!("k{mode:o}"), mode);
            let permissions = check_permissions(&path);
            assert_eq!(permissions.is_too_open(), too_open, "{mode:o}");
            if too_open {
                assert_eq!(permissions, Permissions::TooOpen { mode });
            } else {
                assert_eq!(permissions, Permissions::Fine);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_examined_is_unchecked_not_fine() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_permissions(&dir.path().join("gone")),
            Permissions::Unchecked
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_permissions_of_a_link_are_those_of_what_it_points_to() {
        let dir = tempfile::tempdir().unwrap();
        let target = with_mode(dir.path(), "target", 0o644);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            check_permissions(&link),
            Permissions::TooOpen { mode: 0o644 }
        );
    }

    #[cfg(unix)]
    fn pair(dir: &Path, name: &str, mode: u32) {
        with_mode(dir, name, mode);
        touch(dir, &format!("{name}.pub"));
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn the_fix_sets_exactly_0600() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o644, 0o666, 0o640, 0o400, 0o777] {
            let name = format!("key{mode:o}");
            pair(dir.path(), &name, mode);
            fix_permissions(dir.path(), &name).unwrap();
            assert_eq!(mode_of(&dir.path().join(&name)), 0o600, "from {mode:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_fix_leaves_the_public_key_and_other_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        pair(dir.path(), "k", 0o644);
        let other = with_mode(dir.path(), "other", 0o644);
        let public_before = mode_of(&dir.path().join("k.pub"));
        fix_permissions(dir.path(), "k").unwrap();
        assert_eq!(mode_of(&dir.path().join("k.pub")), public_before);
        assert_eq!(mode_of(&other), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn the_fix_refuses_a_symbolic_link_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = with_mode(elsewhere.path(), "real", 0o644);
        std::os::unix::fs::symlink(&target, dir.path().join("linked")).unwrap();
        touch(dir.path(), "linked.pub");
        let err = fix_permissions(dir.path(), "linked").unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert_eq!(
            mode_of(&target),
            0o644,
            "what the link points to is untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_fix_refuses_anything_that_is_not_a_key_pair_in_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        // A file with no .pub next to it.
        with_mode(dir.path(), "config", 0o644);
        assert!(fix_permissions(dir.path(), "config").is_err());
        assert_eq!(mode_of(&dir.path().join("config")), 0o644);
        // A directory.
        fs::create_dir(dir.path().join("d")).unwrap();
        touch(dir.path(), "d.pub");
        assert!(fix_permissions(dir.path(), "d").is_err());
        // Names that reach elsewhere.
        let outside = tempfile::tempdir().unwrap();
        pair(outside.path(), "victim", 0o644);
        let inside = dir.path().join("sub");
        fs::create_dir(&inside).unwrap();
        for name in [
            "../victim".to_string(),
            format!("{}/victim", outside.path().display()),
            "..".to_string(),
            String::new(),
        ] {
            assert!(fix_permissions(&inside, &name).is_err(), "{name:?}");
        }
        assert_eq!(mode_of(&outside.path().join("victim")), 0o644);
        // Missing.
        assert!(fix_permissions(dir.path(), "nothing").is_err());
    }

    // ---- the snapshot ---------------------------------------------------------------

    /// Answers from a table, and records nothing else.
    struct FakeTools {
        agent: AgentState,
        keys: Vec<(&'static str, Result<Fingerprint, String>)>,
    }

    impl KeyTools for FakeTools {
        fn fingerprint(&self, public: &Path) -> Result<Fingerprint, String> {
            let name = public.file_name().unwrap().to_str().unwrap();
            self.keys
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, answer)| answer.clone())
                .unwrap_or_else(|| Err("unknown".to_string()))
        }

        fn agent(&self) -> AgentState {
            self.agent.clone()
        }
    }

    fn fingerprint(hash: &str, kind: &str) -> Fingerprint {
        Fingerprint {
            bits: 256,
            hash: hash.to_string(),
            comment: Some("c".to_string()),
            key_type: kind.to_string(),
        }
    }

    fn snapshot_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a", "a.pub", "b", "b.pub", "bad", "bad.pub"] {
            touch(dir.path(), name);
        }
        dir
    }

    fn tools(agent: AgentState) -> FakeTools {
        FakeTools {
            agent,
            keys: vec![
                ("a.pub", Ok(fingerprint(A, "ED25519"))),
                ("b.pub", Ok(fingerprint(B, "RSA"))),
                (
                    "bad.pub",
                    Err("ssh-keygen could not read it: not a key".to_string()),
                ),
            ],
        }
    }

    #[test]
    fn a_key_is_loaded_when_its_fingerprint_is_in_the_agent() {
        let dir = snapshot_dir();
        let snapshot = load_keys(
            &tools(AgentState::Running {
                hashes: vec![A.to_string()],
            }),
            dir.path(),
        );
        let loaded: Vec<(&str, Option<bool>)> = snapshot
            .keys
            .iter()
            .map(|k| (k.name.as_str(), k.loaded))
            .collect();
        // The key that could not be read is neither: it is not known.
        assert_eq!(
            loaded,
            [("a", Some(true)), ("b", Some(false)), ("bad", None)]
        );
        assert_eq!(snapshot.agent.hashes().map(<[String]>::len), Some(1));
    }

    #[test]
    fn without_an_answer_from_the_agent_nothing_is_said_to_be_loaded_or_not() {
        let dir = snapshot_dir();
        for agent in [
            AgentState::NotStarted,
            AgentState::Unreachable,
            AgentState::Unavailable("x".to_string()),
            AgentState::Unknown("y".to_string()),
        ] {
            let snapshot = load_keys(&tools(agent.clone()), dir.path());
            assert!(
                snapshot.keys.iter().all(|k| k.loaded.is_none()),
                "{agent:?}"
            );
            assert_eq!(snapshot.agent, agent);
        }
    }

    #[test]
    fn a_key_ssh_keygen_cannot_read_is_listed_with_the_reason() {
        let dir = snapshot_dir();
        let snapshot = load_keys(&tools(AgentState::NotStarted), dir.path());
        let bad = snapshot.keys.iter().find(|k| k.name == "bad").unwrap();
        assert_eq!(
            bad.fingerprint,
            Err("ssh-keygen could not read it: not a key".to_string())
        );
    }

    #[test]
    fn a_missing_or_unreadable_directory_is_reported_in_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = load_keys(&tools(AgentState::NotStarted), &dir.path().join("nope"));
        assert!(snapshot.missing_dir && snapshot.keys.is_empty() && snapshot.problem.is_none());

        touch(dir.path(), "file");
        let snapshot = load_keys(&tools(AgentState::NotStarted), &dir.path().join("file"));
        assert!(
            snapshot
                .problem
                .unwrap()
                .starts_with("Could not read the folder")
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_a_key_that_is_too_open_and_not_a_link_can_be_fixed() {
        let dir = tempfile::tempdir().unwrap();
        pair(dir.path(), "open", 0o644);
        pair(dir.path(), "fine", 0o600);
        let elsewhere = tempfile::tempdir().unwrap();
        let target = with_mode(elsewhere.path(), "real", 0o644);
        std::os::unix::fs::symlink(&target, dir.path().join("link")).unwrap();
        touch(dir.path(), "link.pub");
        let snapshot = load_keys(&tools(AgentState::NotStarted), dir.path());
        let can: Vec<(&str, bool)> = snapshot
            .keys
            .iter()
            .map(|k| (k.name.as_str(), k.can_fix_permissions()))
            .collect();
        assert_eq!(can, [("fine", false), ("link", false), ("open", true)]);
    }

    #[test]
    fn keys_are_never_read_only_their_public_files_are_given_to_ssh_keygen() {
        // The fake would answer for a private file's name too; the snapshot only
        // ever asks for `.pub`.
        struct Recording(std::cell::RefCell<Vec<String>>);
        impl KeyTools for Recording {
            fn fingerprint(&self, public: &Path) -> Result<Fingerprint, String> {
                self.0
                    .borrow_mut()
                    .push(public.file_name().unwrap().to_string_lossy().into());
                Err("not needed".to_string())
            }
            fn agent(&self) -> AgentState {
                AgentState::NotStarted
            }
        }
        let dir = snapshot_dir();
        let recording = Recording(Default::default());
        load_keys(&recording, dir.path());
        let asked = recording.0.borrow();
        assert_eq!(*asked, ["a.pub", "b.pub", "bad.pub"]);
    }

    #[test]
    fn a_program_that_is_missing_is_explained() {
        let tools = SystemKeyTools {
            keygen: None,
            ssh_add: None,
        };
        assert!(
            tools
                .fingerprint(Path::new("/x.pub"))
                .unwrap_err()
                .contains("ssh-keygen was not found")
        );
        assert!(
            matches!(tools.agent(), AgentState::Unavailable(why) if why.contains("ssh-add was not found"))
        );
    }

    // ---- making and adding keys --------------------------------------------------

    #[test]
    fn names_for_a_new_key_are_plain_and_cannot_be_something_ssh_reads() {
        let longest = "k".repeat(64);
        for name in [
            "id_ed25519",
            "work",
            "a",
            "my-key_2.old",
            "Work.Key",
            &longest,
        ] {
            assert_eq!(validate_key_name(name), Ok(()), "{name}");
        }
        for (name, expected) in [
            ("", "Give the key a file name."),
            ("a b", "may only contain"),
            ("a/b", "may only contain"),
            ("a\\b", "may only contain"),
            ("a\nb", "may only contain"),
            ("é", "may only contain"),
            ("-oProxyCommand=x", "may only contain"),
            ("-key", "cannot start with"),
            (".hidden", "cannot start with"),
            ("..", "cannot start with"),
            (".", "cannot start with"),
            ("key.pub", "Do not end the name with .pub"),
            ("KEY.PUB", "Do not end the name with .pub"),
            ("config", "reads for something else"),
            ("Config", "reads for something else"),
            ("known_hosts", "reads for something else"),
            ("authorized_keys", "reads for something else"),
            ("environment", "reads for something else"),
        ] {
            let why = validate_key_name(name).unwrap_err();
            assert!(why.contains(expected), "{name:?}: {why}");
        }
        assert!(
            validate_key_name(&"k".repeat(65))
                .unwrap_err()
                .contains("at most 64")
        );
    }

    #[test]
    fn comments_are_free_text_without_control_characters() {
        for comment in [
            "",
            "me@laptop",
            "dev laptop (work) <me@x>",
            "-starts with a dash",
            "ünïcode ok",
        ] {
            assert_eq!(validate_comment(comment), Ok(()), "{comment:?}");
        }
        for comment in [
            "a\nb",
            "a\tb",
            "esc\x1b[31m",
            "\u{202e}rtl",
            "a\u{2066}b",
            "nul\0",
        ] {
            assert!(
                validate_comment(comment)
                    .unwrap_err()
                    .contains("control characters"),
                "{comment:?}"
            );
        }
        assert!(
            validate_comment(" leading")
                .unwrap_err()
                .contains("start or end with a space")
        );
        assert!(
            validate_comment("trailing ")
                .unwrap_err()
                .contains("start or end with a space")
        );
        assert!(
            validate_comment(&"c".repeat(101))
                .unwrap_err()
                .contains("at most 100")
        );
        assert_eq!(validate_comment(&"c".repeat(100)), Ok(()));
    }

    #[test]
    fn the_suggestion_avoids_names_in_use_ignoring_case() {
        assert_eq!(suggest_key_name(&[]), "id_ed25519");
        assert_eq!(suggest_key_name(&["other"]), "id_ed25519");
        assert_eq!(suggest_key_name(&["id_ed25519"]), "id_ed25519_2");
        assert_eq!(
            suggest_key_name(&["ID_ED25519", "id_ed25519_2"]),
            "id_ed25519_3"
        );
        let many: Vec<String> = (2..100).map(|n| format!("id_ed25519_{n}")).collect();
        let mut taken: Vec<&str> = many.iter().map(String::as_str).collect();
        taken.push("id_ed25519");
        assert_eq!(suggest_key_name(&taken), "id_ed25519_new");
        assert_eq!(validate_key_name(&suggest_key_name(&taken)), Ok(()));
    }

    fn abs_dir() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from("C:\\Users\\dev\\.ssh")
        } else {
            PathBuf::from("/home/dev/.ssh")
        }
    }

    #[test]
    fn the_generate_arguments_are_ed25519_a_path_and_an_optional_comment() {
        let dir = abs_dir();
        let path = dir.join("work").to_str().unwrap().to_string();
        assert_eq!(
            generate_args(&dir, "work", Some("me@x")).unwrap(),
            ["-t", "ed25519", "-f", path.as_str(), "-C", "me@x"]
        );
        // No comment, or an empty one: ssh-keygen's own default.
        assert_eq!(
            generate_args(&dir, "work", None).unwrap(),
            ["-t", "ed25519", "-f", path.as_str()]
        );
        assert_eq!(generate_args(&dir, "work", Some("")).unwrap().len(), 4);
    }

    #[test]
    fn the_generate_arguments_can_never_carry_a_passphrase() {
        // Options are at even positions (-t, -f, -C); the odd ones are their values.
        // Whatever the comment says, it is only ever a value, and -N and -P are
        // never options.
        let dir = abs_dir();
        for comment in [
            None,
            Some("-N"),
            Some("-P secret"),
            Some("-N secret"),
            Some("x"),
        ] {
            let args = generate_args(&dir, "work", comment).unwrap();
            let options: Vec<&str> = args.iter().step_by(2).map(String::as_str).collect();
            assert!(
                options.iter().all(|o| matches!(*o, "-t" | "-f" | "-C")),
                "{options:?}"
            );
        }
    }

    #[test]
    fn the_generate_arguments_refuse_what_the_form_should_already_have_refused() {
        let dir = abs_dir();
        for name in ["", "-x", "a b", "../x", "config", "k.pub", ".."] {
            assert!(generate_args(&dir, name, None).is_err(), "{name:?}");
        }
        for comment in ["a\nb", "esc\x1b", " x"] {
            assert!(
                generate_args(&dir, "work", Some(comment)).is_err(),
                "{comment:?}"
            );
        }
        assert!(
            generate_args(Path::new("relative/.ssh"), "work", None)
                .unwrap_err()
                .contains("not an absolute path")
        );
    }

    #[test]
    fn a_name_is_free_only_when_neither_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(ensure_name_is_free(dir.path(), "new"), Ok(()));
        touch(dir.path(), "taken");
        let why = ensure_name_is_free(dir.path(), "taken").unwrap_err();
        assert!(
            why.contains("'taken' already exists") && why.contains("never overwrites"),
            "{why}"
        );
        touch(dir.path(), "half.pub");
        assert!(
            ensure_name_is_free(dir.path(), "half")
                .unwrap_err()
                .contains("'half.pub'")
        );
        fs::create_dir(dir.path().join("d")).unwrap();
        assert!(
            ensure_name_is_free(dir.path(), "d").is_err(),
            "a directory counts"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_counts_as_taken_even_when_it_points_nowhere() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("dangling")).unwrap();
        assert!(ensure_name_is_free(dir.path(), "dangling").is_err());
    }

    #[test]
    fn a_missing_folder_has_nothing_taken() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            ensure_name_is_free(&dir.path().join("not-yet"), "new"),
            Ok(())
        );
    }

    #[test]
    fn the_add_arguments_are_the_keys_absolute_path_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "id");
        touch(dir.path(), "id.pub");
        let args = add_args(dir.path(), "id").unwrap();
        assert_eq!(args, [dir.path().join("id").to_str().unwrap()]);
        assert!(Path::new(&args[0]).is_absolute());
    }

    #[test]
    fn a_key_is_only_added_when_it_is_still_a_pair_in_the_folder() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "private_only");
        touch(dir.path(), "public_only.pub");
        fs::create_dir(dir.path().join("d")).unwrap();
        touch(dir.path(), "d.pub");
        for name in ["private_only", "public_only", "d", "missing"] {
            let why = add_args(dir.path(), name).unwrap_err();
            assert!(why.contains("not a key pair"), "{name}: {why}");
        }
        for name in ["", "..", "../x", "a/b", "-x/../y"] {
            assert!(add_args(dir.path(), name).is_err(), "{name:?}");
        }
        assert!(
            add_args(Path::new("relative"), "id")
                .unwrap_err()
                .contains("not an absolute path")
        );
    }
}
