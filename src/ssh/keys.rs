//! The user's ssh keys: which key pairs are in `~/.ssh`, what they are, whether
//! ssh will accept their permissions and whether the agent holds them.
//!
//! Bifrost never reads a private key. What a key is (its type, size,
//! fingerprint and comment) comes from `ssh-keygen -l -f name.pub`, run on the
//! **public** file, and the private file is only ever looked at for its
//! permissions. Nothing here overwrites a key, and the only way one is removed is
//! [`delete_key`], which removes a key pair and nothing else.
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

/// The home directory that a `~` stands for, when `ssh_dir` is the `.ssh` of one.
/// Any other folder says nothing about where `~` is.
fn home_of(ssh_dir: &Path) -> Option<&Path> {
    if ssh_dir.file_name().is_some_and(|name| name == ".ssh") {
        ssh_dir.parent()
    } else {
        None
    }
}

/// What is stored as a host's identity file for the key `file_name` of
/// `ssh_dir`: `~/.ssh/name` when the directory is a `.ssh`, as everyone writes it,
/// and the full path when it is anywhere else. ssh expands the `~` itself, on
/// every system, which is also why it is always written with `/`.
pub fn identity_file_value(ssh_dir: &Path, file_name: &str) -> String {
    if home_of(ssh_dir).is_some() {
        format!("~/.ssh/{file_name}")
    } else {
        ssh_dir.join(file_name).display().to_string()
    }
}

/// Whether `identity_file`, as saved on a host, is the key `file_name` of
/// `ssh_dir`: the same file whether it is spelled with `~`, with the full path or
/// with `.` and `..` in it (and, on Windows, with `/` or `\`, in any case).
/// Decided from the words, without looking at the disk, so a link is not followed
/// and a file that is not there yet still matches.
///
/// This is the one way a saved key path is compared with a key on disk. Comparing
/// the text of two paths does not work: the same file is written with different
/// separators on Windows.
pub fn names_this_key(identity_file: &str, ssh_dir: &Path, file_name: &str) -> bool {
    if ssh_dir.as_os_str().is_empty() {
        return false;
    }
    let home = home_of(ssh_dir).map(Path::to_string_lossy);
    // Joined here, with `/`, which separates under the rules of every system,
    // and not with `Path::join`, whose separator depends on the system.
    let key = format!("{}/{file_name}", ssh_dir.to_string_lossy());
    names_key(identity_file, home.as_deref(), &key, cfg!(windows))
}

/// [`names_this_key`] on text, by the rules of Windows or of the others as
/// `windows` says. Nothing in it depends on the system that runs it (`std::path`
/// splits by the rules of the running system), so both sets of rules are tested
/// on every system.
///
/// `home` is what a leading `~` stands for; without it a `~` path matches nothing.
/// `~user` is an ordinary relative path, and `~\` is a home path only with the
/// rules of Windows.
fn names_key(identity_file: &str, home: Option<&str>, key: &str, windows: bool) -> bool {
    let text = identity_file.trim();
    let expanded = match text.strip_prefix('~') {
        None => text.to_string(),
        Some("") => match home {
            Some(home) => home.to_string(),
            None => return false,
        },
        Some(rest) => match rest.strip_prefix(|c| c == '/' || (windows && c == '\\')) {
            Some(tail) => match home {
                Some(home) => format!("{home}/{tail}"),
                None => return false,
            },
            None => text.to_string(),
        },
    };
    path_parts(&expanded, windows) == path_parts(key, windows)
}

/// The parts of `path` with `.` dropped and `..` applied, so that two spellings of
/// one path have the same parts. The first part is `/` for a path that starts at
/// a root. With `windows`, both `/` and `\` separate, a drive (`C:`) is kept as the
/// start, and case does not matter; otherwise only `/` separates and `\` is a
/// letter of a name.
fn path_parts(path: &str, windows: bool) -> Vec<String> {
    let text = if windows {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    let mut parts: Vec<String> = Vec::new();
    for (at, part) in text.split('/').enumerate() {
        match part {
            "" if at == 0 => parts.push("/".to_string()),
            "" | "." => {}
            ".." => match parts.last() {
                // Nothing to go up from, in a path that is not anchored.
                None => parts.push("..".to_string()),
                Some(last) if last == ".." => parts.push("..".to_string()),
                // The root and a drive have no parent: `..` stays where it is.
                Some(last) if last == "/" || (windows && last.ends_with(':')) => {}
                Some(_) => {
                    parts.pop();
                }
            },
            other if windows => parts.push(other.to_lowercase()),
            other => parts.push(other.to_string()),
        }
    }
    parts
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

/// What deleting a key removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    pub private: PathBuf,
    pub public: PathBuf,
}

/// Why a key was not (or not entirely) deleted.
#[derive(Debug)]
pub enum DeleteError {
    /// What was asked for is not a key pair of the ssh folder, so nothing was
    /// touched.
    NotAKeyPair,
    /// The first file could not be removed, so nothing was.
    Failed { path: PathBuf, source: io::Error },
    /// The private file was removed and the `.pub` could not be. The key is gone as
    /// a key; the `.pub` is left over.
    PublicLeft { path: PathBuf, source: io::Error },
}

impl std::fmt::Display for DeleteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeleteError::NotAKeyPair => f.write_str(
                "That is not a key pair in the ssh folder (a private file with its .pub next to \
                 it), so nothing was deleted.",
            ),
            DeleteError::Failed { path, source } => write!(
                f,
                "Could not delete {}: {source}. Nothing was deleted.",
                path.display()
            ),
            DeleteError::PublicLeft { path, source } => write!(
                f,
                "The private key was deleted, but {} could not be: {source}. It is left over \
                 and can be removed by hand.",
                path.display()
            ),
        }
    }
}

impl std::error::Error for DeleteError {}

/// Deletes the key pair `name` and `name.pub` of `ssh_dir`: those two files and
/// nothing else.
///
/// Checked again here, at the moment of deleting, whatever the screen showed: `name`
/// is one plain path component, not a file that ssh reads for something else
/// (`config`, `known_hosts`, ...) and not ending in `.pub`; and both files are still
/// there as files, which is what makes a pair (a directory of that name, or a `.pub`
/// whose private half is missing, is not one). Files are removed with `remove_file`
/// only, so nothing is ever removed recursively. A symbolic link is removed as the
/// link it is and what it points to is left alone.
///
/// The private file goes first: it is the one that matters, and if the second
/// removal fails what is left is a `.pub`, which is harmless.
pub fn delete_key(ssh_dir: &Path, name: &str) -> Result<Deleted, DeleteError> {
    delete_key_with(ssh_dir, name, &mut |path| fs::remove_file(path))
}

/// [`delete_key`] with the removal supplied, so that a failure of the second one
/// can be tested.
fn delete_key_with(
    ssh_dir: &Path,
    name: &str,
    remove: &mut dyn FnMut(&Path) -> io::Result<()>,
) -> Result<Deleted, DeleteError> {
    let reserved = RESERVED_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name));
    if !is_plain_file_name(name) || reserved || name.to_ascii_lowercase().ends_with(".pub") {
        return Err(DeleteError::NotAKeyPair);
    }
    let (private, public) = (ssh_dir.join(name), ssh_dir.join(format!("{name}.pub")));
    // What makes a pair, as the scan of the folder decides it: both are files
    // (through a link if it is one), so a folder of either name is not a key.
    let is_file = |path: &Path| fs::metadata(path).is_ok_and(|m| m.is_file());
    if !is_file(&private) || !is_file(&public) {
        return Err(DeleteError::NotAKeyPair);
    }

    remove(&private).map_err(|source| DeleteError::Failed {
        path: private.clone(),
        source,
    })?;
    if let Err(source) = remove(&public) {
        return Err(DeleteError::PublicLeft {
            path: public,
            source,
        });
    }
    Ok(Deleted { private, public })
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

/// Reads the keys but does not ask the agent, for a caller that only wants to
/// list them (choosing a key file for a host). Asking the agent can take up to
/// [`AGENT_TIMEOUT`], and nothing there needs it; every key is then "unknown" as to
/// whether the agent holds it.
pub struct WithoutAgent<'a>(pub &'a dyn KeyTools);

impl KeyTools for WithoutAgent<'_> {
    fn fingerprint(&self, public: &Path) -> Result<Fingerprint, String> {
        self.0.fingerprint(public)
    }

    fn agent(&self) -> AgentState {
        AgentState::Unavailable("The agent was not asked.".to_string())
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

    // ---- the identity file of a key ---------------------------------------------

    #[test]
    fn the_stored_path_of_a_key_is_the_tilde_form_in_a_dot_ssh_and_the_full_path_elsewhere() {
        assert_eq!(
            identity_file_value(Path::new("/home/dev/.ssh"), "id_ed25519"),
            "~/.ssh/id_ed25519"
        );
        assert_eq!(
            identity_file_value(Path::new("/home/dev/.ssh"), "my.key-2"),
            "~/.ssh/my.key-2"
        );
        assert_eq!(
            identity_file_value(Path::new("/srv/keys"), "id_ed25519"),
            Path::new("/srv/keys")
                .join("id_ed25519")
                .display()
                .to_string()
        );
        // A folder that only has ".ssh" in its name is not the default one.
        assert_eq!(
            identity_file_value(Path::new("/home/dev/not.ssh"), "k"),
            Path::new("/home/dev/not.ssh")
                .join("k")
                .display()
                .to_string()
        );
    }

    #[test]
    fn every_way_of_writing_the_same_key_is_recognized() {
        let dir = Path::new("/home/dev/.ssh");
        for spelled in [
            "~/.ssh/id_ed25519",
            "/home/dev/.ssh/id_ed25519",
            "  ~/.ssh/id_ed25519  ",
            "/home/dev/.ssh/./id_ed25519",
            "/home/dev/.ssh/../.ssh/id_ed25519",
            "~/./.ssh//id_ed25519",
        ] {
            assert!(names_this_key(spelled, dir, "id_ed25519"), "{spelled:?}");
        }
    }

    #[test]
    fn other_files_and_near_misses_are_not_the_key() {
        let dir = Path::new("/home/dev/.ssh");
        for spelled in [
            "",
            "~/.ssh/id_ed25519_2",
            "~/.ssh/id_ed2551",
            "~/.ssh/ID_ED25519",
            "~/.ssh/id_ed25519.pub",
            "/home/other/.ssh/id_ed25519",
            "/home/dev/.ssh/sub/id_ed25519",
            "/elsewhere/id_ed25519",
            "id_ed25519",
            "~other/.ssh/id_ed25519",
            "~/.ssh",
        ] {
            let same = names_this_key(spelled, dir, "id_ed25519");
            // Case is the one thing that differs by system.
            if spelled == "~/.ssh/ID_ED25519" && cfg!(windows) {
                continue;
            }
            assert!(!same, "{spelled:?}");
        }
    }

    // The two sets of rules are tested on plain text, so that each says the same on
    // every system that runs the tests: `std::path` would split by the rules of the
    // running one.

    #[test]
    fn the_windows_way_of_writing_a_path_is_recognized_on_every_system() {
        let home = Some(r"C:\Users\dev");
        // The key as it is built: the folder as the system spells it, then `/`, and
        // as a person would write it.
        for key in [
            r"C:\Users\dev\.ssh/id_ed25519",
            r"C:\Users\dev\.ssh\id_ed25519",
        ] {
            for spelled in [
                "~/.ssh/id_ed25519",
                r"~\.ssh\id_ed25519",
                r"C:\Users\dev\.ssh\id_ed25519",
                "C:/Users/dev/.ssh/id_ed25519",
                r"C:\Users\dev/.ssh\id_ed25519",
                r"c:\users\DEV\.SSH\ID_ED25519",
                r"C:\Users\dev\.ssh\.\id_ed25519",
                r"C:\Users\dev\.ssh\..\.ssh\id_ed25519",
                r"C:\Users\dev\.ssh\\id_ed25519",
                r"  ~\.ssh\id_ed25519  ",
                // `..` cannot climb out of a drive.
                r"C:\..\..\Users\dev\.ssh\id_ed25519",
            ] {
                assert!(names_key(spelled, home, key, true), "{spelled:?} {key:?}");
            }
            for spelled in [
                "",
                r"D:\Users\dev\.ssh\id_ed25519",
                r"\Users\dev\.ssh\id_ed25519",
                r"C:\Users\other\.ssh\id_ed25519",
                r"C:\Users\dev\.ssh\sub\id_ed25519",
                r"C:\Users\dev\.ssh\id_ed25519.pub",
                r"~\.ssh\id_ed25519_2",
                r"~other\.ssh\id_ed25519",
                "id_ed25519",
            ] {
                assert!(!names_key(spelled, home, key, true), "{spelled:?} {key:?}");
            }
        }
        // A `~` with no home to stand for is nothing.
        assert!(!names_key("~/.ssh/id", None, r"C:\Users\dev\.ssh/id", true));
        assert!(!names_key("~", None, r"C:\Users\dev\.ssh/id", true));
    }

    #[test]
    fn on_other_systems_a_backslash_is_part_of_a_name_and_case_matters() {
        let home = Some("/home/dev");
        let key = "/home/dev/.ssh/id_ed25519";
        for spelled in [
            "~/.ssh/id_ed25519",
            "/home/dev/.ssh/id_ed25519",
            "/home/dev/.ssh/./id_ed25519",
            "/home/dev/.ssh/../.ssh/id_ed25519",
            "~/./.ssh//id_ed25519",
        ] {
            assert!(names_key(spelled, home, key, false), "{spelled:?}");
        }
        for spelled in [
            r"~\.ssh\id_ed25519",
            r"/home/dev/.ssh\id_ed25519",
            "/home/dev/.ssh/ID_ED25519",
            "/HOME/dev/.ssh/id_ed25519",
        ] {
            assert!(!names_key(spelled, home, key, false), "{spelled:?}");
        }
        // `~\` is a home path only with the rules of Windows: here it is a file called
        // `~\id` in the current folder, and not `id` in the home.
        assert!(!names_key(r"~\id", home, "/home/dev/id", false));
        assert!(names_key(
            r"~\id",
            Some("C:/Users/dev"),
            "C:/Users/dev/id",
            true
        ));
        // The same name with a backslash in it is its own file.
        assert!(names_key(r"~/.ssh/a\b", home, r"/home/dev/.ssh/a\b", false));
        assert!(!names_key(r"~/.ssh/a\b", home, "/home/dev/.ssh/a/b", false));
    }

    #[test]
    fn a_relative_path_is_never_a_key_of_an_absolute_folder() {
        for windows in [false, true] {
            for spelled in ["k", ".ssh/k", "../k", "../.ssh/k", "./.ssh/k"] {
                assert!(
                    !names_key(spelled, Some("/home/dev"), "/home/dev/.ssh/k", windows),
                    "{spelled:?} {windows}"
                );
            }
        }
    }

    #[test]
    fn a_tilde_only_means_the_home_when_the_folder_is_a_dot_ssh() {
        // `/srv/keys` says nothing about where `~` is: `~/keys/k` is not its `k`.
        assert!(!names_this_key("~/keys/k", Path::new("/srv/keys"), "k"));
        assert!(names_this_key("/srv/keys/k", Path::new("/srv/keys"), "k"));
        // No folder, no key: a bare file name is not one.
        assert!(!names_this_key("k", Path::new(""), "k"));
    }

    #[test]
    fn a_tilde_with_no_home_is_not_a_match_and_does_not_panic() {
        // The root has no parent, so there is no home to expand `~` against.
        assert!(!names_this_key("~/.ssh/k", Path::new("/"), "k"));
        assert!(!names_this_key("~", Path::new("/home/dev/.ssh"), "k"));
    }

    // ---- listing without the agent ----------------------------------------------

    /// Tools that fail the test if the agent is asked.
    struct NeverAsksTheAgent;

    impl KeyTools for NeverAsksTheAgent {
        fn fingerprint(&self, _: &Path) -> Result<Fingerprint, String> {
            Ok(Fingerprint {
                bits: 256,
                hash: "SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw".to_string(),
                comment: None,
                key_type: "ED25519".to_string(),
            })
        }

        fn agent(&self) -> AgentState {
            panic!("the agent was asked");
        }
    }

    #[test]
    fn listing_without_the_agent_never_asks_it_and_says_nothing_about_what_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a", "b"] {
            fs::write(dir.path().join(name), "x").unwrap();
            fs::write(dir.path().join(format!("{name}.pub")), "x").unwrap();
        }
        let snapshot = load_keys(&WithoutAgent(&NeverAsksTheAgent), dir.path());
        assert_eq!(snapshot.keys.len(), 2);
        assert!(snapshot.keys.iter().all(|key| key.loaded.is_none()));
        assert!(matches!(snapshot.agent, AgentState::Unavailable(_)));
        assert!(
            snapshot.keys.iter().all(|key| key.fingerprint.is_ok()),
            "still reads each key"
        );
    }

    // ---- deleting a key -----------------------------------------------------------

    /// A `.ssh` with these files (name, contents), and a few that must survive.
    fn ssh_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            fs::write(dir.path().join(name), text).unwrap();
        }
        dir
    }

    fn what_is_left(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    const BYSTANDERS: [(&str, &str); 6] = [
        ("other", "other private"),
        ("other.pub", "other public"),
        ("config", "Host x"),
        ("known_hosts", "x"),
        ("authorized_keys", "x"),
        ("lonely.pub", "no private half"),
    ];

    fn with_bystanders(pair: &[(&str, &str)]) -> tempfile::TempDir {
        let mut files: Vec<(&str, &str)> = BYSTANDERS.to_vec();
        files.extend_from_slice(pair);
        ssh_with(&files)
    }

    #[test]
    fn a_key_pair_is_removed_and_nothing_else_is() {
        let dir = with_bystanders(&[("id_ed25519", "secret"), ("id_ed25519.pub", "public")]);
        let done = delete_key(dir.path(), "id_ed25519").unwrap();
        assert_eq!(done.private, dir.path().join("id_ed25519"));
        assert_eq!(done.public, dir.path().join("id_ed25519.pub"));
        assert_eq!(
            what_is_left(dir.path()),
            [
                "authorized_keys",
                "config",
                "known_hosts",
                "lonely.pub",
                "other",
                "other.pub"
            ]
        );
        for (name, text) in BYSTANDERS {
            assert_eq!(
                fs::read_to_string(dir.path().join(name)).unwrap(),
                text,
                "{name}"
            );
        }
    }

    #[test]
    fn a_name_that_is_not_one_plain_file_name_is_refused_and_nothing_is_touched() {
        let dir = with_bystanders(&[("k", "s"), ("k.pub", "p")]);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("victim"), "x").unwrap();
        fs::write(outside.path().join("victim.pub"), "x").unwrap();
        let escape = format!(
            "../{}/victim",
            outside.path().file_name().unwrap().to_string_lossy()
        );
        for bad in [
            "",
            ".",
            "..",
            "../k",
            "a/../k",
            "sub/k",
            "/etc/passwd",
            "k\\x",
            "k\nx",
            "k\u{7}",
            escape.as_str(),
        ] {
            assert!(
                matches!(delete_key(dir.path(), bad), Err(DeleteError::NotAKeyPair)),
                "{bad:?}"
            );
        }
        assert!(dir.path().join("k").exists() && dir.path().join("k.pub").exists());
        assert!(
            outside.path().join("victim").exists(),
            "nothing outside the folder"
        );
    }

    #[test]
    fn the_files_ssh_reads_for_other_purposes_are_never_deleted_even_with_a_pub_next_to_them() {
        for reserved in [
            "config",
            "known_hosts",
            "authorized_keys",
            "AUTHORIZED_KEYS",
            "environment",
            "rc",
        ] {
            let dir = ssh_with(&[(reserved, "precious"), (&format!("{reserved}.pub"), "x")]);
            assert!(
                matches!(
                    delete_key(dir.path(), reserved),
                    Err(DeleteError::NotAKeyPair)
                ),
                "{reserved}"
            );
            assert_eq!(
                fs::read_to_string(dir.path().join(reserved)).unwrap(),
                "precious"
            );
        }
    }

    #[test]
    fn a_name_ending_in_pub_is_refused_so_that_a_public_key_is_never_taken_for_the_private_one() {
        let dir = ssh_with(&[("k", "s"), ("k.pub", "p"), ("k.pub.pub", "pp")]);
        for name in ["k.pub", "K.PUB", "k.pub.pub"] {
            assert!(
                matches!(delete_key(dir.path(), name), Err(DeleteError::NotAKeyPair)),
                "{name}"
            );
        }
        assert_eq!(what_is_left(dir.path()), ["k", "k.pub", "k.pub.pub"]);
    }

    #[test]
    fn what_is_not_a_pair_is_refused_a_private_file_alone_a_pub_alone_and_a_folder() {
        let dir = ssh_with(&[("alone", "s"), ("only.pub", "p")]);
        fs::create_dir(dir.path().join("folder")).unwrap();
        fs::write(dir.path().join("folder/inner"), "x").unwrap();
        fs::create_dir(dir.path().join("folder.pub")).unwrap();
        fs::write(dir.path().join("k"), "s").unwrap();
        fs::create_dir(dir.path().join("k.pub")).unwrap();
        for name in ["alone", "only", "folder", "k", "missing"] {
            assert!(
                matches!(delete_key(dir.path(), name), Err(DeleteError::NotAKeyPair)),
                "{name}"
            );
        }
        assert!(dir.path().join("alone").exists());
        assert!(
            dir.path().join("folder/inner").exists(),
            "nothing inside a folder is touched"
        );
        assert!(dir.path().join("k").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_removed_as_a_link_and_what_it_points_to_is_left_alone() {
        use std::os::unix::fs::symlink;
        let dir = with_bystanders(&[]);
        let elsewhere = tempfile::tempdir().unwrap();
        fs::write(elsewhere.path().join("real"), "the real private key").unwrap();
        fs::write(elsewhere.path().join("real.pub"), "the real public key").unwrap();
        symlink(elsewhere.path().join("real"), dir.path().join("linked")).unwrap();
        symlink(
            elsewhere.path().join("real.pub"),
            dir.path().join("linked.pub"),
        )
        .unwrap();

        let done = delete_key(dir.path(), "linked").unwrap();
        assert_eq!(done.private, dir.path().join("linked"));
        assert!(
            fs::symlink_metadata(dir.path().join("linked")).is_err(),
            "the link is gone"
        );
        assert!(fs::symlink_metadata(dir.path().join("linked.pub")).is_err());
        assert_eq!(
            fs::read_to_string(elsewhere.path().join("real")).unwrap(),
            "the real private key",
            "the file it pointed to is untouched"
        );
        assert_eq!(
            fs::read_to_string(elsewhere.path().join("real.pub")).unwrap(),
            "the real public key"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_folder_or_to_nothing_is_not_a_key_and_is_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = ssh_with(&[("k.pub", "p"), ("j.pub", "p")]);
        let elsewhere = tempfile::tempdir().unwrap();
        fs::write(elsewhere.path().join("inside"), "precious").unwrap();
        symlink(elsewhere.path(), dir.path().join("k")).unwrap();
        symlink(elsewhere.path().join("nothing"), dir.path().join("j")).unwrap();
        for name in ["k", "j"] {
            assert!(
                matches!(delete_key(dir.path(), name), Err(DeleteError::NotAKeyPair)),
                "{name}"
            );
        }
        assert_eq!(
            fs::read_to_string(elsewhere.path().join("inside")).unwrap(),
            "precious"
        );
        assert!(dir.path().join("k.pub").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_that_is_itself_a_link_is_used_as_the_folder_it_is() {
        use std::os::unix::fs::symlink;
        // ~/.ssh is often a link into a dotfiles folder.
        let real = ssh_with(&[("k", "s"), ("k.pub", "p"), ("keep", "x")]);
        let holder = tempfile::tempdir().unwrap();
        let ssh = holder.path().join(".ssh");
        symlink(real.path(), &ssh).unwrap();
        delete_key(&ssh, "k").unwrap();
        assert_eq!(what_is_left(real.path()), ["keep"]);
    }

    #[test]
    fn if_the_private_file_cannot_be_removed_nothing_is_and_it_is_said() {
        let dir = ssh_with(&[("k", "s"), ("k.pub", "p")]);
        let mut asked = Vec::new();
        let result = delete_key_with(dir.path(), "k", &mut |path| {
            asked.push(path.to_path_buf());
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        });
        let Err(DeleteError::Failed { path, .. }) = &result else {
            panic!("{result:?}");
        };
        assert_eq!(path, &dir.path().join("k"));
        assert_eq!(asked, [dir.path().join("k")], "the .pub was not even tried");
        let said = result.unwrap_err().to_string();
        assert!(
            said.contains("denied") && said.contains("Nothing was deleted."),
            "{said}"
        );
        assert_eq!(what_is_left(dir.path()), ["k", "k.pub"]);
    }

    #[test]
    fn if_only_the_public_file_cannot_be_removed_that_is_said_plainly() {
        let dir = ssh_with(&[("k", "s"), ("k.pub", "p")]);
        let result = delete_key_with(dir.path(), "k", &mut |path| {
            if path.ends_with("k.pub") {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
            } else {
                fs::remove_file(path)
            }
        });
        let Err(DeleteError::PublicLeft { path, .. }) = &result else {
            panic!("{result:?}");
        };
        assert_eq!(path, &dir.path().join("k.pub"));
        let said = result.unwrap_err().to_string();
        assert!(
            said.starts_with("The private key was deleted, but"),
            "{said}"
        );
        assert_eq!(what_is_left(dir.path()), ["k.pub"]);
    }

    #[test]
    fn the_private_file_is_removed_before_the_public_one() {
        let dir = ssh_with(&[("k", "s"), ("k.pub", "p")]);
        let mut order = Vec::new();
        delete_key_with(dir.path(), "k", &mut |path| {
            order.push(path.file_name().unwrap().to_string_lossy().into_owned());
            fs::remove_file(path)
        })
        .unwrap();
        assert_eq!(order, ["k", "k.pub"]);
    }

    #[test]
    fn a_missing_folder_or_a_key_that_is_gone_is_not_a_crash() {
        let dir = ssh_with(&[("k", "s"), ("k.pub", "p")]);
        delete_key(dir.path(), "k").unwrap();
        assert!(matches!(
            delete_key(dir.path(), "k"),
            Err(DeleteError::NotAKeyPair)
        ));
        assert!(matches!(
            delete_key(&dir.path().join("nowhere"), "k"),
            Err(DeleteError::NotAKeyPair)
        ));
    }

    #[test]
    fn every_error_says_in_plain_english_what_happened_to_the_files() {
        for (error, must_say) in [
            (DeleteError::NotAKeyPair, "nothing was deleted"),
            (
                DeleteError::Failed {
                    path: PathBuf::from("/x/k"),
                    source: io::Error::other("no"),
                },
                "Nothing was deleted.",
            ),
            (
                DeleteError::PublicLeft {
                    path: PathBuf::from("/x/k.pub"),
                    source: io::Error::other("no"),
                },
                "left over",
            ),
        ] {
            let text = error.to_string();
            assert!(text.contains(must_say) && !text.contains("::"), "{text}");
        }
    }
}
