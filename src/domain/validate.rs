//! Validation of host fields.
//!
//! Every text value that can reach an `ssh` argument vector or an exported
//! config file passes through here first. All text fields reject control
//! characters (including newlines, except in notes), a leading `-`, and
//! leading or trailing whitespace; the per-field rules narrow that further.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::jump::{ChainError, jump_chain};
use super::{Forward, Host, Warning};
use crate::text::escape_control;

pub const MAX_NAME_LEN: usize = 64;
pub const MAX_USER_LEN: usize = 64;
pub const MAX_HOSTNAME_LEN: usize = 253;
pub const MAX_HOSTNAME_LABEL_LEN: usize = 63;
pub const MAX_IDENTITY_FILE_LEN: usize = 1024;
pub const MAX_TAGS: usize = 10;
pub const MAX_TAG_LEN: usize = 32;
pub const MAX_NOTES_LEN: usize = 500;

/// The host field a validation problem belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Hostname,
    User,
    Port,
    IdentityFile,
    ProxyJump,
    LocalForward,
    RemoteForward,
    Tags,
    Notes,
}

impl Field {
    /// Human-readable name of the field, as used at the start of messages.
    pub fn label(self) -> &'static str {
        match self {
            Field::Name => "Name",
            Field::Hostname => "Hostname",
            Field::User => "User",
            Field::Port => "Port",
            Field::IdentityFile => "Identity file",
            Field::ProxyJump => "Jump host",
            Field::LocalForward => "Local forward",
            Field::RemoteForward => "Remote forward",
            Field::Tags => "Tags",
            Field::Notes => "Notes",
        }
    }
}

/// A value that cannot be accepted, with a message fit to show to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    field: Field,
    message: String,
    host: Option<(usize, String)>,
}

impl ValidationError {
    pub(crate) fn new(field: Field, message: impl Into<String>) -> Self {
        ValidationError {
            field,
            message: message.into(),
            host: None,
        }
    }

    pub(crate) fn with_host(mut self, index: usize, name: &str) -> Self {
        self.host = Some((index, name.to_string()));
        self
    }

    pub fn field(&self) -> Field {
        self.field
    }

    /// The message without the host prefix.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Name of the host the error belongs to, when validating a collection.
    pub fn host_name(&self) -> Option<&str> {
        self.host.as_ref().map(|(_, name)| name.as_str())
    }

    /// Position of the offending host in the collection, when known.
    pub fn host_index(&self) -> Option<usize> {
        self.host.as_ref().map(|(index, _)| *index)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Some((_, name)) => write!(f, "Host '{}': {}", escape_control(name), self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ValidationError {}

type Check = Result<(), ValidationError>;

/// Rules shared by every text field except notes.
fn check_text(field: Field, what: &str, value: &str) -> Check {
    if value.chars().any(char::is_control) {
        return Err(ValidationError::new(
            field,
            format!("{what} must not contain control characters or line breaks."),
        ));
    }
    if value.starts_with('-') {
        return Err(ValidationError::new(
            field,
            format!("{what} must not start with '-'."),
        ));
    }
    if value.trim() != value {
        return Err(ValidationError::new(
            field,
            format!("{what} must not start or end with whitespace."),
        ));
    }
    Ok(())
}

fn check_len(field: Field, what: &str, value: &str, max: usize) -> Check {
    if value.chars().count() > max {
        return Err(ValidationError::new(
            field,
            format!("{what} must be at most {max} characters long."),
        ));
    }
    Ok(())
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

fn validate_name_like(field: Field, what: &str, value: &str) -> Check {
    if value.is_empty() {
        return Err(ValidationError::new(
            field,
            format!("{what} cannot be empty."),
        ));
    }
    check_text(field, what, value)?;
    check_len(field, what, value, MAX_NAME_LEN)?;
    if !value.chars().all(is_name_char) {
        return Err(ValidationError::new(
            field,
            format!("{what} may only contain letters, digits, '.', '_' and '-'."),
        ));
    }
    Ok(())
}

/// A host name as shown in Bifrost: 1-64 characters from `A-Za-z0-9._-`.
pub fn validate_name(value: &str) -> Check {
    validate_name_like(Field::Name, "Name", value)
}

fn validate_host_like(field: Field, what: &str, value: &str) -> Check {
    if value.is_empty() {
        return Err(ValidationError::new(
            field,
            format!("{what} cannot be empty."),
        ));
    }
    check_text(field, what, value)?;
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if value.len() > MAX_HOSTNAME_LEN {
        return Err(ValidationError::new(
            field,
            format!("{what} must be at most {MAX_HOSTNAME_LEN} characters long."),
        ));
    }
    let labels: Vec<&str> = value.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err(ValidationError::new(
                field,
                format!("{what} has an empty part; check for a leading, trailing or doubled '.'."),
            ));
        }
        if label.len() > MAX_HOSTNAME_LABEL_LEN {
            return Err(ValidationError::new(
                field,
                format!(
                    "Each part of {what} (between dots) must be at most \
                     {MAX_HOSTNAME_LABEL_LEN} characters long."
                ),
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ValidationError::new(
                field,
                format!(
                    "{what} may only contain letters, digits, '-' and '.', or be an IP address."
                ),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ValidationError::new(
                field,
                format!("Parts of {what} must not start or end with '-'."),
            ));
        }
    }
    let last = labels.last().copied().unwrap_or_default();
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ValidationError::new(
            field,
            format!("{what} looks like an IP address but is not a valid one."),
        ));
    }
    Ok(())
}

/// An IPv4 address, an IPv6 address or a DNS name (max 253 characters,
/// labels of at most 63).
pub fn validate_hostname(value: &str) -> Check {
    validate_host_like(Field::Hostname, "Hostname", value)
}

/// The remote user: 1-64 characters from `A-Za-z0-9._-@\`.
pub fn validate_user(value: &str) -> Check {
    if value.is_empty() {
        return Err(ValidationError::new(Field::User, "User cannot be empty."));
    }
    check_text(Field::User, "User", value)?;
    check_len(Field::User, "User", value, MAX_USER_LEN)?;
    if !value
        .chars()
        .all(|c| is_name_char(c) || matches!(c, '@' | '\\'))
    {
        return Err(ValidationError::new(
            Field::User,
            "User may only contain letters, digits, '.', '_', '-', '@' and '\\'.",
        ));
    }
    Ok(())
}

fn validate_port_like(field: Field, what: &str, port: u16) -> Check {
    if port == 0 {
        return Err(ValidationError::new(
            field,
            format!("{what} must be between 1 and 65535."),
        ));
    }
    Ok(())
}

/// A TCP port between 1 and 65535.
pub fn validate_port(port: u16) -> Check {
    validate_port_like(Field::Port, "Port", port)
}

/// Path to a private key. Public keys (`.pub`) are rejected.
pub fn validate_identity_file(value: &str) -> Check {
    let field = Field::IdentityFile;
    if value.is_empty() {
        return Err(ValidationError::new(
            field,
            "Identity file cannot be empty.",
        ));
    }
    check_text(field, "Identity file", value)?;
    check_len(field, "Identity file", value, MAX_IDENTITY_FILE_LEN)?;
    if value.to_ascii_lowercase().ends_with(".pub") {
        return Err(ValidationError::new(
            field,
            "Identity file looks like a public key (it ends in .pub). \
             Choose the private key file instead.",
        ));
    }
    Ok(())
}

/// The name of another host to use as a jump host. Whether that host exists
/// is checked when validating the whole collection.
pub fn validate_jump_name(value: &str) -> Check {
    validate_name_like(Field::ProxyJump, "Jump host", value)
}

/// A port forward. The bind address is always localhost, so there is none.
pub fn validate_forward(field: Field, forward: &Forward) -> Check {
    let base = field.label();
    validate_port_like(field, &format!("{base} listen port"), forward.listen_port)?;
    validate_host_like(
        field,
        &format!("{base} destination host"),
        &forward.dest_host,
    )?;
    validate_port_like(
        field,
        &format!("{base} destination port"),
        forward.dest_port,
    )
}

/// At most 10 tags, each 1-32 characters from `a-z0-9-`.
pub fn validate_tags(tags: &[String]) -> Check {
    if tags.len() > MAX_TAGS {
        return Err(ValidationError::new(
            Field::Tags,
            format!("A host can have at most {MAX_TAGS} tags."),
        ));
    }
    for tag in tags {
        check_text(Field::Tags, "Tags", tag)?;
        if tag.is_empty() {
            return Err(ValidationError::new(Field::Tags, "Tags cannot be empty."));
        }
        check_len(Field::Tags, "Tags", tag, MAX_TAG_LEN)?;
        if !tag
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(ValidationError::new(
                Field::Tags,
                format!(
                    "Tags may only contain lowercase letters, digits and '-' ('{}' does not).",
                    escape_control(tag)
                ),
            ));
        }
    }
    Ok(())
}

/// Free text of at most 500 characters. Notes are private and never reach ssh,
/// so the text rules are looser than for other fields: leading `-` and
/// surrounding whitespace are fine, and so are line breaks and tabs. Other
/// control characters are not.
pub fn validate_notes(value: &str) -> Check {
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err(ValidationError::new(
            Field::Notes,
            "Notes may contain line breaks and tabs but no other control characters.",
        ));
    }
    check_len(Field::Notes, "Notes", value, MAX_NOTES_LEN)
}

/// Validates every field of one host on its own. References to other hosts
/// (`proxy_jump`) are only checked for shape; see [`check_hosts`].
pub fn validate_host_fields(host: &Host) -> Check {
    validate_name(&host.name)?;
    validate_hostname(&host.hostname)?;
    if let Some(user) = &host.user {
        validate_user(user)?;
    }
    if let Some(port) = host.port {
        validate_port(port)?;
    }
    if let Some(identity_file) = &host.identity_file {
        validate_identity_file(identity_file)?;
    }
    if let Some(jump) = &host.proxy_jump {
        validate_jump_name(jump)?;
    }
    for forward in &host.local_forwards {
        validate_forward(Field::LocalForward, forward)?;
    }
    for forward in &host.remote_forwards {
        validate_forward(Field::RemoteForward, forward)?;
    }
    validate_tags(&host.tags)?;
    if let Some(notes) = &host.notes {
        validate_notes(notes)?;
    }
    Ok(())
}

/// Validates a whole collection: every host's fields, case-insensitive name
/// uniqueness, and that each jump chain resolves (targets exist, no loops,
/// at most [`super::jump::MAX_JUMP_HOPS`] hops).
///
/// The error names the offending host and its position in `hosts`.
pub fn check_hosts(hosts: &[Host]) -> Check {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (index, host) in hosts.iter().enumerate() {
        validate_host_fields(host).map_err(|e| e.with_host(index, &host.name))?;
        if seen.insert(host.name.to_ascii_lowercase(), index).is_some() {
            return Err(ValidationError::new(
                Field::Name,
                format!(
                    "A host named '{}' already exists (names are not case-sensitive).",
                    host.name
                ),
            )
            .with_host(index, &host.name));
        }
    }
    for (index, host) in hosts.iter().enumerate() {
        if host.proxy_jump.is_some() {
            jump_chain(hosts, host).map_err(|e: ChainError| {
                ValidationError::new(Field::ProxyJump, e.to_string()).with_host(index, &host.name)
            })?;
        }
    }
    Ok(())
}

/// Warns when the identity file does not exist. `home` is used to expand a
/// leading `~`; without it, `~` paths cannot be checked and yield no warning.
pub fn identity_file_warning(host: &Host, home: Option<&Path>) -> Option<Warning> {
    let path = host.identity_file.as_deref()?;
    let expanded = expand_tilde(path, home)?;
    if expanded.exists() {
        return None;
    }
    Some(Warning::new(format!(
        "Host '{}': the identity file '{}' does not exist.",
        host.name, path
    )))
}

pub(crate) fn expand_tilde(path: &str, home: Option<&Path>) -> Option<PathBuf> {
    match path.strip_prefix('~') {
        None => Some(PathBuf::from(path)),
        Some("") => home.map(Path::to_path_buf),
        Some(rest) => match rest.strip_prefix(['/', '\\']) {
            Some(tail) => home.map(|home| home.join(tail)),
            // `~user/...` is not supported; treat as an ordinary path.
            None => Some(PathBuf::from(path)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(check: Check) -> String {
        check.expect_err("value should be rejected").to_string()
    }

    type Mutation = Box<dyn Fn(&mut Host)>;

    fn host(name: &str) -> Host {
        Host::new(name, format!("{name}.example.com"))
    }

    // ---- shared text rules -------------------------------------------------

    #[test]
    fn text_fields_reject_control_characters_and_newlines() {
        for bad in [
            "a\nb", "a\rb", "a\0b", "a\x1bb", "a\tb", "a\u{7f}b", "a\u{85}b",
        ] {
            assert!(validate_name(bad).is_err(), "name {bad:?}");
            assert!(validate_hostname(bad).is_err(), "hostname {bad:?}");
            assert!(validate_user(bad).is_err(), "user {bad:?}");
            assert!(validate_identity_file(bad).is_err(), "identity {bad:?}");
            assert!(validate_jump_name(bad).is_err(), "jump {bad:?}");
        }
        assert_eq!(
            message(validate_identity_file("key\nProxyCommand evil")),
            "Identity file must not contain control characters or line breaks."
        );
    }

    #[test]
    fn text_fields_reject_a_leading_dash() {
        for bad in ["-oProxyCommand=evil", "-x", "--"] {
            assert!(validate_name(bad).is_err(), "name {bad:?}");
            assert!(validate_hostname(bad).is_err(), "hostname {bad:?}");
            assert!(validate_user(bad).is_err(), "user {bad:?}");
            assert!(validate_identity_file(bad).is_err(), "identity {bad:?}");
            assert!(validate_jump_name(bad).is_err(), "jump {bad:?}");
        }
        assert_eq!(
            message(validate_name("-oProxyCommand=id")),
            "Name must not start with '-'."
        );
    }

    #[test]
    fn text_fields_reject_surrounding_whitespace() {
        for bad in [" a", "a ", "\u{a0}a", "a\u{3000}"] {
            assert!(validate_name(bad).is_err(), "name {bad:?}");
            assert!(validate_hostname(bad).is_err(), "hostname {bad:?}");
            assert!(validate_user(bad).is_err(), "user {bad:?}");
            assert!(validate_identity_file(bad).is_err(), "identity {bad:?}");
        }
    }

    // ---- name --------------------------------------------------------------

    #[test]
    fn name_accepts_valid_values() {
        for good in ["a", "web-01", "db.internal", "my_host", "A.b_c-9"] {
            assert!(validate_name(good).is_ok(), "{good}");
        }
        assert!(validate_name(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn name_rejects_invalid_values() {
        assert_eq!(message(validate_name("")), "Name cannot be empty.");
        assert_eq!(
            message(validate_name(&"a".repeat(65))),
            "Name must be at most 64 characters long."
        );
        for bad in [
            "a b", "a/b", "a;b", "a$(id)", "a`id`", "münchen", "a:b", "a@b",
        ] {
            assert_eq!(
                message(validate_name(bad)),
                "Name may only contain letters, digits, '.', '_' and '-'.",
                "{bad}"
            );
        }
    }

    // ---- hostname ----------------------------------------------------------

    #[test]
    fn hostname_accepts_ips_and_dns_names() {
        for good in [
            "192.168.1.10",
            "::1",
            "2001:db8::ff00:42:8329",
            "fe80::1",
            "localhost",
            "example.com",
            "a-b.c-d.example.org",
            "xn--mnchen-3ya.de",
            "host1",
        ] {
            assert!(validate_hostname(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn hostname_rejects_invalid_dns_names() {
        for bad in [
            "",
            "exa mple.com",
            "example..com",
            ".example.com",
            "example.com.",
            "-example.com",
            "example-.com",
            "ex_ample.com",
            "münchen.de",
            "exa$mple.com",
            "[::1]",
            "host;id",
            "999.999.999.999",
            "1.2.3",
        ] {
            assert!(validate_hostname(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hostname_length_limits() {
        let label63 = "a".repeat(63);
        assert!(validate_hostname(&format!("{label63}.com")).is_ok());
        assert_eq!(
            message(validate_hostname(&format!("{}.com", "a".repeat(64)))),
            "Each part of Hostname (between dots) must be at most 63 characters long."
        );
        // 4 labels of 63 + 3 dots = 255 > 253.
        let too_long = [label63.as_str(); 4].join(".");
        assert_eq!(
            message(validate_hostname(&too_long)),
            "Hostname must be at most 253 characters long."
        );
        // 3 labels of 63 + one of 61 + 3 dots = 253: allowed.
        let max = format!("{0}.{0}.{0}.{1}", label63, "a".repeat(61));
        assert_eq!(max.len(), 253);
        assert!(validate_hostname(&max).is_ok());
    }

    // ---- user --------------------------------------------------------------

    #[test]
    fn user_accepts_documented_characters() {
        for good in [
            "root",
            "deploy",
            "j.doe",
            "svc_backup",
            "a-b",
            "user@corp",
            "DOMAIN\\user",
        ] {
            assert!(validate_user(good).is_ok(), "{good}");
        }
        assert!(validate_user(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn user_rejects_everything_else() {
        assert_eq!(message(validate_user("")), "User cannot be empty.");
        assert_eq!(
            message(validate_user(&"a".repeat(65))),
            "User must be at most 64 characters long."
        );
        for bad in [
            "a b", "a;b", "a$b", "a/b", "a:b", "a%b", "üser", "a\"b", "a'b",
        ] {
            assert!(validate_user(bad).is_err(), "{bad:?}");
        }
    }

    // ---- port --------------------------------------------------------------

    #[test]
    fn port_range() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(22).is_ok());
        assert!(validate_port(65535).is_ok());
        assert_eq!(
            message(validate_port(0)),
            "Port must be between 1 and 65535."
        );
    }

    // ---- identity file -----------------------------------------------------

    #[test]
    fn identity_file_rejects_public_keys() {
        for bad in ["~/.ssh/id_ed25519.pub", "/keys/a.PUB", "C:\\keys\\id.pub"] {
            assert_eq!(
                message(validate_identity_file(bad)),
                "Identity file looks like a public key (it ends in .pub). \
                 Choose the private key file instead.",
                "{bad}"
            );
        }
    }

    #[test]
    fn identity_file_accepts_ordinary_paths() {
        for good in [
            "~/.ssh/id_ed25519",
            "/home/me/keys/my key",
            "C:\\Users\\me\\.ssh\\id_ed25519",
            "keys/pub-notes",
        ] {
            assert!(validate_identity_file(good).is_ok(), "{good}");
        }
        assert!(validate_identity_file("").is_err());
        assert!(validate_identity_file(&"a".repeat(1025)).is_err());
    }

    #[test]
    fn missing_identity_file_only_warns() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("id_ed25519");
        std::fs::write(&existing, "not a real key").unwrap();

        let mut host = host("web");
        host.identity_file = Some(existing.to_string_lossy().into_owned());
        assert_eq!(identity_file_warning(&host, None), None);

        let missing = dir.path().join("missing_key");
        host.identity_file = Some(missing.to_string_lossy().into_owned());
        let warning = identity_file_warning(&host, None).expect("warning expected");
        assert!(warning.message().contains("does not exist"));
        assert!(warning.message().contains("Host 'web'"));
        // Still valid: a missing file is not an error.
        assert!(validate_host_fields(&host).is_ok());
    }

    #[test]
    fn tilde_paths_expand_against_the_given_home() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("key"), "x").unwrap();
        let mut host = host("web");
        host.identity_file = Some("~/key".to_string());
        assert_eq!(identity_file_warning(&host, Some(dir.path())), None);
        host.identity_file = Some("~/absent".to_string());
        assert!(identity_file_warning(&host, Some(dir.path())).is_some());
        // Without a home directory a `~` path cannot be checked.
        assert_eq!(identity_file_warning(&host, None), None);
    }

    // ---- jump host name ----------------------------------------------------

    #[test]
    fn jump_name_uses_the_name_rules() {
        assert!(validate_jump_name("bastion").is_ok());
        assert_eq!(
            message(validate_jump_name("bad name")),
            "Jump host may only contain letters, digits, '.', '_' and '-'."
        );
    }

    // ---- forwards ----------------------------------------------------------

    fn forward(listen: u16, dest: &str, port: u16) -> Forward {
        Forward {
            listen_port: listen,
            dest_host: dest.to_string(),
            dest_port: port,
        }
    }

    #[test]
    fn forwards_validate_ports_and_destination() {
        let field = Field::LocalForward;
        assert!(validate_forward(field, &forward(8080, "localhost", 80)).is_ok());
        assert!(validate_forward(field, &forward(8080, "10.0.0.5", 5432)).is_ok());
        assert!(validate_forward(field, &forward(8080, "::1", 80)).is_ok());
        assert_eq!(
            message(validate_forward(field, &forward(0, "db", 80))),
            "Local forward listen port must be between 1 and 65535."
        );
        assert_eq!(
            message(validate_forward(
                Field::RemoteForward,
                &forward(80, "db", 0)
            )),
            "Remote forward destination port must be between 1 and 65535."
        );
    }

    #[test]
    fn forward_destination_is_validated_like_a_hostname() {
        let field = Field::LocalForward;
        for bad in [
            "",
            "-oProxyCommand=x",
            "db\nhost",
            "db host",
            "db;id",
            "db_host",
        ] {
            assert!(
                validate_forward(field, &forward(8080, bad, 80)).is_err(),
                "{bad:?}"
            );
        }
    }

    // ---- tags --------------------------------------------------------------

    #[test]
    fn tags_rules() {
        let tags = |list: &[&str]| list.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert!(validate_tags(&tags(&["prod", "eu-west-1", "a1"])).is_ok());
        assert!(validate_tags(&tags(&["a"; 10])).is_ok());
        assert_eq!(
            message(validate_tags(&tags(&["a"; 11]))),
            "A host can have at most 10 tags."
        );
        assert!(validate_tags(&tags(&[&"a".repeat(32)])).is_ok());
        assert!(validate_tags(&tags(&[&"a".repeat(33)])).is_err());
        for bad in ["", "Prod", "a b", "a_b", "-a", "a.b", "a\nb", "é"] {
            assert!(validate_tags(&tags(&[bad])).is_err(), "{bad:?}");
        }
    }

    // ---- notes -------------------------------------------------------------

    #[test]
    fn notes_may_contain_newlines_and_tabs_but_not_other_control_characters() {
        assert!(validate_notes("first line\nsecond line").is_ok());
        assert!(validate_notes("").is_ok());
        assert!(validate_notes("col1\tcol2").is_ok());
        for bad in [
            "cr\r\nlf",
            "esc\x1b[31m",
            "nul\0",
            "bell\x07",
            "del\x7f",
            "nel\u{85}",
        ] {
            assert_eq!(
                message(validate_notes(bad)),
                "Notes may contain line breaks and tabs but no other control characters.",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn notes_are_exempt_from_the_dash_and_whitespace_rules() {
        for good in [
            "- buy milk",
            "-oProxyCommand=id is only text here",
            "  indented",
            "trailing newline\n",
            "\n\nleading blank lines",
            "\ttabbed",
        ] {
            assert!(validate_notes(good).is_ok(), "{good:?}");
        }
        // The other text fields keep those rules.
        assert!(validate_name("- buy milk").is_err());
        assert!(validate_identity_file(" key").is_err());
    }

    #[test]
    fn notes_length_limit_counts_characters() {
        assert!(validate_notes(&"a".repeat(500)).is_ok());
        assert!(validate_notes(&"é".repeat(500)).is_ok());
        assert_eq!(
            message(validate_notes(&"a".repeat(501))),
            "Notes must be at most 500 characters long."
        );
    }

    // ---- collections -------------------------------------------------------

    #[test]
    fn names_must_be_unique_case_insensitively() {
        let hosts = vec![host("Web"), host("web")];
        let err = check_hosts(&hosts).unwrap_err();
        assert_eq!(err.field(), Field::Name);
        assert_eq!(err.host_index(), Some(1));
        assert_eq!(
            err.to_string(),
            "Host 'web': A host named 'web' already exists (names are not case-sensitive)."
        );
    }

    #[test]
    fn errors_name_the_offending_host() {
        let mut bad = host("bad");
        bad.port = Some(0);
        let err = check_hosts(&[host("good"), bad]).unwrap_err();
        assert_eq!(err.host_name(), Some("bad"));
        assert_eq!(err.host_index(), Some(1));
        assert_eq!(
            err.to_string(),
            "Host 'bad': Port must be between 1 and 65535."
        );
    }

    #[test]
    fn jump_hosts_must_exist() {
        let mut a = host("a");
        a.proxy_jump = Some("ghost".into());
        let err = check_hosts(&[a]).unwrap_err();
        assert_eq!(err.field(), Field::ProxyJump);
        assert_eq!(
            err.to_string(),
            "Host 'a': The jump host 'ghost' does not exist."
        );
    }

    #[test]
    fn self_referencing_jump_is_rejected() {
        let mut a = host("a");
        a.proxy_jump = Some("a".into());
        let err = check_hosts(&[a]).unwrap_err();
        assert_eq!(err.message(), "A host cannot be its own jump host.");
    }

    #[test]
    fn jump_cycles_are_rejected() {
        let mut a = host("a");
        a.proxy_jump = Some("b".into());
        let mut b = host("b");
        b.proxy_jump = Some("c".into());
        let mut c = host("c");
        c.proxy_jump = Some("a".into());
        let err = check_hosts(&[a, b, c]).unwrap_err();
        assert_eq!(
            err.message(),
            "The jump hosts form a loop: a -> b -> c -> a."
        );
    }

    #[test]
    fn jump_chains_longer_than_five_hops_are_rejected() {
        let chain = |hops: usize| -> Vec<Host> {
            (0..=hops)
                .map(|i| {
                    let mut h = host(&format!("h{i}"));
                    if i < hops {
                        h.proxy_jump = Some(format!("h{}", i + 1));
                    }
                    h
                })
                .collect()
        };
        assert!(check_hosts(&chain(5)).is_ok());
        let err = check_hosts(&chain(6)).unwrap_err();
        assert_eq!(err.host_name(), Some("h0"));
        assert!(err.message().contains("at most 5 hops"));
    }

    #[test]
    fn injection_attempts_in_any_field_are_rejected() {
        let attempts: Vec<(&str, Mutation)> = vec![
            ("name", Box::new(|h| h.name = "-oProxyCommand=id".into())),
            (
                "name newline",
                Box::new(|h| h.name = "a\nProxyCommand id".into()),
            ),
            (
                "hostname option",
                Box::new(|h| h.hostname = "-oProxyCommand=id".into()),
            ),
            (
                "hostname newline",
                Box::new(|h| h.hostname = "h\nProxyCommand id".into()),
            ),
            (
                "user option",
                Box::new(|h| h.user = Some("-oProxyCommand=id".into())),
            ),
            (
                "user newline",
                Box::new(|h| h.user = Some("u\nProxyCommand id".into())),
            ),
            (
                "identity option",
                Box::new(|h| h.identity_file = Some("-oProxyCommand=id".into())),
            ),
            (
                "identity newline",
                Box::new(|h| h.identity_file = Some("k\nProxyCommand id".into())),
            ),
            (
                "jump option",
                Box::new(|h| h.proxy_jump = Some("-oProxyCommand=id".into())),
            ),
            (
                "forward host",
                Box::new(|h| h.local_forwards.push(forward(1, "-oProxyCommand=id", 2))),
            ),
            (
                "forward newline",
                Box::new(|h| h.remote_forwards.push(forward(1, "a\nb", 2))),
            ),
            ("tag", Box::new(|h| h.tags.push("-oProxyCommand=id".into()))),
            (
                "notes control",
                Box::new(|h| h.notes = Some("x\x1b]0;evil\x07".into())),
            ),
        ];
        for (label, mutate) in attempts {
            let mut candidate = host("ok");
            mutate(&mut candidate);
            assert!(
                validate_host_fields(&candidate).is_err(),
                "{label} should be rejected"
            );
        }
    }
}
