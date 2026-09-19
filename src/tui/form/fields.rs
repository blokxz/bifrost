//! The fields of the add/edit form: their names, the help shown for each, and
//! the conversion between what the user types and the typed values of a
//! [`crate::domain::Host`].
//!
//! Validation itself is not repeated here: every rule comes from
//! [`crate::domain::validate`], so the form can never accept what the store
//! would refuse. This module only turns text into values, and explains what a
//! field expects.

use crate::domain::validate::{
    Field, validate_forward, validate_hostname, validate_identity_file, validate_name,
    validate_notes, validate_port, validate_tags, validate_user,
};
use crate::domain::{Forward, ValidationError};

/// One row of the form. `Advanced` is the row that shows or hides the last four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormField {
    Name,
    Hostname,
    User,
    Port,
    IdentityFile,
    Tags,
    Notes,
    Advanced,
    ProxyJump,
    LocalForwards,
    RemoteForwards,
    ForwardAgent,
}

/// The rows always shown, in order.
pub const BASIC: [FormField; 7] = [
    FormField::Name,
    FormField::Hostname,
    FormField::User,
    FormField::Port,
    FormField::IdentityFile,
    FormField::Tags,
    FormField::Notes,
];

/// The rows inside the collapsed "Advanced" section, in order.
pub const ADVANCED: [FormField; 4] = [
    FormField::ProxyJump,
    FormField::LocalForwards,
    FormField::RemoteForwards,
    FormField::ForwardAgent,
];

impl FormField {
    pub fn label(self) -> &'static str {
        match self {
            FormField::Name => "Name",
            FormField::Hostname => "Hostname",
            FormField::User => "User",
            FormField::Port => "Port",
            FormField::IdentityFile => "Identity file",
            FormField::Tags => "Tags",
            FormField::Notes => "Notes",
            FormField::Advanced => "Advanced",
            FormField::ProxyJump => "Jump host",
            FormField::LocalForwards => "Local forwards",
            FormField::RemoteForwards => "Remote fwds",
            FormField::ForwardAgent => "Forward agent",
        }
    }

    /// Whether the value is typed into a text box.
    pub fn is_text(self) -> bool {
        !matches!(
            self,
            FormField::Advanced | FormField::ProxyJump | FormField::ForwardAgent
        )
    }

    pub fn is_advanced(self) -> bool {
        ADVANCED.contains(&self)
    }

    /// The form row that shows a validation problem about `field`.
    pub fn from_validation(field: Field) -> FormField {
        match field {
            Field::Name => FormField::Name,
            Field::Hostname => FormField::Hostname,
            Field::User => FormField::User,
            Field::Port => FormField::Port,
            Field::IdentityFile => FormField::IdentityFile,
            Field::ProxyJump => FormField::ProxyJump,
            Field::LocalForward => FormField::LocalForwards,
            Field::RemoteForward => FormField::RemoteForwards,
            Field::Tags => FormField::Tags,
            Field::Notes => FormField::Notes,
        }
    }

    /// What the field is for, and an example of a good value.
    pub fn help(self) -> FieldHelp {
        let (explanation, example) = match self {
            FormField::Name => (
                "A short label for this connection. Letters, digits, . _ and - only.",
                "prod-web-1",
            ),
            FormField::Hostname => (
                "The server's DNS name or IP address.",
                "web.example.com  or  203.0.113.10",
            ),
            FormField::User => (
                "Your login name on the server. Leave empty to use ssh's default.",
                "deploy",
            ),
            FormField::Port => (
                "The server's SSH port. Leave empty for the default, 22.",
                "2222",
            ),
            FormField::IdentityFile => (
                "Path to your private key file. Leave empty to use ssh's default keys.",
                "~/.ssh/id_ed25519",
            ),
            FormField::Tags => (
                "Labels to group hosts, separated by commas: lowercase letters, digits and -.",
                "prod, web",
            ),
            FormField::Notes => (
                "Private notes, never sent to ssh or exported. Type \\n (backslash, n) to insert a line break.",
                "Nightly backup runs here.\\nOwner: ops team",
            ),
            FormField::Advanced => (
                "Options most people do not need: a jump host, port forwards, agent forwarding.",
                "Press Enter or Space to show or hide them.",
            ),
            FormField::ProxyJump => (
                "Connect through another saved host first (a bastion). Enter opens the list.",
                "bastion",
            ),
            FormField::LocalForwards => (
                "Make a service on the server reachable on this machine, as listen-port:host:port. Separate several with commas.",
                "8080:localhost:80, 5433:db.internal:5432",
            ),
            FormField::RemoteForwards => (
                "Make a service on this machine reachable from the server. Same format, separate several with commas.",
                "9000:localhost:3000",
            ),
            FormField::ForwardAgent => (
                "Lets the server use your ssh keys while you are connected. Space turns it on or off.",
                "off (recommended)",
            ),
        };
        FieldHelp {
            explanation,
            example,
        }
    }
}

/// The help shown while a field is focused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldHelp {
    pub explanation: &'static str,
    pub example: &'static str,
}

/// The warning shown while agent forwarding is on.
pub const AGENT_WARNING: &str = "Anyone who controls this server can use your ssh keys while you \
     are connected. Only enable this for servers you fully trust.";

// ---- notes ---------------------------------------------------------------

/// Notes as typed in a single-line box: a backslash becomes `\\`, a line break
/// `\n` and a tab `\t`, so multi-line notes survive editing unchanged.
pub fn escape_notes(notes: &str) -> String {
    let mut out = String::with_capacity(notes.len());
    for c in notes.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// The inverse of [`escape_notes`]. A backslash followed by anything else is
/// kept as typed.
pub fn unescape_notes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('n') => {
                out.push('\n');
                chars.next();
            }
            Some('t') => {
                out.push('\t');
                chars.next();
            }
            Some('\\') => {
                out.push('\\');
                chars.next();
            }
            _ => out.push('\\'),
        }
    }
    out
}

// ---- conversions ---------------------------------------------------------

fn message(err: ValidationError) -> String {
    err.message().to_string()
}

/// A single-line value with the whitespace around it removed: it is never
/// meaningful, and the store would refuse it.
fn trimmed(text: &str) -> &str {
    text.trim()
}

pub fn parse_name(text: &str) -> Result<String, String> {
    let name = trimmed(text);
    validate_name(name).map_err(message)?;
    Ok(name.to_string())
}

pub fn parse_hostname(text: &str) -> Result<String, String> {
    let hostname = trimmed(text);
    validate_hostname(hostname).map_err(message)?;
    Ok(hostname.to_string())
}

/// Empty means "not set".
pub fn parse_user(text: &str) -> Result<Option<String>, String> {
    let user = trimmed(text);
    if user.is_empty() {
        return Ok(None);
    }
    validate_user(user).map_err(message)?;
    Ok(Some(user.to_string()))
}

/// Empty means "not set" (ssh's default, 22).
pub fn parse_port(text: &str) -> Result<Option<u16>, String> {
    let text = trimmed(text);
    if text.is_empty() {
        return Ok(None);
    }
    let port: u16 = match text.parse() {
        Ok(port) => port,
        Err(_) => return Err("Port must be a number between 1 and 65535.".to_string()),
    };
    validate_port(port).map_err(message)?;
    Ok(Some(port))
}

/// Empty means "not set".
pub fn parse_identity_file(text: &str) -> Result<Option<String>, String> {
    let path = trimmed(text);
    if path.is_empty() {
        return Ok(None);
    }
    validate_identity_file(path).map_err(message)?;
    Ok(Some(path.to_string()))
}

/// Tags separated by commas and/or spaces.
pub fn parse_tags(text: &str) -> Result<Vec<String>, String> {
    let tags: Vec<String> = text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();
    validate_tags(&tags).map_err(message)?;
    Ok(tags)
}

pub fn format_tags(tags: &[String]) -> String {
    tags.join(", ")
}

/// Empty means "no notes". Surrounding whitespace is kept: notes may have it.
pub fn parse_notes(text: &str) -> Result<Option<String>, String> {
    let notes = unescape_notes(text);
    if notes.is_empty() {
        return Ok(None);
    }
    validate_notes(&notes).map_err(message)?;
    Ok(Some(notes))
}

pub fn format_notes(notes: Option<&str>) -> String {
    notes.map(escape_notes).unwrap_or_default()
}

/// `listen-port:host:port`, separated by commas. The host may be an IPv6
/// address: only the first and last `:` separate the ports.
pub fn parse_forwards(text: &str, field: Field) -> Result<Vec<Forward>, String> {
    let mut forwards = Vec::new();
    for item in text.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        let bad_format = || {
            format!(
                "'{item}' is not a forward. Write it as listen-port:host:port, \
                 for example 8080:localhost:80."
            )
        };
        let (listen, rest) = item.split_once(':').ok_or_else(bad_format)?;
        let (dest_host, dest_port) = rest.rsplit_once(':').ok_or_else(bad_format)?;
        let port = |text: &str| text.trim().parse::<u16>().map_err(|_| bad_format());
        let forward = Forward {
            listen_port: port(listen)?,
            dest_host: dest_host.trim().trim_matches(['[', ']']).to_string(),
            dest_port: port(dest_port)?,
        };
        validate_forward(field, &forward).map_err(message)?;
        forwards.push(forward);
    }
    Ok(forwards)
}

pub fn format_forwards(forwards: &[Forward]) -> String {
    forwards
        .iter()
        .map(|f| {
            let host = if f.dest_host.contains(':') {
                format!("[{}]", f.dest_host)
            } else {
                f.dest_host.clone()
            };
            format!("{}:{host}:{}", f.listen_port, f.dest_port)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- notes -------------------------------------------------------------

    #[test]
    fn notes_escape_and_unescape_are_inverse() {
        for notes in [
            "plain",
            "two\nlines",
            "tab\there",
            "back\\slash",
            "a\\nb",
            "\\",
            "trailing\\",
            "mix\n\t\\\n",
            "",
            " leading and trailing ",
        ] {
            assert_eq!(unescape_notes(&escape_notes(notes)), notes, "{notes:?}");
        }
    }

    #[test]
    fn typing_backslash_n_makes_a_line_break() {
        assert_eq!(unescape_notes("one\\ntwo"), "one\ntwo");
        assert_eq!(unescape_notes("a\\tb"), "a\tb");
        assert_eq!(unescape_notes("a\\\\b"), "a\\b");
    }

    #[test]
    fn an_unknown_escape_is_kept_as_typed() {
        assert_eq!(unescape_notes("C:\\Users"), "C:\\Users");
        assert_eq!(unescape_notes("end\\"), "end\\");
    }

    #[test]
    fn escaped_notes_are_a_single_line_without_control_characters() {
        let shown = escape_notes("a\nb\tc");
        assert_eq!(shown, "a\\nb\\tc");
        assert!(!shown.chars().any(char::is_control));
    }

    #[test]
    fn notes_keep_their_surrounding_whitespace_and_line_breaks() {
        assert_eq!(
            parse_notes(" spaced\\nout ").unwrap().as_deref(),
            Some(" spaced\nout ")
        );
        assert_eq!(parse_notes("").unwrap(), None);
    }

    #[test]
    fn notes_over_the_limit_are_refused_with_the_store_message() {
        let err = parse_notes(&"x".repeat(501)).unwrap_err();
        assert!(err.contains("at most 500"), "{err}");
    }

    // ---- single values -----------------------------------------------------

    #[test]
    fn surrounding_whitespace_is_removed_from_single_line_values() {
        assert_eq!(parse_name("  web  ").unwrap(), "web");
        assert_eq!(
            parse_hostname(" web.example.com ").unwrap(),
            "web.example.com"
        );
        assert_eq!(parse_user(" deploy ").unwrap().as_deref(), Some("deploy"));
    }

    #[test]
    fn empty_optional_values_mean_not_set() {
        assert_eq!(parse_user("").unwrap(), None);
        assert_eq!(parse_user("   ").unwrap(), None);
        assert_eq!(parse_port("").unwrap(), None);
        assert_eq!(parse_identity_file("").unwrap(), None);
        assert_eq!(parse_tags("").unwrap(), Vec::<String>::new());
        assert!(parse_forwards("", Field::LocalForward).unwrap().is_empty());
    }

    #[test]
    fn required_values_cannot_be_empty() {
        assert!(parse_name("").unwrap_err().contains("cannot be empty"));
        assert!(parse_hostname("").unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn store_rules_are_the_ones_applied() {
        assert!(
            parse_name("bad name")
                .unwrap_err()
                .contains("may only contain")
        );
        assert!(
            parse_name("-rf")
                .unwrap_err()
                .contains("must not start with '-'")
        );
        assert!(parse_user("-oProxyCommand=x").unwrap_err().contains("'-'"));
        assert!(
            parse_identity_file("~/.ssh/id.pub")
                .unwrap_err()
                .contains(".pub")
        );
        assert!(parse_hostname("not a host").is_err());
    }

    #[test]
    fn ports_are_numbers_between_1_and_65535() {
        assert_eq!(parse_port("22").unwrap(), Some(22));
        assert_eq!(parse_port(" 2222 ").unwrap(), Some(2222));
        for bad in ["0", "65536", "-1", "abc", "22a", "2 2", "1.5"] {
            let err = parse_port(bad).unwrap_err();
            assert!(err.contains("between 1 and 65535"), "{bad}: {err}");
        }
    }

    // ---- tags --------------------------------------------------------------

    #[test]
    fn tags_are_split_on_commas_and_spaces() {
        assert_eq!(parse_tags("prod, web").unwrap(), ["prod", "web"]);
        assert_eq!(parse_tags("prod web,db").unwrap(), ["prod", "web", "db"]);
        assert_eq!(parse_tags(" , ,a,, ").unwrap(), ["a"]);
    }

    #[test]
    fn tags_follow_the_store_rules() {
        assert!(parse_tags("Prod").is_err(), "uppercase is refused");
        assert!(parse_tags("a_b").is_err());
        let many = (0..11)
            .map(|n| format!("t{n}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_tags(&many).unwrap_err().contains("at most 10"));
    }

    #[test]
    fn tags_round_trip() {
        let tags = vec!["prod".to_string(), "eu-west".to_string()];
        assert_eq!(parse_tags(&format_tags(&tags)).unwrap(), tags);
    }

    // ---- forwards ----------------------------------------------------------

    fn forward(listen: u16, host: &str, port: u16) -> Forward {
        Forward {
            listen_port: listen,
            dest_host: host.to_string(),
            dest_port: port,
        }
    }

    #[test]
    fn forwards_are_listen_port_host_port() {
        assert_eq!(
            parse_forwards("8080:localhost:80", Field::LocalForward).unwrap(),
            [forward(8080, "localhost", 80)]
        );
    }

    #[test]
    fn several_forwards_are_separated_by_commas() {
        assert_eq!(
            parse_forwards(
                " 8080:localhost:80 , 5433:db.internal:5432 ",
                Field::LocalForward
            )
            .unwrap(),
            [
                forward(8080, "localhost", 80),
                forward(5433, "db.internal", 5432)
            ]
        );
    }

    #[test]
    fn an_ipv6_destination_works_with_or_without_brackets() {
        let expected = [forward(8080, "::1", 80)];
        assert_eq!(
            parse_forwards("8080:::1:80", Field::LocalForward).unwrap(),
            expected
        );
        assert_eq!(
            parse_forwards("8080:[::1]:80", Field::LocalForward).unwrap(),
            expected
        );
        assert_eq!(format_forwards(&expected), "8080:[::1]:80");
    }

    #[test]
    fn a_malformed_forward_explains_the_format() {
        for bad in [
            "8080",
            "8080:localhost",
            "x:localhost:80",
            "8080:localhost:y",
            "8080::80",
        ] {
            let err = parse_forwards(bad, Field::LocalForward).unwrap_err();
            assert!(
                err.contains("listen-port:host:port") || err.contains("cannot be empty"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn forwards_follow_the_store_rules() {
        let err = parse_forwards("0:localhost:80", Field::LocalForward).unwrap_err();
        assert!(err.contains("between 1 and 65535"), "{err}");
        let err = parse_forwards("8080:bad host:80", Field::RemoteForward).unwrap_err();
        assert!(err.contains("Remote forward"), "{err}");
    }

    #[test]
    fn forwards_round_trip() {
        let forwards = vec![
            forward(8080, "localhost", 80),
            forward(9000, "2001:db8::1", 22),
        ];
        let text = format_forwards(&forwards);
        assert_eq!(
            parse_forwards(&text, Field::LocalForward).unwrap(),
            forwards
        );
    }

    // ---- fields ------------------------------------------------------------

    #[test]
    fn every_field_has_a_label_an_explanation_and_an_example() {
        for field in BASIC.iter().chain(&ADVANCED).chain(&[FormField::Advanced]) {
            let help = field.help();
            assert!(!field.label().is_empty());
            assert!(help.explanation.len() > 20, "{field:?}");
            assert!(!help.example.is_empty(), "{field:?}");
        }
    }

    #[test]
    fn the_notes_help_says_how_to_insert_a_line_break() {
        let help = FormField::Notes.help();
        assert!(help.explanation.contains("\\n"), "{}", help.explanation);
        assert!(
            help.explanation.contains("line break"),
            "{}",
            help.explanation
        );
    }

    #[test]
    fn labels_fit_the_label_column() {
        for field in BASIC.iter().chain(&ADVANCED).chain(&[FormField::Advanced]) {
            assert!(field.label().len() <= 14, "{:?}", field.label());
        }
    }

    #[test]
    fn text_and_special_fields_are_told_apart() {
        assert!(BASIC.iter().all(|f| f.is_text()));
        assert!(!FormField::Advanced.is_text());
        assert!(!FormField::ProxyJump.is_text());
        assert!(!FormField::ForwardAgent.is_text());
        assert!(FormField::LocalForwards.is_text());
        assert!(ADVANCED.iter().all(|f| f.is_advanced()));
        assert!(!FormField::Name.is_advanced());
    }

    #[test]
    fn validation_problems_map_to_the_form_row_that_shows_them() {
        assert_eq!(FormField::from_validation(Field::Name), FormField::Name);
        assert_eq!(
            FormField::from_validation(Field::ProxyJump),
            FormField::ProxyJump
        );
        assert_eq!(
            FormField::from_validation(Field::LocalForward),
            FormField::LocalForwards
        );
        assert_eq!(
            FormField::from_validation(Field::RemoteForward),
            FormField::RemoteForwards
        );
    }

    #[test]
    fn the_agent_warning_is_about_trusting_the_server() {
        assert!(AGENT_WARNING.contains("ssh keys"));
        assert!(AGENT_WARNING.contains("trust"));
    }
}
