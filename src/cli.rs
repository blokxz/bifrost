//! Command-line interface definition.

use clap::{Parser, Subcommand};

/// Beginner-friendly SSH TUI.
///
/// Run without arguments to open the TUI, pass a host to connect directly,
/// or use `list` to print the saved hosts.
#[derive(Debug, Parser)]
#[command(name = "bifrost", version, args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Saved host to connect to directly.
    ///
    /// The name `list` is reserved for the `list` subcommand.
    host: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the saved hosts.
    List,
}

/// What the user asked Bifrost to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Open the TUI.
    OpenTui,
    /// Connect directly to a host.
    Connect { host: String },
    /// Print the saved hosts.
    List,
}

impl Cli {
    pub fn action(self) -> Action {
        match (self.command, self.host) {
            (Some(Command::List), _) => Action::List,
            (None, Some(host)) => Action::Connect { host },
            (None, None) => Action::OpenTui,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<Action, clap::Error> {
        Cli::try_parse_from(std::iter::once("bifrost").chain(args.iter().copied())).map(Cli::action)
    }

    fn parse_err(args: &[&str]) -> clap::Error {
        parse(args).expect_err("arguments should be rejected")
    }

    #[test]
    fn no_arguments_opens_the_tui() {
        assert_eq!(parse(&[]).unwrap(), Action::OpenTui);
    }

    #[test]
    fn host_argument_connects_directly() {
        assert_eq!(
            parse(&["prod-db"]).unwrap(),
            Action::Connect {
                host: "prod-db".to_string()
            }
        );
    }

    #[test]
    fn list_subcommand_lists_hosts() {
        assert_eq!(parse(&["list"]).unwrap(), Action::List);
    }

    #[test]
    fn list_does_not_accept_a_host() {
        assert_eq!(
            parse_err(&["list", "prod-db"]).kind(),
            ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn ssh_style_options_are_rejected_as_hosts() {
        assert_eq!(
            parse_err(&["-oProxyCommand=evil"]).kind(),
            ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn extra_positional_arguments_are_rejected() {
        // clap reports this as a conflict with a subcommand; only the rejection matters.
        assert_eq!(parse_err(&["one", "two"]).exit_code(), 2);
    }

    #[test]
    fn help_flags_display_help() {
        for flag in ["--help", "-h"] {
            let err = parse_err(&[flag]);
            assert_eq!(err.kind(), ErrorKind::DisplayHelp, "flag {flag}");
            let text = err.to_string();
            assert!(text.contains("list"), "help should mention `list`: {text}");
            assert!(text.contains("[HOST]"), "help should mention host: {text}");
        }
    }

    #[test]
    fn version_flags_display_the_package_version() {
        for flag in ["--version", "-V"] {
            let err = parse_err(&[flag]);
            assert_eq!(err.kind(), ErrorKind::DisplayVersion, "flag {flag}");
            assert_eq!(
                err.to_string().trim(),
                format!("bifrost {}", env!("CARGO_PKG_VERSION"))
            );
        }
    }
}
