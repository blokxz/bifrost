#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use bifrost_ssh::cli::{Action, Cli};
use bifrost_ssh::error::Result;
use clap::Parser;

fn main() -> ExitCode {
    let action = Cli::parse().action();
    match run(action, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Ignore a failure to report the failure: nothing else can be done.
            let _ = writeln!(io::stderr(), "bifrost: error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Block 1 stub: only reports what each action would do.
fn run(action: Action, out: &mut impl Write) -> Result<()> {
    match action {
        Action::OpenTui => writeln!(out, "Would open the TUI.")?,
        // `{:?}` escapes control characters in the user-supplied host name.
        Action::Connect { host } => writeln!(out, "Would connect to host {host:?}.")?,
        Action::List => writeln!(out, "Would list the saved hosts.")?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output_of(action: Action) -> String {
        let mut buf = Vec::new();
        run(action, &mut buf).expect("stub should not fail");
        String::from_utf8(buf).expect("stub output should be UTF-8")
    }

    #[test]
    fn stubs_describe_what_they_would_do() {
        assert_eq!(output_of(Action::OpenTui), "Would open the TUI.\n");
        assert_eq!(output_of(Action::List), "Would list the saved hosts.\n");
        assert_eq!(
            output_of(Action::Connect {
                host: "prod-db".to_string()
            }),
            "Would connect to host \"prod-db\".\n"
        );
    }

    #[test]
    fn connect_stub_escapes_control_characters() {
        let out = output_of(Action::Connect {
            host: "evil\x1b[31m\nhost".to_string(),
        });
        assert!(!out.contains('\x1b'));
        assert_eq!(out.matches('\n').count(), 1, "only the final newline");
    }

    #[test]
    fn write_failures_become_app_errors() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let err = run(Action::List, &mut Broken).expect_err("write should fail");
        assert!(err.to_string().contains("closed"));
    }
}
