#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use bifrost_ssh::cli::{Action, Cli};
use bifrost_ssh::commands;
use bifrost_ssh::error::Result;
use bifrost_ssh::sanitize::sanitize_lines;
use bifrost_ssh::store::Store;
use bifrost_ssh::sysenv::process_env;
use bifrost_ssh::tui;
use clap::Parser;

fn main() -> ExitCode {
    let action = Cli::parse().action();
    match run(action, &mut io::stdout().lock(), &mut io::stderr().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Error text can quote file contents and host names, so it is
            // sanitized like everything else that reaches the terminal.
            // Ignore a failure to report the failure: nothing else can be done.
            let _ = writeln!(
                io::stderr(),
                "bifrost: error: {}",
                sanitize_lines(&err.to_string())
            );
            ExitCode::FAILURE
        }
    }
}

/// `out` receives data meant for pipes; `err` receives messages for the user.
fn run(action: Action, out: &mut impl Write, err: &mut impl Write) -> Result<()> {
    match action {
        Action::OpenTui => {
            // A store that cannot be found or read must not stop the TUI from
            // opening: the home screen explains the problem.
            let loaded = Store::from_process_env().and_then(|store| {
                let loaded = store.load()?;
                Ok((store, loaded))
            });
            tui::run(loaded, &process_env)
        }
        // Block 5 stub. `{:?}` escapes control characters in the user-supplied
        // host name.
        Action::Connect { host } => {
            writeln!(out, "Would connect to host {host:?}.")?;
            Ok(())
        }
        Action::List => {
            let store = Store::from_process_env()?;
            commands::list(&store, out, err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_output(host: &str) -> String {
        let mut out = Vec::new();
        let action = Action::Connect {
            host: host.to_string(),
        };
        run(action, &mut out, &mut Vec::new()).expect("stub should not fail");
        String::from_utf8(out).expect("stub output should be UTF-8")
    }

    #[test]
    fn connect_is_still_a_stub() {
        assert_eq!(
            connect_output("prod-db"),
            "Would connect to host \"prod-db\".\n"
        );
    }

    #[test]
    fn connect_stub_escapes_control_characters() {
        let out = connect_output("evil\x1b[31m\nhost");
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
        let action = Action::Connect {
            host: "prod-db".to_string(),
        };
        let err = run(action, &mut Broken, &mut Vec::new()).expect_err("write should fail");
        assert!(err.to_string().contains("closed"));
    }
}
