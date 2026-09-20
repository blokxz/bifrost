#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use bifrost_ssh::cli::{Action, Cli};
use bifrost_ssh::commands;
use bifrost_ssh::error::Result;
use bifrost_ssh::sanitize::sanitize_lines;
use bifrost_ssh::ssh::binary::resolve_ssh;
use bifrost_ssh::store::Store;
use bifrost_ssh::sysenv::process_env;
use bifrost_ssh::sysenv::{Platform, home_dir};
use bifrost_ssh::tui;
use clap::Parser;

fn main() -> ExitCode {
    let action = Cli::parse().action();
    if let Action::Connect { host } = action {
        return exit_with(connect(&host));
    }
    match run(action, &mut io::stdout(), &mut io::stderr()) {
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

/// Exits with `status`. Statuses above 255 (a Windows process can return any
/// 32-bit value) cannot be an `ExitCode`, so they exit directly.
fn exit_with(status: i32) -> ExitCode {
    match u8::try_from(status) {
        Ok(status) => ExitCode::from(status),
        Err(_) => std::process::exit(status),
    }
}

/// `bifrost <host>`: connects and returns the status to exit with. Bifrost's own
/// failures are [`commands::OWN_ERROR`], not the 1 of the other commands, which
/// a remote command can also return.
///
/// The streams are not locked for the whole run: connecting copies ssh's stderr
/// to ours from another thread, which would wait forever for a lock held here.
/// Each write takes the lock for itself.
fn connect(host: &str) -> i32 {
    let store = match Store::from_process_env() {
        Ok(store) => store,
        Err(err) => {
            let _ = writeln!(
                io::stderr(),
                "bifrost: error: {}",
                sanitize_lines(&err.to_string())
            );
            return commands::OWN_ERROR;
        }
    };
    let known_hosts = home_dir(Platform::current(), &process_env)
        .map(|home| home.join(".ssh").join("known_hosts"));
    commands::connect(
        host,
        &store,
        resolve_ssh,
        known_hosts.as_deref(),
        &mut io::stderr(),
        io::stderr(),
    )
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
        // Handled by `connect` before this is reached: its exit status is not
        // an error of this kind.
        Action::Connect { .. } => Ok(()),
        Action::List => {
            let store = Store::from_process_env()?;
            commands::list(&store, out, err)
        }
    }
}
