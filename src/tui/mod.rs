//! The synchronous terminal interface.
//!
//! - [`terminal`]: raw mode, alternate screen and the panic hook.
//! - [`app`]: state and key handling, free of any I/O apart from saving through
//!   [`persist`].
//! - [`startup`]: the store's load result as plain data for the first screen.
//! - [`list`], [`fuzzy`], [`input`]: the host list, the search and text editing.
//! - [`keys`]: the keys screen's state.
//! - [`form`]: the add/edit form's state machine.
//! - [`clipboard`]: asking the terminal to copy text (OSC 52).
//! - [`effects`]: what the app asks the outside world to do, and how it is done.
//! - [`handover`]: giving the terminal to ssh and taking it back.
//! - [`ui`], [`theme`], [`wrap`]: rendering.
//! - [`event`]: the single-threaded event loop.

use std::io::{self, IsTerminal};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::{AppError, Result};
use crate::ssh::binary::{resolve_keygen, resolve_ssh, resolve_ssh_add};
use crate::ssh::interrupt;
use crate::store::{Loaded, Store, StoreError};
use crate::sysenv::{Env, Platform, home_dir};

pub mod app;
pub mod clipboard;
pub mod effects;
pub mod event;
pub mod form;
pub mod fuzzy;
pub mod handover;
pub mod input;
pub mod keys;
pub mod list;
pub mod persist;
pub mod sshconfig;
pub mod startup;
pub mod terminal;
pub mod theme;
pub mod ui;
pub mod wrap;

use app::App;
use effects::{Programs, System};
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use startup::Startup;
use terminal::{CrosstermOps, TerminalGuard};
use theme::Theme;

/// Opens the TUI and runs it until the user quits.
///
/// `loaded` is the result of locating and loading the store, with the store
/// itself so that changes can be saved. A failure is not fatal here: the first
/// screen explains it. `env` decides the theme (`NO_COLOR`).
pub fn run(loaded: std::result::Result<(Store, Loaded), StoreError>, env: Env<'_>) -> Result<()> {
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        return Err(AppError::NotATerminal);
    }

    let mut app = App::new(Startup::from_load(loaded));
    let theme = Theme::from_env(env);

    // Resolved once, before anything runs, to an absolute path. Not finding one
    // is not fatal: the list still works, and the action that needs it explains
    // what is missing.
    let programs = Programs {
        ssh: resolve_ssh(),
        keygen: resolve_keygen(),
        ssh_add: resolve_ssh_add(),
    };
    let home = home_dir(Platform::current(), env);
    // The file `ssh-keygen -R` edits when it is not told which: the only one
    // Bifrost offers to remove a key from.
    app.set_known_hosts_file(
        home.as_ref()
            .map(|home| home.join(".ssh").join("known_hosts")),
    );
    app.set_ssh_dir(home.as_ref().map(|home| home.join(".ssh")));
    // From here a SIGINT (which raw mode keeps the keyboard from producing, but
    // `kill -INT` and Ctrl-C during a connection do) no longer kills Bifrost.
    interrupt::arm()?;

    terminal::install_panic_hook();
    // Created before the ratatui terminal so that it is dropped after it.
    let mut guard = TerminalGuard::enter(CrosstermOps)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut system = System::new(&mut guard, programs, home.map(|home| home.join(".ssh")));

    event::run_loop(
        &mut terminal,
        &mut app,
        &theme,
        |timeout| {
            if interrupt::take() {
                // A SIGINT outside a connection is a request to quit, handled
                // like the Ctrl+C key: a form with unsaved changes still asks.
                return Ok(Some(Event::Key(KeyEvent::new(
                    KeyCode::Char('c'),
                    KeyModifiers::CONTROL,
                ))));
            }
            event::next_crossterm_event(timeout)
        },
        |request| system.execute(request),
    )?;
    Ok(())
}
