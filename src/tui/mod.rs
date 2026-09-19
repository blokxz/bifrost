//! The synchronous terminal interface.
//!
//! - [`terminal`]: raw mode, alternate screen and the panic hook.
//! - [`app`]: state and key handling, free of any I/O apart from saving through
//!   [`persist`].
//! - [`startup`]: the store's load result as plain data for the first screen.
//! - [`list`], [`fuzzy`], [`input`]: the host list, the search and text editing.
//! - [`form`]: the add/edit form's state machine.
//! - [`clipboard`]: asking the terminal to copy text (OSC 52).
//! - [`ui`], [`theme`], [`wrap`]: rendering.
//! - [`event`]: the single-threaded event loop.

use std::io::{self, IsTerminal};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::{AppError, Result};
use crate::store::{Loaded, Store, StoreError};
use crate::sysenv::Env;

pub mod app;
pub mod clipboard;
pub mod event;
pub mod form;
pub mod fuzzy;
pub mod input;
pub mod list;
pub mod persist;
pub mod startup;
pub mod terminal;
pub mod theme;
pub mod ui;
pub mod wrap;

use app::App;
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

    terminal::install_panic_hook();
    // Created before the ratatui terminal so that it is dropped after it.
    let _guard = TerminalGuard::enter(CrosstermOps)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    event::run_loop(
        &mut terminal,
        &mut app,
        &theme,
        event::next_crossterm_event,
        |text| clipboard::copy_to_terminal(&mut io::stdout().lock(), text),
    )?;
    Ok(())
}
