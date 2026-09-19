//! The synchronous terminal interface.
//!
//! - [`terminal`]: raw mode, alternate screen and the panic hook.
//! - [`app`]: state and key handling, free of any I/O.
//! - [`startup`]: the store's load result as plain data for the home screen.
//! - [`ui`], [`theme`], [`wrap`]: rendering.
//! - [`event`]: the single-threaded event loop.

use std::io::{self, IsTerminal};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::{AppError, Result};
use crate::store::{Loaded, StoreError};
use crate::sysenv::Env;

pub mod app;
pub mod event;
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
/// `loaded` is the result of locating and loading the store. A failure is not
/// fatal here: the home screen explains it. `env` decides the theme (`NO_COLOR`).
pub fn run(loaded: std::result::Result<Loaded, StoreError>, env: Env<'_>) -> Result<()> {
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        return Err(AppError::NotATerminal);
    }

    let mut app = App::new(Startup::from_load(loaded));
    let theme = Theme::from_env(env);

    terminal::install_panic_hook();
    // Created before the ratatui terminal so that it is dropped after it.
    let _guard = TerminalGuard::enter(CrosstermOps)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    event::run_loop(&mut terminal, &mut app, &theme, event::next_crossterm_event)?;
    Ok(())
}
