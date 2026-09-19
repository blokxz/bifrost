//! Application state and key handling.
//!
//! [`App`] holds everything that decides what is on screen and never touches the
//! terminal: key events go in, state changes come out. Saving goes through the
//! [`super::persist::HostStore`] it was given. Rendering (see [`super::ui`])
//! only reads the state, so all of this is unit-testable.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::form::{Form, FormField, FormMode, Outcome};
use super::input::TextInput;
use super::list::{self, ListState, Row};
use super::startup::{Library, Notice, Startup};
use crate::domain::validate::{self, Field};
use crate::domain::{Hosts, HostsError, ValidationError};
use crate::ssh::command::{Shell, build_args, display_command};

/// The screens of the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// The host list. When the hosts could not be loaded it shows the problem
    /// instead.
    List,
    Help,
    /// The warnings found when the hosts were loaded.
    Notices,
    /// Adding or editing a host.
    Form,
}

/// What the keys do on the list screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListMode {
    Browse,
    /// Typing a search; letters go into the search box.
    Search,
    /// Asking the user to type the host's name before deleting it.
    ConfirmDelete,
    /// Showing the ssh command for the selected host.
    Command,
}

/// The delete confirmation: the host's name has to be typed to go on.
#[derive(Debug)]
pub struct DeleteConfirm {
    pub name: String,
    pub input: TextInput,
    /// Set when Enter was pressed with something other than the name.
    pub mismatch: bool,
}

/// The ssh command being shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandView {
    pub host: String,
    /// The command for a person to read and paste: quoted, on one line.
    pub text: String,
}

/// How serious a [`Status`] message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Warning,
    Error,
}

/// A one-off message about what just happened. It stays until the next key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub kind: StatusKind,
    pub text: String,
}

/// What rendering learned about the screen, reported back after each draw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Metrics {
    /// How far the current text page can scroll.
    pub max_scroll: usize,
    /// How many host rows fit on the list screen.
    pub list_rows: usize,
    /// The first visible line of the form, kept so that the focused field is in view.
    pub form_scroll: usize,
}

/// One entry of the footer: a key (or keys) and what it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHint {
    pub keys: &'static str,
    pub label: &'static str,
}

/// One row of the help screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelpRow {
    pub keys: &'static str,
    pub description: &'static str,
}

/// A titled group of help rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelpSection {
    pub title: &'static str,
    pub rows: &'static [HelpRow],
}

const fn row(keys: &'static str, description: &'static str) -> HelpRow {
    HelpRow { keys, description }
}

const fn hint(keys: &'static str, label: &'static str) -> KeyHint {
    KeyHint { keys, label }
}

/// Every key Bifrost understands, for the help screen.
pub const HELP: &[HelpSection] = &[
    HelpSection {
        title: "Host list",
        rows: &[
            row("Up/Down j/k", "Move the selection"),
            row("Home/End", "Jump to the first or last host"),
            row("PgUp/PgDn", "Move by a screenful"),
            row("/", "Search the hosts"),
            row("a", "Add a host"),
            row("e", "Edit the selected host"),
            row(
                "d",
                "Delete the selected host, after typing its name to confirm",
            ),
            row("f", "Mark or unmark the selected host as a favorite"),
            row(
                "c",
                "Show the ssh command for the selected host and ask the terminal to copy it",
            ),
            row("w", "Read the warnings found when the hosts were loaded"),
            row("?", "Open this help, or close it"),
            row("Esc", "Clear the search, or quit when there is none"),
            row("q", "Quit"),
        ],
    },
    HelpSection {
        title: "While searching",
        rows: &[
            row(
                "Type",
                "Filter by name, hostname or tag. Letters can be spread out: dbp finds db-prod",
            ),
            row("Up/Down", "Move through the results"),
            row("Enter", "Keep the filter and go back to the list keys"),
            row("Esc", "Clear the search"),
        ],
    },
    HelpSection {
        title: "Deleting a host",
        rows: &[
            row("Type", "The host's name, exactly, to confirm"),
            row("Enter", "Delete it. It cannot be undone"),
            row("Esc", "Cancel"),
        ],
    },
    HelpSection {
        title: "The ssh command",
        rows: &[row("Any key", "Close the command")],
    },
    HelpSection {
        title: "Adding or editing a host",
        rows: &[
            row(
                "Tab/Shift+Tab",
                "Next or previous field. Down and Up work too. A field is checked when you leave it",
            ),
            row(
                "Enter",
                "Next field. On Jump host it opens the list; on Advanced it shows or hides the section",
            ),
            row("Space", "Turn Forward agent on or off"),
            row(
                "Ctrl+S",
                "Save the host. Not possible while a field has an error",
            ),
            row("Esc", "Cancel. Asks first if there are unsaved changes"),
            row("y/n", "Answer the question about discarding changes"),
        ],
    },
    HelpSection {
        title: "Choosing a jump host",
        rows: &[
            row("Up/Down j/k", "Move through the saved hosts"),
            row("Enter", "Choose the highlighted one, or (none)"),
            row("Esc", "Close the list without choosing"),
        ],
    },
    HelpSection {
        title: "In this help and in the warnings",
        rows: &[row("Up/Down j/k", "Scroll"), row("Esc", "Close")],
    },
    HelpSection {
        title: "Anywhere",
        rows: &[row("Ctrl+C", "Quit")],
    },
];

/// The state of the TUI.
#[derive(Debug)]
pub struct App {
    screen: Screen,
    mode: ListMode,
    library: Option<Library>,
    notices: Vec<Notice>,
    list: ListState,
    form: Option<Form>,
    delete: Option<DeleteConfirm>,
    command: Option<CommandView>,
    /// Text to ask the terminal to copy; taken by the event loop.
    copy_request: Option<String>,
    status: Option<Status>,
    help_scroll: usize,
    notices_scroll: usize,
    /// How far the current text page can scroll, as last reported by rendering.
    max_scroll: usize,
    quit: bool,
}

impl App {
    pub fn new(startup: Startup) -> Self {
        let mut app = App {
            screen: Screen::List,
            mode: ListMode::Browse,
            library: startup.library,
            notices: startup.notices,
            list: ListState::default(),
            form: None,
            delete: None,
            command: None,
            copy_request: None,
            status: None,
            help_scroll: 0,
            notices_scroll: 0,
            max_scroll: 0,
            quit: false,
        };
        app.normalize_selection();
        app
    }

    pub fn screen(&self) -> Screen {
        self.screen
    }

    pub fn mode(&self) -> ListMode {
        self.mode
    }

    /// The hosts, or `None` when they could not be loaded.
    pub fn hosts(&self) -> Option<&Hosts> {
        self.library.as_ref().map(|library| &library.hosts)
    }

    pub fn notices(&self) -> &[Notice] {
        &self.notices
    }

    pub fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    pub fn list(&self) -> &ListState {
        &self.list
    }

    /// The add/edit form, while it is open.
    pub fn form(&self) -> Option<&Form> {
        self.form.as_ref()
    }

    /// The delete confirmation, while it is showing.
    pub fn delete(&self) -> Option<&DeleteConfirm> {
        self.delete.as_ref()
    }

    /// The ssh command, while it is showing.
    pub fn command(&self) -> Option<&CommandView> {
        self.command.as_ref()
    }

    /// The text to ask the terminal to copy, if a copy was just requested. It is
    /// returned once: the caller sends it to the terminal (see
    /// [`super::clipboard`]).
    pub fn take_copy_request(&mut self) -> Option<String> {
        self.copy_request.take()
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// The rows of the host list for the current search.
    pub fn rows(&self) -> Vec<Row> {
        self.hosts()
            .map(|hosts| list::rows(hosts, self.list.query.value()))
            .unwrap_or_default()
    }

    /// How many lines the current text page is scrolled down.
    pub fn scroll(&self) -> usize {
        match self.screen {
            Screen::Help => self.help_scroll,
            Screen::Notices | Screen::List | Screen::Form => self.notices_scroll,
        }
    }

    /// The keys to list in the footer of the current screen.
    pub fn footer_hints(&self) -> Vec<KeyHint> {
        match self.screen {
            Screen::Help => vec![
                hint("Up/Down j/k", "scroll"),
                hint("?/Esc", "close help"),
                hint("q", "quit"),
            ],
            Screen::Notices => vec![
                hint("Up/Down j/k", "scroll"),
                hint("w/Esc", "close"),
                hint("q", "quit"),
            ],
            Screen::Form => match self.form.as_ref().map(|form| (form.mode(), form.focus())) {
                Some((FormMode::PickJump(_), _)) => vec![
                    hint("Up/Down j/k", "move"),
                    hint("Enter", "choose"),
                    hint("Esc", "close"),
                ],
                Some((FormMode::ConfirmDiscard, _)) => {
                    vec![hint("y", "discard"), hint("n", "keep editing")]
                }
                other => {
                    let mut hints = vec![hint("Tab/Shift+Tab", "move"), hint("Ctrl+S", "save")];
                    match other.map(|(_, focus)| focus) {
                        Some(FormField::ProxyJump) => hints.push(hint("Enter", "choose")),
                        Some(FormField::Advanced) => hints.push(hint("Enter", "show/hide")),
                        Some(FormField::ForwardAgent) => hints.push(hint("Space", "toggle")),
                        _ => {}
                    }
                    hints.push(hint("Esc", "cancel"));
                    hints
                }
            },
            Screen::List if self.library.is_none() => vec![
                hint("Up/Down j/k", "scroll"),
                hint("?", "help"),
                hint("q/Esc", "quit"),
            ],
            Screen::List => match self.mode {
                ListMode::ConfirmDelete => vec![
                    hint("Type", "the host name"),
                    hint("Enter", "delete"),
                    hint("Esc", "cancel"),
                ],
                ListMode::Command => vec![hint("Any key", "close")],
                ListMode::Search => vec![
                    hint("Type", "to filter"),
                    hint("Up/Down", "results"),
                    hint("Enter", "keep filter"),
                    hint("Esc", "clear"),
                ],
                ListMode::Browse => {
                    let mut hints = vec![
                        hint("Up/Down j/k", "move"),
                        hint("/", "search"),
                        hint("a", "add"),
                        hint("e", "edit"),
                        hint("d", "delete"),
                        hint("f", "favorite"),
                        hint("c", "copy"),
                    ];
                    if !self.notices.is_empty() {
                        hints.push(hint("w", "warnings"));
                    }
                    hints.push(hint("?", "help"));
                    if self.list.query.is_empty() {
                        hints.push(hint("q/Esc", "quit"));
                    } else {
                        hints.push(hint("Esc", "clear search"));
                        hints.push(hint("q", "quit"));
                    }
                    hints
                }
            },
        }
    }

    /// Adopts what rendering learned about the screen.
    ///
    /// Rendering knows how much fits, so it reports after each draw; scrolling
    /// never goes past the limit, and a shrinking limit (for example after a
    /// resize) pulls the position back.
    pub fn apply_metrics(&mut self, metrics: Metrics) {
        self.max_scroll = metrics.max_scroll;
        let max = self.max_scroll;
        if let Some(scroll) = self.scroll_mut() {
            *scroll = (*scroll).min(max);
        }
        if let Some(form) = &mut self.form {
            form.scroll = metrics.form_scroll;
        }

        if let Some(library) = &self.library {
            let rows = list::rows(&library.hosts, self.list.query.value());
            self.list
                .set_visible(&library.hosts, &rows, metrics.list_rows);
        }
    }

    /// Applies a key press. Callers must pass only key presses, not releases.
    pub fn handle_key(&mut self, key: KeyEvent) {
        self.status = None;
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            // A form with unsaved changes asks before Ctrl+C throws them away.
            self.quit = match (self.screen, self.form.as_mut()) {
                (Screen::Form, Some(form)) => form.ctrl_c(),
                _ => true,
            };
            return;
        }
        match self.screen {
            Screen::List => self.list_key(key),
            Screen::Help => self.help_key(key),
            Screen::Notices => self.notices_key(key),
            Screen::Form => self.form_key(key),
        }
    }

    // ---- shared helpers --------------------------------------------------

    /// Keys with Ctrl or Alt belong to the terminal or the system.
    fn is_plain(key: KeyEvent) -> bool {
        !key.modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    }

    fn set_status(&mut self, kind: StatusKind, text: impl Into<String>) {
        self.status = Some(Status {
            kind,
            text: text.into(),
        });
    }

    /// The scroll position of the current text page. The form has none: it
    /// keeps its own focused field in view.
    fn scroll_mut(&mut self) -> Option<&mut usize> {
        match self.screen {
            Screen::Help => Some(&mut self.help_scroll),
            Screen::Notices | Screen::List => Some(&mut self.notices_scroll),
            Screen::Form => None,
        }
    }

    /// Scrolls a text page. Returns whether `key` was a scrolling key.
    fn scroll_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(scroll) = self.scroll_mut() {
                    *scroll = scroll.saturating_sub(1);
                }
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = self.max_scroll;
                if let Some(scroll) = self.scroll_mut() {
                    *scroll = (*scroll + 1).min(max);
                }
                true
            }
            _ => false,
        }
    }

    fn open(&mut self, screen: Screen) {
        self.screen = screen;
        match screen {
            Screen::Help => self.help_scroll = 0,
            Screen::Notices => self.notices_scroll = 0,
            Screen::List | Screen::Form => {}
        }
        // The limit belongs to the screen that was drawn; until the new one is
        // drawn, stay put rather than scroll by a stale amount.
        self.max_scroll = 0;
    }

    fn normalize_selection(&mut self) {
        if let Some(library) = &self.library {
            let rows = list::rows(&library.hosts, self.list.query.value());
            self.list.normalize(&library.hosts, &rows);
        }
    }

    // ---- help and notices ------------------------------------------------

    fn help_key(&mut self, key: KeyEvent) {
        if !Self::is_plain(key) {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') | KeyCode::Esc => self.open(Screen::List),
            _ => {
                self.scroll_key(key);
            }
        }
    }

    fn notices_key(&mut self, key: KeyEvent) {
        if !Self::is_plain(key) {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('w') | KeyCode::Esc => self.open(Screen::List),
            _ => {
                self.scroll_key(key);
            }
        }
    }

    // ---- the list --------------------------------------------------------

    fn list_key(&mut self, key: KeyEvent) {
        if self.library.is_none() {
            self.unavailable_key(key);
            return;
        }
        match self.mode {
            ListMode::Browse => self.browse_key(key),
            ListMode::Search => self.search_key(key),
            ListMode::ConfirmDelete => self.delete_key(key),
            ListMode::Command => self.command_key(),
        }
    }

    /// The hosts could not be loaded: the screen only explains why.
    fn unavailable_key(&mut self, key: KeyEvent) {
        if !Self::is_plain(key) {
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('?') => self.open(Screen::Help),
            KeyCode::Char('/' | 'a' | 'e' | 'd' | 'f' | 'c') => self.set_status(
                StatusKind::Info,
                "Hosts cannot be shown or changed until the problem above is fixed.",
            ),
            _ => {
                self.scroll_key(key);
            }
        }
    }

    fn move_selection(&mut self, movement: impl FnOnce(&mut ListState, &Hosts, &[Row])) {
        if let Some(library) = &self.library {
            let rows = list::rows(&library.hosts, self.list.query.value());
            movement(&mut self.list, &library.hosts, &rows);
        }
    }

    /// Moves the selection for a navigation key. Returns whether `key` was one.
    /// `with_letters` is off while typing a search, where `j`, `k`, Home and End
    /// belong to the text.
    fn navigation_key(&mut self, key: KeyEvent, with_letters: bool) -> bool {
        match key.code {
            KeyCode::Up => self.move_selection(|list, hosts, rows| list.move_by(hosts, rows, -1)),
            KeyCode::Down => self.move_selection(|list, hosts, rows| list.move_by(hosts, rows, 1)),
            KeyCode::Char('k') if with_letters => {
                self.move_selection(|list, hosts, rows| list.move_by(hosts, rows, -1));
            }
            KeyCode::Char('j') if with_letters => {
                self.move_selection(|list, hosts, rows| list.move_by(hosts, rows, 1));
            }
            KeyCode::PageUp => {
                self.move_selection(|list, hosts, rows| list.page(hosts, rows, false));
            }
            KeyCode::PageDown => {
                self.move_selection(|list, hosts, rows| list.page(hosts, rows, true));
            }
            KeyCode::Home if with_letters => {
                self.move_selection(|list, hosts, rows| list.select_first(hosts, rows));
            }
            KeyCode::End if with_letters => {
                self.move_selection(|list, hosts, rows| list.select_last(hosts, rows));
            }
            _ => return false,
        }
        true
    }

    fn browse_key(&mut self, key: KeyEvent) {
        if !Self::is_plain(key) {
            return;
        }
        if self.navigation_key(key, true) {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Esc => {
                if self.list.query.is_empty() {
                    self.quit = true;
                } else {
                    self.clear_search();
                }
            }
            KeyCode::Char('?') => self.open(Screen::Help),
            KeyCode::Char('w') => {
                if self.notices.is_empty() {
                    self.set_status(StatusKind::Info, "There are no warnings.");
                } else {
                    self.open(Screen::Notices);
                }
            }
            KeyCode::Char('/') => self.mode = ListMode::Search,
            KeyCode::Char('a') => self.open_form(Form::add()),
            KeyCode::Char('e') => self.edit_selected(),
            KeyCode::Char('d') => self.start_delete(),
            KeyCode::Char('f') => self.toggle_favorite(),
            KeyCode::Char('c') => self.show_command(),
            _ => {}
        }
    }

    fn clear_search(&mut self) {
        self.list.query.clear();
        self.mode = ListMode::Browse;
        self.normalize_selection();
    }

    fn search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.clear_search(),
            KeyCode::Enter => self.mode = ListMode::Browse,
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown
                if Self::is_plain(key) =>
            {
                self.navigation_key(key, false);
            }
            _ => {
                if self.list.query.handle_key(key) {
                    // A new query: start from its best match.
                    if let Some(library) = &self.library {
                        let rows = list::rows(&library.hosts, self.list.query.value());
                        self.list.select_first(&library.hosts, &rows);
                    }
                }
            }
        }
    }

    // ---- deleting --------------------------------------------------------

    fn start_delete(&mut self) {
        let Some(hosts) = self.hosts() else {
            return;
        };
        let Some(name) = self.list.selected.clone() else {
            self.set_status(StatusKind::Info, "There is no host to delete.");
            return;
        };
        // Refuse before asking anything: typing the name would lead nowhere.
        let dependents = hosts.dependents_of(&name);
        if !dependents.is_empty() {
            let refusal = HostsError::InUse { name, dependents };
            self.set_status(StatusKind::Error, refusal.to_string());
            return;
        }
        self.delete = Some(DeleteConfirm {
            name,
            input: TextInput::default(),
            mismatch: false,
        });
        self.mode = ListMode::ConfirmDelete;
    }

    fn cancel_delete(&mut self) {
        self.delete = None;
        self.mode = ListMode::Browse;
    }

    fn delete_key(&mut self, key: KeyEvent) {
        let Some(confirm) = self.delete.as_mut() else {
            self.mode = ListMode::Browse;
            return;
        };
        match key.code {
            KeyCode::Esc => self.cancel_delete(),
            KeyCode::Enter => {
                // The name must match exactly, case included.
                if confirm.input.value() == confirm.name {
                    self.finish_delete();
                } else {
                    confirm.mismatch = true;
                }
            }
            _ => {
                if confirm.input.handle_key(key) {
                    confirm.mismatch = false;
                }
            }
        }
    }

    /// Deletes the confirmed host and saves. On failure the host stays.
    fn finish_delete(&mut self) {
        let Some(confirm) = self.delete.take() else {
            return;
        };
        self.mode = ListMode::Browse;
        let name = confirm.name;

        let Some(hosts) = self.hosts() else {
            return;
        };
        let position = self.list.position(hosts, &self.rows());
        let mut candidate = hosts.clone();
        // Still refused if another host has come to depend on it meanwhile.
        if let Err(refusal) = candidate.remove(&name) {
            self.set_status(StatusKind::Error, refusal.to_string());
            return;
        }
        match self.commit(candidate) {
            Ok(()) => {
                // Select whatever moved into the deleted host's place.
                if let Some(library) = &self.library {
                    let rows = list::rows(&library.hosts, self.list.query.value());
                    self.list
                        .select(&library.hosts, &rows, position.unwrap_or(0));
                }
                self.set_status(StatusKind::Info, format!("Deleted host '{name}'."));
            }
            Err(message) => self.set_status(StatusKind::Error, message),
        }
    }

    // ---- the ssh command -------------------------------------------------

    /// Shows the ssh command for the selected host and asks the terminal to
    /// copy it. The command on screen is the part that always works.
    fn show_command(&mut self) {
        let Some(hosts) = self.hosts() else {
            return;
        };
        let Some(host) = self.list.selected.as_deref().and_then(|n| hosts.get(n)) else {
            self.set_status(StatusKind::Info, "There is no host to show a command for.");
            return;
        };
        let shown =
            build_args(host, hosts).and_then(|args| display_command(&args, Shell::current()));
        match shown {
            Ok(command) => {
                let text = command.as_str().to_string();
                self.command = Some(CommandView {
                    host: host.name.clone(),
                    text: text.clone(),
                });
                self.copy_request = Some(text);
                self.mode = ListMode::Command;
            }
            Err(err) => self.set_status(StatusKind::Error, err.to_string()),
        }
    }

    /// Any key closes the command (Ctrl+C is handled before this).
    fn command_key(&mut self) {
        self.command = None;
        self.mode = ListMode::Browse;
    }

    // ---- the form --------------------------------------------------------

    fn open_form(&mut self, form: Form) {
        self.form = Some(form);
        self.screen = Screen::Form;
        self.max_scroll = 0;
    }

    fn close_form(&mut self) {
        self.form = None;
        self.screen = Screen::List;
        self.max_scroll = 0;
    }

    fn edit_selected(&mut self) {
        let host = self
            .list
            .selected
            .as_deref()
            .and_then(|name| self.hosts()?.get(name))
            .cloned();
        match host {
            Some(host) => self.open_form(Form::edit(&host)),
            None => self.set_status(
                StatusKind::Info,
                "There is no host to edit. Press a to add one.",
            ),
        }
    }

    fn form_key(&mut self, key: KeyEvent) {
        let (Some(form), Some(library)) = (self.form.as_mut(), self.library.as_ref()) else {
            return;
        };
        match form.handle_key(key, &library.hosts) {
            Outcome::Stay => {}
            Outcome::Close => self.close_form(),
            Outcome::Save => self.save_form(),
        }
    }

    /// Checks the form, saves the host, and on success closes the form. Any
    /// problem leaves the form open with everything the user typed.
    fn save_form(&mut self) {
        let (Some(form), Some(library)) = (self.form.as_mut(), self.library.as_ref()) else {
            return;
        };
        let host = match form.build(&library.hosts) {
            Ok(host) => host,
            Err(_) => {
                form.set_notice("Fix the fields marked with an error before saving.");
                return;
            }
        };

        // The whole collection is validated again, which also catches what one
        // field cannot know: a jump host that no longer exists, a chain that
        // has become too long.
        let mut candidate = library.hosts.clone();
        let editing = form.original_name().map(str::to_string);
        let checked = match &editing {
            Some(original) => candidate
                .update(original, host.clone())
                .map_err(|err| match err {
                    HostsError::Invalid(problem) => problem,
                    other => ValidationError::new(Field::Name, other.to_string()),
                }),
            None => candidate.add(host.clone()),
        };
        if let Err(problem) = checked {
            form.show_error(
                FormField::from_validation(problem.field()),
                problem.message(),
            );
            form.set_notice("Fix the field marked with an error before saving.");
            return;
        }

        match self.commit(candidate) {
            Ok(()) => self.finish_save(&host, editing.is_some()),
            Err(message) => {
                if let Some(form) = self.form.as_mut() {
                    form.set_notice(message);
                }
            }
        }
    }

    /// Closes the form after a successful save, shows the host in the list and
    /// says what happened, including a warning if its key file is missing.
    fn finish_save(&mut self, host: &crate::domain::Host, edited: bool) {
        let warning = self
            .library
            .as_ref()
            .and_then(|library| validate::identity_file_warning(host, library.store.home()));

        self.close_form();
        // The saved host must be visible, whatever the search was.
        self.list.query.clear();
        self.mode = ListMode::Browse;
        self.list.selected = Some(host.name.clone());
        self.normalize_selection();

        let verb = if edited { "Updated" } else { "Added" };
        match warning {
            Some(warning) => self.set_status(
                StatusKind::Warning,
                format!("{verb} host '{}'. {}", host.name, warning.message()),
            ),
            None => self.set_status(StatusKind::Info, format!("{verb} host '{}'.", host.name)),
        }
    }

    // ---- changing hosts --------------------------------------------------

    /// Saves `candidate` and, only if that worked, makes it the current hosts.
    /// On failure the hosts stay as they were, so what is on screen always
    /// matches what is on disk.
    fn commit(&mut self, candidate: Hosts) -> Result<(), String> {
        let Some(library) = &mut self.library else {
            return Err("There are no hosts to save.".to_string());
        };
        library
            .store
            .save(&candidate)
            .map_err(|err| format!("Could not save your changes: {err}"))?;
        library.hosts = candidate;
        Ok(())
    }

    fn toggle_favorite(&mut self) {
        let Some(name) = self.list.selected.clone() else {
            return;
        };
        let Some(hosts) = self.hosts() else {
            return;
        };
        let Some(mut host) = hosts.get(&name).cloned() else {
            return;
        };
        host.favorite = !host.favorite;
        let now_favorite = host.favorite;

        let mut candidate = hosts.clone();
        if let Err(err) = candidate.update(&name, host) {
            self.set_status(StatusKind::Error, err.to_string());
            return;
        }
        match self.commit(candidate) {
            Ok(()) => {
                self.normalize_selection();
                let text = if now_favorite {
                    format!("'{name}' is now a favorite.")
                } else {
                    format!("'{name}' is no longer a favorite.")
                };
                self.set_status(StatusKind::Info, text);
            }
            Err(message) => self.set_status(StatusKind::Error, message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Host;
    use crate::tui::persist::testing::FakeStore;
    use ratatui::crossterm::event::KeyEventKind;

    fn host(name: &str, favorite: bool) -> Host {
        let mut host = Host::new(name, format!("{name}.example.com"));
        host.favorite = favorite;
        host
    }

    fn hosts(list: Vec<Host>) -> Hosts {
        Hosts::from_vec(list).unwrap()
    }

    fn sample() -> Hosts {
        hosts(vec![
            host("web", false),
            host("db", false),
            host("backup", true),
        ])
    }

    fn app_with(hosts: Hosts, notices: Vec<Notice>) -> (App, FakeStore) {
        let store = FakeStore::default();
        let app = App::new(Startup::loaded(hosts, store.clone(), notices));
        (app, store)
    }

    fn app() -> App {
        app_with(sample(), Vec::new()).0
    }

    fn unavailable() -> App {
        App::new(Startup {
            library: None,
            notices: vec![Notice::error("Bifrost could not read your saved hosts.")],
        })
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ch(c: char) -> KeyEvent {
        press(KeyCode::Char(c))
    }

    fn with(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_key(ch(c));
        }
    }

    fn selected(app: &App) -> Option<&str> {
        app.list().selected.as_deref()
    }

    fn listed(app: &App) -> Vec<String> {
        let hosts = app.hosts().unwrap();
        app.rows()
            .iter()
            .map(|row| hosts.as_slice()[row.index].name.clone())
            .collect()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    // ---- start and quit --------------------------------------------------

    #[test]
    fn starts_on_the_list_with_the_first_host_selected() {
        let app = app();
        assert_eq!(app.screen(), Screen::List);
        assert_eq!(app.mode(), ListMode::Browse);
        assert!(!app.should_quit());
        assert_eq!(selected(&app), Some("backup"), "favorites first");
    }

    #[test]
    fn q_and_esc_quit_from_the_list() {
        for key in [ch('q'), press(KeyCode::Esc)] {
            let mut app = app();
            app.handle_key(key);
            assert!(app.should_quit(), "{key:?}");
        }
    }

    #[test]
    fn ctrl_c_quits_from_every_screen_and_mode() {
        for setup in ["", "?", "/", "w"] {
            let (mut app, _) = app_with(sample(), vec![Notice::warning("careful")]);
            type_text(&mut app, setup);
            app.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
            assert!(app.should_quit(), "after {setup:?}");
        }
        let mut app = unavailable();
        app.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit());
    }

    #[test]
    fn other_ctrl_and_alt_combinations_are_ignored() {
        for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            for code in [
                KeyCode::Char('q'),
                KeyCode::Char('?'),
                KeyCode::Char('f'),
                KeyCode::Char('/'),
                KeyCode::Esc,
            ] {
                let (mut app, store) = app_with(sample(), Vec::new());
                app.handle_key(with(code, modifiers));
                assert!(!app.should_quit(), "{code:?} with {modifiers:?}");
                assert_eq!(app.screen(), Screen::List);
                assert_eq!(app.mode(), ListMode::Browse);
                assert_eq!(store.save_count(), 0);
            }
        }
    }

    #[test]
    fn unknown_keys_change_nothing() {
        let mut app = app();
        for key in [
            ch('x'),
            press(KeyCode::Enter),
            press(KeyCode::Tab),
            press(KeyCode::F(5)),
        ] {
            app.handle_key(key);
        }
        assert_eq!(app.screen(), Screen::List);
        assert_eq!(app.mode(), ListMode::Browse);
        assert!(!app.should_quit());
    }

    #[test]
    fn key_kind_does_not_matter_to_the_state() {
        // Filtering out releases is the event loop's job, not the state's.
        let mut app = app();
        app.handle_key(KeyEvent::new_with_kind(
            KeyCode::Char('?'),
            KeyModifiers::NONE,
            KeyEventKind::Press,
        ));
        assert_eq!(app.screen(), Screen::Help);
    }

    // ---- selection -------------------------------------------------------

    #[test]
    fn arrows_and_j_k_move_the_selection() {
        let mut app = app();
        assert_eq!(selected(&app), Some("backup"));
        app.handle_key(ch('j'));
        assert_eq!(selected(&app), Some("db"));
        app.handle_key(press(KeyCode::Down));
        assert_eq!(selected(&app), Some("web"));
        app.handle_key(press(KeyCode::Down));
        assert_eq!(selected(&app), Some("web"), "stops at the end");
        app.handle_key(ch('k'));
        app.handle_key(press(KeyCode::Up));
        assert_eq!(selected(&app), Some("backup"));
        app.handle_key(press(KeyCode::Up));
        assert_eq!(selected(&app), Some("backup"), "stops at the start");
    }

    #[test]
    fn home_and_end_jump_to_the_ends() {
        let mut app = app();
        app.handle_key(press(KeyCode::End));
        assert_eq!(selected(&app), Some("web"));
        app.handle_key(press(KeyCode::Home));
        assert_eq!(selected(&app), Some("backup"));
    }

    #[test]
    fn page_keys_move_by_the_reported_number_of_rows() {
        let many = hosts(
            (0..30)
                .map(|n| host(&format!("host-{n:02}"), false))
                .collect(),
        );
        let (mut app, _) = app_with(many, Vec::new());
        app.apply_metrics(Metrics {
            max_scroll: 0,
            list_rows: 8,
            ..Metrics::default()
        });
        app.handle_key(press(KeyCode::PageDown));
        assert_eq!(selected(&app), Some("host-08"));
        app.handle_key(press(KeyCode::PageDown));
        assert_eq!(selected(&app), Some("host-16"));
        app.handle_key(press(KeyCode::PageUp));
        assert_eq!(selected(&app), Some("host-08"));
    }

    #[test]
    fn an_empty_list_has_no_selection_and_ignores_movement() {
        let (mut app, store) = app_with(Hosts::new(), Vec::new());
        assert_eq!(selected(&app), None);
        for key in [press(KeyCode::Down), press(KeyCode::End), ch('f')] {
            app.handle_key(key);
        }
        assert_eq!(selected(&app), None);
        assert_eq!(store.save_count(), 0);
    }

    // ---- search ----------------------------------------------------------

    #[test]
    fn slash_starts_a_search_and_typing_filters_live() {
        let mut app = app();
        app.handle_key(ch('/'));
        assert_eq!(app.mode(), ListMode::Search);
        type_text(&mut app, "d");
        assert_eq!(listed(&app), names(&["db"]), "only db has a d");
        type_text(&mut app, "b");
        assert_eq!(listed(&app), names(&["db"]));
        app.handle_key(press(KeyCode::Backspace));
        app.handle_key(press(KeyCode::Backspace));
        type_text(&mut app, "b");
        assert_eq!(listed(&app).len(), 3, "every host has a b somewhere");
        assert_eq!(listed(&app)[0], "backup", "a prefix match ranks first");
        assert_eq!(selected(&app), Some("backup"), "the best match is selected");
        type_text(&mut app, "z");
        assert!(listed(&app).is_empty(), "no host has a z after its b");
    }

    #[test]
    fn letters_typed_while_searching_are_not_commands() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "qwf?j/");
        assert!(!app.should_quit());
        assert_eq!(app.screen(), Screen::List);
        assert_eq!(app.list().query.value(), "qwf?j/");
    }

    #[test]
    fn a_search_that_matches_nothing_lists_nothing() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "zzz");
        assert!(listed(&app).is_empty());
        assert_eq!(selected(&app), None);
    }

    #[test]
    fn backspace_widens_the_search_again() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "web");
        assert_eq!(listed(&app), names(&["web"]));
        for _ in 0..3 {
            app.handle_key(press(KeyCode::Backspace));
        }
        assert_eq!(listed(&app).len(), 3);
    }

    #[test]
    fn arrows_move_through_the_results_while_searching() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "b");
        let results = listed(&app);
        assert_eq!(results.len(), 3);
        assert_eq!(selected(&app), Some(results[0].as_str()));
        app.handle_key(press(KeyCode::Down));
        assert_eq!(selected(&app), Some(results[1].as_str()));
        app.handle_key(press(KeyCode::Up));
        assert_eq!(selected(&app), Some(results[0].as_str()));
        assert_eq!(app.list().query.value(), "b", "j and k stay typing keys");
    }

    #[test]
    fn enter_keeps_the_filter_and_returns_to_the_list_keys() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "web");
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.mode(), ListMode::Browse);
        assert_eq!(listed(&app), names(&["web"]));
        // The list keys work on the filtered list again.
        app.handle_key(ch('f'));
        assert!(app.hosts().unwrap().get("web").unwrap().favorite);
    }

    #[test]
    fn esc_while_searching_clears_the_search() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "web");
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.mode(), ListMode::Browse);
        assert!(app.list().query.is_empty());
        assert_eq!(listed(&app).len(), 3);
        assert!(!app.should_quit());
    }

    #[test]
    fn esc_with_a_kept_filter_clears_it_and_only_then_quits() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "web");
        app.handle_key(press(KeyCode::Enter));

        app.handle_key(press(KeyCode::Esc));
        assert!(app.list().query.is_empty());
        assert!(!app.should_quit());

        app.handle_key(press(KeyCode::Esc));
        assert!(app.should_quit());
    }

    #[test]
    fn clearing_a_search_keeps_the_selected_host_selected() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "web");
        assert_eq!(selected(&app), Some("web"));
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(selected(&app), Some("web"));
    }

    // ---- favorites -------------------------------------------------------

    #[test]
    fn f_toggles_the_favorite_flag_and_saves() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('j'));
        assert_eq!(selected(&app), Some("db"));

        app.handle_key(ch('f'));

        assert!(app.hosts().unwrap().get("db").unwrap().favorite);
        assert_eq!(store.save_count(), 1);
        assert!(store.last_saved().unwrap().get("db").unwrap().favorite);
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert!(status.text.contains("'db' is now a favorite"), "{status:?}");
    }

    #[test]
    fn f_again_removes_the_favorite() {
        let (mut app, store) = app_with(sample(), Vec::new());
        assert_eq!(selected(&app), Some("backup"));
        app.handle_key(ch('f'));
        assert!(!app.hosts().unwrap().get("backup").unwrap().favorite);
        assert_eq!(store.save_count(), 1);
        assert!(app.status().unwrap().text.contains("no longer a favorite"));
    }

    #[test]
    fn the_selection_follows_a_host_that_becomes_a_favorite() {
        let mut app = app();
        app.handle_key(press(KeyCode::End));
        assert_eq!(selected(&app), Some("web"));
        app.handle_key(ch('f'));
        assert_eq!(selected(&app), Some("web"));
        assert_eq!(listed(&app)[..2], names(&["backup", "web"]));
    }

    #[test]
    fn a_failed_save_leaves_the_hosts_unchanged_and_says_why() {
        let (mut app, store) = app_with(sample(), Vec::new());
        store.fail_saves(true);

        app.handle_key(ch('j'));
        app.handle_key(ch('f'));

        assert!(!app.hosts().unwrap().get("db").unwrap().favorite);
        assert_eq!(store.save_count(), 0);
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert!(
            status.text.contains("Could not save your changes"),
            "{status:?}"
        );
        assert!(status.text.contains("disk is full"), "{status:?}");

        // Once the problem is gone, the same key works.
        store.fail_saves(false);
        app.handle_key(ch('f'));
        assert!(app.hosts().unwrap().get("db").unwrap().favorite);
    }

    #[test]
    fn messages_last_until_the_next_key() {
        let mut app = app();
        app.handle_key(ch('f'));
        assert!(app.status().is_some());
        app.handle_key(press(KeyCode::Down));
        assert!(app.status().is_none());
    }

    // ---- help and notices ------------------------------------------------

    #[test]
    fn question_mark_opens_and_closes_help() {
        let mut app = app();
        app.handle_key(ch('?'));
        assert_eq!(app.screen(), Screen::Help);
        app.handle_key(ch('?'));
        assert_eq!(app.screen(), Screen::List);
        assert!(!app.should_quit());
    }

    #[test]
    fn shift_question_mark_opens_help() {
        // Many terminals report '?' together with the Shift modifier.
        let mut app = app();
        app.handle_key(with(KeyCode::Char('?'), KeyModifiers::SHIFT));
        assert_eq!(app.screen(), Screen::Help);
    }

    #[test]
    fn esc_closes_help_without_quitting_and_q_quits_from_it() {
        let mut app = app();
        app.handle_key(ch('?'));
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::List);
        assert!(!app.should_quit());

        app.handle_key(ch('?'));
        app.handle_key(ch('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn help_scrolls_within_the_limit_rendering_reports() {
        let mut app = app();
        app.handle_key(ch('?'));
        app.handle_key(ch('j'));
        assert_eq!(
            app.scroll(),
            0,
            "nothing scrolls until rendering reports a limit"
        );

        app.apply_metrics(Metrics {
            max_scroll: 3,
            list_rows: 0,
            ..Metrics::default()
        });
        for key in [ch('j'), press(KeyCode::Down), ch('j'), ch('j')] {
            app.handle_key(key);
        }
        assert_eq!(app.scroll(), 3, "stops at the limit");
        app.handle_key(ch('k'));
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.scroll(), 1);
        app.handle_key(ch('k'));
        app.handle_key(ch('k'));
        assert_eq!(app.scroll(), 0, "stops at the top");
    }

    #[test]
    fn a_smaller_limit_pulls_the_scroll_position_back() {
        let mut app = app();
        app.handle_key(ch('?'));
        app.apply_metrics(Metrics {
            max_scroll: 10,
            list_rows: 0,
            ..Metrics::default()
        });
        for _ in 0..8 {
            app.handle_key(ch('j'));
        }
        assert_eq!(app.scroll(), 8);
        app.apply_metrics(Metrics {
            max_scroll: 5,
            list_rows: 0,
            ..Metrics::default()
        });
        assert_eq!(app.scroll(), 5);
    }

    #[test]
    fn help_opens_at_the_top_each_time() {
        let mut app = app();
        app.handle_key(ch('?'));
        app.apply_metrics(Metrics {
            max_scroll: 10,
            list_rows: 0,
            ..Metrics::default()
        });
        app.handle_key(ch('j'));
        app.handle_key(ch('j'));
        app.handle_key(ch('?'));
        app.handle_key(ch('?'));
        assert_eq!(app.scroll(), 0);
    }

    #[test]
    fn w_opens_the_warnings_and_esc_or_w_closes_them() {
        let (mut app, _) = app_with(sample(), vec![Notice::warning("careful")]);
        app.handle_key(ch('w'));
        assert_eq!(app.screen(), Screen::Notices);
        app.handle_key(ch('w'));
        assert_eq!(app.screen(), Screen::List);
        app.handle_key(ch('w'));
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::List);
        assert!(!app.should_quit());
    }

    #[test]
    fn w_without_warnings_says_so_instead_of_opening_an_empty_page() {
        let mut app = app();
        app.handle_key(ch('w'));
        assert_eq!(app.screen(), Screen::List);
        assert!(app.status().unwrap().text.contains("no warnings"));
    }

    // ---- hosts that could not be loaded ----------------------------------

    #[test]
    fn without_hosts_the_list_screen_only_explains_and_scrolls() {
        let mut app = unavailable();
        assert!(app.hosts().is_none());
        assert!(app.rows().is_empty());
        app.apply_metrics(Metrics {
            max_scroll: 4,
            list_rows: 0,
            ..Metrics::default()
        });
        app.handle_key(ch('j'));
        assert_eq!(app.scroll(), 1);
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.scroll(), 0);
    }

    #[test]
    fn without_hosts_editing_keys_explain_why_they_do_nothing() {
        for key in ['/', 'f'] {
            let mut app = unavailable();
            app.handle_key(ch(key));
            assert_eq!(app.mode(), ListMode::Browse);
            let status = app.status().unwrap();
            assert!(
                status.text.contains("until the problem above is fixed"),
                "{status:?}"
            );
        }
    }

    #[test]
    fn without_hosts_q_esc_and_help_still_work() {
        let mut app = unavailable();
        app.handle_key(ch('?'));
        assert_eq!(app.screen(), Screen::Help);
        app.handle_key(ch('?'));
        app.handle_key(press(KeyCode::Esc));
        assert!(app.should_quit());
    }

    // ---- footer and help text --------------------------------------------

    fn labels(app: &App) -> Vec<&'static str> {
        app.footer_hints().iter().map(|h| h.label).collect()
    }

    #[test]
    fn the_footer_follows_the_screen_and_the_mode() {
        let (mut app, _) = app_with(sample(), vec![Notice::warning("careful")]);
        assert_eq!(
            labels(&app),
            [
                "move", "search", "add", "edit", "delete", "favorite", "copy", "warnings", "help",
                "quit"
            ]
        );

        app.handle_key(ch('/'));
        assert_eq!(
            labels(&app),
            ["to filter", "results", "keep filter", "clear"]
        );
        type_text(&mut app, "web");
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(
            labels(&app),
            [
                "move",
                "search",
                "add",
                "edit",
                "delete",
                "favorite",
                "copy",
                "warnings",
                "help",
                "clear search",
                "quit"
            ]
        );

        app.handle_key(press(KeyCode::Esc));
        app.handle_key(ch('?'));
        assert_eq!(labels(&app), ["scroll", "close help", "quit"]);
        app.handle_key(ch('?'));
        app.handle_key(ch('w'));
        assert_eq!(labels(&app), ["scroll", "close", "quit"]);
    }

    #[test]
    fn the_footer_only_offers_the_warnings_key_when_there_are_warnings() {
        assert!(!labels(&app()).contains(&"warnings"));
    }

    fn tokens(keys: &str) -> Vec<&str> {
        if keys == "/" {
            return vec!["/"];
        }
        keys.split([' ', '/']).filter(|t| !t.is_empty()).collect()
    }

    #[test]
    fn every_footer_key_is_listed_in_the_help() {
        let documented: Vec<&str> = HELP
            .iter()
            .flat_map(|section| section.rows)
            .flat_map(|row| tokens(row.keys))
            .collect();
        let (mut app, _) = app_with(sample(), vec![Notice::warning("careful")]);
        let mut seen = app.footer_hints();
        app.handle_key(ch('/'));
        seen.extend(app.footer_hints());
        app.handle_key(press(KeyCode::Esc));
        app.handle_key(ch('?'));
        seen.extend(app.footer_hints());
        app.handle_key(ch('?'));
        app.handle_key(ch('w'));
        seen.extend(app.footer_hints());
        seen.extend(unavailable().footer_hints());
        for hint in seen {
            for key in tokens(hint.keys) {
                assert!(documented.contains(&key), "{key:?} is not in the help");
            }
        }
    }

    #[test]
    fn help_rows_have_short_keys_and_descriptions() {
        for section in HELP {
            assert!(!section.rows.is_empty(), "{}", section.title);
            for row in section.rows {
                assert!(
                    row.keys.len() <= 13,
                    "{:?} is too wide for the key column",
                    row.keys
                );
                assert!(!row.description.is_empty());
            }
        }
    }

    // ---- adding and editing hosts ----------------------------------------

    fn ctrl(c: char) -> KeyEvent {
        with(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn form_focus(app: &App) -> FormField {
        app.form().expect("the form should be open").focus()
    }

    fn goto(app: &mut App, field: FormField) {
        for _ in 0..20 {
            if form_focus(app) == field {
                return;
            }
            app.handle_key(press(KeyCode::Tab));
        }
        panic!("could not reach {field:?}");
    }

    /// Types a name and hostname into a fresh add form.
    fn fill_new_host(app: &mut App, name: &str, hostname: &str) {
        type_text(app, name);
        app.handle_key(press(KeyCode::Tab));
        type_text(app, hostname);
    }

    #[test]
    fn a_opens_an_empty_form_and_e_opens_the_selected_host() {
        let mut app = app();
        app.handle_key(ch('a'));
        assert_eq!(app.screen(), Screen::Form);
        assert_eq!(app.form().unwrap().title(), "Add host");
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::List, "nothing typed: closes at once");
        assert!(app.form().is_none());

        app.handle_key(ch('j'));
        app.handle_key(ch('e'));
        assert_eq!(app.screen(), Screen::Form);
        assert_eq!(app.form().unwrap().title(), "Edit host 'db'");
    }

    #[test]
    fn e_with_no_host_selected_explains_instead_of_opening_a_form() {
        let (mut app, _) = app_with(Hosts::new(), Vec::new());
        app.handle_key(ch('e'));
        assert_eq!(app.screen(), Screen::List);
        assert!(app.status().unwrap().text.contains("Press a to add one"));
    }

    #[test]
    fn a_and_e_are_typed_letters_while_searching() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "ae");
        assert_eq!(app.screen(), Screen::List);
        assert_eq!(app.list().query.value(), "ae");
    }

    #[test]
    fn adding_a_host_saves_it_selects_it_and_says_so() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('a'));
        fill_new_host(&mut app, "app", "app.example.com");
        app.handle_key(ctrl('s'));

        assert_eq!(app.screen(), Screen::List);
        assert!(app.form().is_none());
        assert_eq!(store.save_count(), 1);
        let saved = store.last_saved().unwrap();
        assert_eq!(saved.len(), 4);
        assert_eq!(saved.get("app").unwrap().hostname, "app.example.com");
        assert_eq!(
            app.hosts().unwrap(),
            &saved,
            "what is shown is what was saved"
        );
        assert_eq!(selected(&app), Some("app"));
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert_eq!(status.text, "Added host 'app'.");
    }

    #[test]
    fn a_new_host_is_visible_even_if_a_search_was_active() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "web");
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(ch('a'));
        fill_new_host(&mut app, "zulu", "zulu.example.com");
        app.handle_key(ctrl('s'));
        assert!(
            app.list().query.is_empty(),
            "the search would have hidden it"
        );
        assert!(listed(&app).contains(&"zulu".to_string()));
        assert_eq!(selected(&app), Some("zulu"));
        assert_eq!(app.mode(), ListMode::Browse);
    }

    #[test]
    fn saving_is_blocked_while_a_field_is_invalid_and_nothing_is_written() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('a'));
        type_text(&mut app, "bad name");
        app.handle_key(ctrl('s'));

        assert_eq!(app.screen(), Screen::Form, "the form stays open");
        assert_eq!(store.save_count(), 0);
        let form = app.form().unwrap();
        assert!(
            form.error(FormField::Name)
                .unwrap()
                .contains("may only contain")
        );
        assert!(form.error(FormField::Hostname).is_some());
        assert!(
            form.notice()
                .unwrap()
                .contains("Fix the fields marked with an error")
        );
        assert_eq!(
            form.input(FormField::Name).unwrap().value(),
            "bad name",
            "input kept"
        );
    }

    #[test]
    fn a_duplicate_name_blocks_saving_and_is_shown_on_the_name_field() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('a'));
        fill_new_host(&mut app, "WEB", "other.example.com");
        app.handle_key(ctrl('s'));
        assert_eq!(app.screen(), Screen::Form);
        assert_eq!(store.save_count(), 0);
        let error = app.form().unwrap().error(FormField::Name).unwrap();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            form_focus(&app),
            FormField::Name,
            "the focus goes to the problem"
        );
    }

    #[test]
    fn a_failing_store_keeps_the_form_and_everything_typed_and_a_retry_works() {
        let (mut app, store) = app_with(sample(), Vec::new());
        store.fail_saves(true);
        app.handle_key(ch('a'));
        fill_new_host(&mut app, "app", "app.example.com");
        goto(&mut app, FormField::Notes);
        type_text(&mut app, "line one\\nline two");

        app.handle_key(ctrl('s'));

        assert_eq!(app.screen(), Screen::Form, "the form is not lost");
        assert_eq!(app.hosts().unwrap().len(), 3, "nothing was added");
        let form = app.form().unwrap();
        let notice = form.notice().unwrap();
        assert!(
            notice.starts_with("Could not save your changes"),
            "{notice}"
        );
        assert!(notice.contains("disk is full"), "{notice}");
        assert_eq!(form.input(FormField::Name).unwrap().value(), "app");
        assert_eq!(
            form.input(FormField::Notes).unwrap().value(),
            "line one\\nline two"
        );

        store.fail_saves(false);
        app.handle_key(ctrl('s'));
        assert_eq!(app.screen(), Screen::List);
        let saved = store.last_saved().unwrap();
        assert_eq!(
            saved.get("app").unwrap().notes.as_deref(),
            Some("line one\nline two"),
            "typing backslash-n made a real line break"
        );
    }

    #[test]
    fn editing_updates_the_host_and_keeps_its_favorite_flag() {
        let (mut app, store) = app_with(sample(), Vec::new());
        assert_eq!(selected(&app), Some("backup"));
        app.handle_key(ch('e'));
        goto(&mut app, FormField::Hostname);
        for _ in 0.."backup.example.com".len() {
            app.handle_key(press(KeyCode::Backspace));
        }
        type_text(&mut app, "10.9.9.9");
        app.handle_key(ctrl('s'));

        assert_eq!(app.screen(), Screen::List);
        let saved = store.last_saved().unwrap();
        let host = saved.get("backup").unwrap();
        assert_eq!(host.hostname, "10.9.9.9");
        assert!(
            host.favorite,
            "the form does not show the flag, so it must not lose it"
        );
        assert_eq!(app.status().unwrap().text, "Updated host 'backup'.");
    }

    #[test]
    fn renaming_a_host_updates_the_hosts_that_jump_through_it() {
        let mut client = host("client", false);
        client.proxy_jump = Some("bastion".to_string());
        let (mut app, store) = app_with(hosts(vec![host("bastion", false), client]), Vec::new());
        assert_eq!(selected(&app), Some("bastion"));
        app.handle_key(ch('e'));
        for _ in 0.."bastion".len() {
            app.handle_key(press(KeyCode::Backspace));
        }
        type_text(&mut app, "gateway");
        app.handle_key(ctrl('s'));

        let saved = store.last_saved().unwrap();
        assert!(saved.get("bastion").is_none());
        assert_eq!(
            saved.get("client").unwrap().proxy_jump.as_deref(),
            Some("gateway")
        );
        assert_eq!(selected(&app), Some("gateway"));
    }

    #[test]
    fn a_host_can_be_saved_with_a_jump_host_forwards_and_agent_forwarding() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('a'));
        fill_new_host(&mut app, "app", "app.example.com");
        goto(&mut app, FormField::Advanced);
        app.handle_key(press(KeyCode::Enter));
        goto(&mut app, FormField::ProxyJump);
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(press(KeyCode::Down));
        app.handle_key(press(KeyCode::Enter));
        goto(&mut app, FormField::LocalForwards);
        type_text(&mut app, "8080:localhost:80");
        goto(&mut app, FormField::ForwardAgent);
        app.handle_key(ch(' '));

        app.handle_key(ctrl('s'));

        let saved = store.last_saved().unwrap();
        let host = saved.get("app").unwrap();
        assert_eq!(host.proxy_jump.as_deref(), Some("backup"));
        assert_eq!(host.local_forwards.len(), 1);
        assert!(host.forward_agent);
    }

    // ---- cancelling ------------------------------------------------------

    #[test]
    fn esc_with_unsaved_changes_asks_and_n_keeps_editing() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('a'));
        type_text(&mut app, "app");
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::Form);
        assert_eq!(app.form().unwrap().mode(), &FormMode::ConfirmDiscard);

        app.handle_key(ch('n'));
        assert_eq!(app.form().unwrap().mode(), &FormMode::Editing);
        assert_eq!(
            app.form().unwrap().input(FormField::Name).unwrap().value(),
            "app"
        );
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn answering_y_discards_the_form_without_saving() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('a'));
        fill_new_host(&mut app, "app", "app.example.com");
        app.handle_key(press(KeyCode::Esc));
        app.handle_key(ch('y'));
        assert_eq!(app.screen(), Screen::List);
        assert!(app.form().is_none());
        assert_eq!(app.hosts().unwrap().len(), 3);
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn q_does_not_quit_from_a_form_it_is_just_a_letter() {
        let mut app = app();
        app.handle_key(ch('a'));
        type_text(&mut app, "q?/fjkwae");
        assert!(!app.should_quit());
        assert_eq!(app.screen(), Screen::Form);
        assert_eq!(
            app.form().unwrap().input(FormField::Name).unwrap().value(),
            "q?/fjkwae"
        );
    }

    #[test]
    fn ctrl_c_in_a_clean_form_quits_but_in_a_dirty_form_asks_first() {
        let mut clean = app();
        clean.handle_key(ch('a'));
        clean.handle_key(ctrl('c'));
        assert!(clean.should_quit());

        let mut dirty = app();
        dirty.handle_key(ch('a'));
        type_text(&mut dirty, "app");
        dirty.handle_key(ctrl('c'));
        assert!(
            !dirty.should_quit(),
            "unsaved input is not thrown away by one keystroke"
        );
        assert_eq!(dirty.form().unwrap().mode(), &FormMode::ConfirmDiscard);
        dirty.handle_key(ctrl('c'));
        assert!(dirty.should_quit(), "but pressing it again means it");
    }

    // ---- the identity file warning ---------------------------------------

    fn app_with_home(home: &std::path::Path) -> (App, FakeStore) {
        let store = FakeStore::with_home(home.to_path_buf());
        let app = App::new(Startup::loaded(sample(), store.clone(), Vec::new()));
        (app, store)
    }

    fn add_host_with_key(app: &mut App, key_path: &str) {
        app.handle_key(ch('a'));
        fill_new_host(app, "app", "app.example.com");
        goto(app, FormField::IdentityFile);
        type_text(app, key_path);
        app.handle_key(ctrl('s'));
    }

    #[test]
    fn a_missing_key_file_is_reported_after_a_successful_save() {
        let dir = tempfile::tempdir().unwrap();
        let (mut app, store) = app_with_home(dir.path());
        add_host_with_key(&mut app, "/nonexistent/id_ed25519");

        assert_eq!(store.save_count(), 1, "a missing key does not block saving");
        assert_eq!(app.screen(), Screen::List);
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Warning);
        assert!(status.text.starts_with("Added host 'app'."), "{status:?}");
        assert!(
            status
                .text
                .contains("the identity file '/nonexistent/id_ed25519' does not exist"),
            "{status:?}"
        );
    }

    #[test]
    fn an_existing_key_file_gives_no_warning() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        std::fs::write(&key, "not a real key").unwrap();
        let (mut app, _) = app_with_home(dir.path());
        add_host_with_key(&mut app, key.to_str().unwrap());
        assert_eq!(app.status().unwrap().kind, StatusKind::Info);
    }

    #[test]
    fn a_tilde_key_path_is_checked_against_the_home_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".ssh")).unwrap();
        std::fs::write(dir.path().join(".ssh").join("id_ed25519"), "x").unwrap();

        let (mut app, _) = app_with_home(dir.path());
        add_host_with_key(&mut app, "~/.ssh/id_ed25519");
        assert_eq!(
            app.status().unwrap().kind,
            StatusKind::Info,
            "found under home"
        );

        let (mut app, _) = app_with_home(dir.path());
        add_host_with_key(&mut app, "~/.ssh/missing");
        assert_eq!(app.status().unwrap().kind, StatusKind::Warning);
    }

    #[test]
    fn editing_a_host_also_warns_about_a_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let (mut app, _) = app_with_home(dir.path());
        app.handle_key(ch('e'));
        goto(&mut app, FormField::IdentityFile);
        type_text(&mut app, "/nonexistent/key");
        app.handle_key(ctrl('s'));
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Warning);
        assert!(
            status.text.starts_with("Updated host 'backup'."),
            "{status:?}"
        );
    }

    // ---- the form's footer and scrolling ---------------------------------

    #[test]
    fn every_form_footer_key_is_listed_in_the_help() {
        let documented: Vec<&str> = HELP
            .iter()
            .flat_map(|section| section.rows)
            .flat_map(|row| tokens(row.keys))
            .collect();
        let mut app = app();
        app.handle_key(ch('a'));
        let mut seen = Vec::new();
        for _ in 0..8 {
            seen.extend(app.footer_hints());
            app.handle_key(press(KeyCode::Tab));
        }
        goto(&mut app, FormField::Advanced);
        app.handle_key(press(KeyCode::Enter));
        for _ in 0..5 {
            seen.extend(app.footer_hints());
            app.handle_key(press(KeyCode::Tab));
        }
        goto(&mut app, FormField::ProxyJump);
        app.handle_key(press(KeyCode::Enter));
        seen.extend(app.footer_hints());
        app.handle_key(press(KeyCode::Esc));
        type_text(&mut app, "x");
        app.handle_key(press(KeyCode::Esc));
        seen.extend(app.footer_hints());
        assert!(seen.len() > 10);
        for hint in seen {
            for key in tokens(hint.keys) {
                assert!(documented.contains(&key), "{key:?} is not in the help");
            }
        }
    }

    #[test]
    fn the_form_scroll_position_comes_from_rendering() {
        let mut app = app();
        app.handle_key(ch('a'));
        app.apply_metrics(Metrics {
            form_scroll: 4,
            ..Metrics::default()
        });
        assert_eq!(app.form().unwrap().scroll, 4);
    }

    // ---- deleting --------------------------------------------------------

    fn type_name_and_confirm(app: &mut App, name: &str) {
        type_text(app, name);
        app.handle_key(press(KeyCode::Enter));
    }

    #[test]
    fn d_asks_for_the_host_name_before_deleting_anything() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('j'));
        assert_eq!(selected(&app), Some("db"));
        app.handle_key(ch('d'));

        assert_eq!(app.mode(), ListMode::ConfirmDelete);
        let confirm = app.delete().unwrap();
        assert_eq!(confirm.name, "db");
        assert!(confirm.input.is_empty());
        assert_eq!(
            app.hosts().unwrap().len(),
            3,
            "nothing is deleted by asking"
        );
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn typing_the_exact_name_and_pressing_enter_deletes_and_saves() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('j'));
        app.handle_key(ch('d'));
        type_name_and_confirm(&mut app, "db");

        assert_eq!(app.mode(), ListMode::Browse);
        assert!(app.delete().is_none());
        assert!(app.hosts().unwrap().get("db").is_none());
        assert_eq!(store.save_count(), 1);
        assert!(store.last_saved().unwrap().get("db").is_none());
        assert_eq!(app.hosts().unwrap(), &store.last_saved().unwrap());
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert_eq!(status.text, "Deleted host 'db'.");
    }

    #[test]
    fn the_selection_moves_to_the_host_that_takes_the_deleted_ones_place() {
        let (mut app, _) = app_with(sample(), Vec::new());
        // Order: backup, db, web. Delete the middle one.
        app.handle_key(ch('j'));
        app.handle_key(ch('d'));
        type_name_and_confirm(&mut app, "db");
        assert_eq!(selected(&app), Some("web"));

        // Deleting the last one selects the new last one.
        app.handle_key(ch('d'));
        type_name_and_confirm(&mut app, "web");
        assert_eq!(selected(&app), Some("backup"));
    }

    #[test]
    fn deleting_the_last_host_leaves_an_empty_list() {
        let (mut app, store) = app_with(hosts(vec![host("only", false)]), Vec::new());
        app.handle_key(ch('d'));
        type_name_and_confirm(&mut app, "only");
        assert!(app.hosts().unwrap().is_empty());
        assert_eq!(selected(&app), None);
        assert_eq!(store.last_saved().unwrap().len(), 0);
    }

    #[test]
    fn a_wrong_name_does_not_delete_and_says_so_until_it_is_edited() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('d'));
        type_name_and_confirm(&mut app, "backu");

        assert_eq!(app.mode(), ListMode::ConfirmDelete, "still asking");
        assert!(app.delete().unwrap().mismatch);
        assert_eq!(store.save_count(), 0);
        assert!(app.hosts().unwrap().get("backup").is_some());

        app.handle_key(ch('p'));
        assert!(
            !app.delete().unwrap().mismatch,
            "typing again clears the message"
        );
        app.handle_key(press(KeyCode::Enter));
        assert!(app.hosts().unwrap().get("backup").is_none());
    }

    #[test]
    fn the_name_must_match_exactly_including_case() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('d'));
        type_name_and_confirm(&mut app, "BACKUP");
        assert!(app.delete().unwrap().mismatch);
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn enter_with_nothing_typed_does_not_delete() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('d'));
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.mode(), ListMode::ConfirmDelete);
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn esc_cancels_the_deletion() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('d'));
        type_text(&mut app, "backup");
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.mode(), ListMode::Browse);
        assert!(app.delete().is_none());
        assert_eq!(app.hosts().unwrap().len(), 3);
        assert_eq!(store.save_count(), 0);
        assert!(!app.should_quit());
    }

    #[test]
    fn letters_typed_in_the_confirmation_are_text_not_commands() {
        let (mut app, store) = app_with(sample(), Vec::new());
        app.handle_key(ch('d'));
        type_text(&mut app, "q?/fdcae");
        assert!(!app.should_quit());
        assert_eq!(app.screen(), Screen::List);
        assert_eq!(app.delete().unwrap().input.value(), "q?/fdcae");
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn ctrl_c_still_quits_from_the_confirmation() {
        let mut app = app();
        app.handle_key(ch('d'));
        app.handle_key(ctrl('c'));
        assert!(app.should_quit());
    }

    #[test]
    fn a_host_that_others_jump_through_is_refused_at_once_with_the_dependents_listed() {
        let mut a = host("a", false);
        a.proxy_jump = Some("bastion".to_string());
        let mut b = host("b", false);
        b.proxy_jump = Some("bastion".to_string());
        let (mut app, store) = app_with(hosts(vec![host("bastion", false), a, b]), Vec::new());
        assert_eq!(selected(&app), Some("a"));
        app.handle_key(press(KeyCode::End));
        app.handle_key(ch('k'));
        app.handle_key(ch('k'));
        assert_eq!(selected(&app), Some("a"));
        app.handle_key(ch('j'));
        app.handle_key(ch('j'));
        assert_eq!(selected(&app), Some("bastion"));

        app.handle_key(ch('d'));

        assert_eq!(app.mode(), ListMode::Browse, "no confirmation is asked");
        assert!(app.delete().is_none());
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert_eq!(
            status.text,
            "Host 'bastion' is the jump host of 'a', 'b'. \
             Change or remove the jump host on those hosts first."
        );
        assert_eq!(store.save_count(), 0);
        assert!(app.hosts().unwrap().get("bastion").is_some());
    }

    #[test]
    fn a_host_that_nothing_jumps_through_can_be_deleted_even_if_it_jumps_itself() {
        let mut client = host("client", false);
        client.proxy_jump = Some("bastion".to_string());
        let (mut app, _) = app_with(hosts(vec![host("bastion", false), client]), Vec::new());
        assert_eq!(selected(&app), Some("bastion"));
        app.handle_key(press(KeyCode::Down));
        assert_eq!(selected(&app), Some("client"));
        app.handle_key(ch('d'));
        assert_eq!(app.mode(), ListMode::ConfirmDelete);
    }

    #[test]
    fn a_failed_save_keeps_the_host_and_says_why() {
        let (mut app, store) = app_with(sample(), Vec::new());
        store.fail_saves(true);
        app.handle_key(ch('d'));
        type_name_and_confirm(&mut app, "backup");

        assert!(app.hosts().unwrap().get("backup").is_some(), "still there");
        assert_eq!(app.mode(), ListMode::Browse);
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert!(
            status.text.contains("Could not save your changes"),
            "{status:?}"
        );
        assert!(status.text.contains("disk is full"), "{status:?}");
        assert_eq!(selected(&app), Some("backup"));
    }

    #[test]
    fn d_with_nothing_selected_says_so() {
        let (mut app, _) = app_with(Hosts::new(), Vec::new());
        app.handle_key(ch('d'));
        assert_eq!(app.mode(), ListMode::Browse);
        assert!(app.status().unwrap().text.contains("no host to delete"));
    }

    #[test]
    fn d_deletes_the_selected_host_of_a_filtered_list() {
        let (mut app, _) = app_with(sample(), Vec::new());
        app.handle_key(ch('/'));
        type_text(&mut app, "web");
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(ch('d'));
        assert_eq!(app.delete().unwrap().name, "web");
        type_name_and_confirm(&mut app, "web");
        assert!(app.hosts().unwrap().get("web").is_none());
        assert_eq!(app.hosts().unwrap().len(), 2);
    }

    // ---- the ssh command -------------------------------------------------

    fn deploy_host() -> Hosts {
        let mut web = host("web", false);
        web.user = Some("deploy".to_string());
        web.port = Some(2222);
        hosts(vec![web, host("db", false)])
    }

    #[test]
    fn c_shows_the_command_and_asks_the_terminal_to_copy_it() {
        let (mut app, _) = app_with(deploy_host(), Vec::new());
        app.handle_key(press(KeyCode::Down));
        assert_eq!(selected(&app), Some("web"));

        app.handle_key(ch('c'));

        assert_eq!(app.mode(), ListMode::Command);
        let view = app.command().unwrap();
        assert_eq!(view.host, "web");
        assert_eq!(view.text, "ssh -l deploy -p 2222 -- web.example.com");
        assert_eq!(
            app.take_copy_request().as_deref(),
            Some("ssh -l deploy -p 2222 -- web.example.com")
        );
    }

    #[test]
    fn a_copy_request_is_handed_out_once() {
        let (mut app, _) = app_with(deploy_host(), Vec::new());
        app.handle_key(ch('c'));
        assert!(app.take_copy_request().is_some());
        assert!(app.take_copy_request().is_none());
    }

    #[test]
    fn any_key_closes_the_command_and_does_nothing_else() {
        for key in [
            ch('x'),
            ch('q'),
            ch('d'),
            press(KeyCode::Enter),
            press(KeyCode::Esc),
            ch('c'),
        ] {
            let (mut app, store) = app_with(deploy_host(), Vec::new());
            app.handle_key(ch('c'));
            app.handle_key(key);
            assert_eq!(app.mode(), ListMode::Browse, "{key:?}");
            assert!(app.command().is_none());
            assert!(!app.should_quit(), "{key:?} only closes the command");
            assert!(app.delete().is_none());
            assert_eq!(store.save_count(), 0);
        }
    }

    #[test]
    fn closing_the_command_does_not_ask_for_another_copy() {
        let (mut app, _) = app_with(deploy_host(), Vec::new());
        app.handle_key(ch('c'));
        app.take_copy_request();
        app.handle_key(ch('x'));
        assert!(app.take_copy_request().is_none());
    }

    #[test]
    fn ctrl_c_quits_even_while_the_command_is_shown() {
        let (mut app, _) = app_with(deploy_host(), Vec::new());
        app.handle_key(ch('c'));
        app.handle_key(ctrl('c'));
        assert!(app.should_quit());
    }

    #[test]
    fn the_command_uses_the_jump_chain_and_the_identity_file() {
        let mut jump = host("bastion", false);
        jump.user = Some("ops".to_string());
        let mut web = host("web", false);
        web.proxy_jump = Some("bastion".to_string());
        web.identity_file = Some("~/.ssh/my key".to_string());
        let (mut app, _) = app_with(hosts(vec![jump, web]), Vec::new());
        app.handle_key(press(KeyCode::Down));
        app.handle_key(ch('c'));
        let text = &app.command().unwrap().text;
        if cfg!(unix) {
            assert_eq!(
                text,
                "ssh -i '~/.ssh/my key' -o IdentitiesOnly=yes \
                 -J ops@bastion.example.com:22 -- web.example.com"
            );
        } else {
            assert!(text.contains("IdentitiesOnly=yes"), "{text}");
        }
    }

    #[test]
    fn c_with_nothing_selected_says_so() {
        let (mut app, _) = app_with(Hosts::new(), Vec::new());
        app.handle_key(ch('c'));
        assert_eq!(app.mode(), ListMode::Browse);
        assert!(
            app.status()
                .unwrap()
                .text
                .contains("no host to show a command for")
        );
        assert!(app.take_copy_request().is_none());
    }

    #[test]
    fn d_and_c_explain_themselves_when_hosts_could_not_be_loaded() {
        for key in ['d', 'c'] {
            let mut app = unavailable();
            app.handle_key(ch(key));
            assert_eq!(app.mode(), ListMode::Browse);
            assert!(
                app.status()
                    .unwrap()
                    .text
                    .contains("until the problem above is fixed")
            );
            assert!(app.take_copy_request().is_none());
        }
    }

    #[test]
    fn d_and_c_are_typed_letters_while_searching() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "dc");
        assert_eq!(app.mode(), ListMode::Search);
        assert!(app.delete().is_none() && app.command().is_none());
        assert!(app.take_copy_request().is_none());
    }

    #[test]
    fn the_footer_and_the_help_cover_deleting_and_copying() {
        let documented: Vec<&str> = HELP
            .iter()
            .flat_map(|section| section.rows)
            .flat_map(|row| tokens(row.keys))
            .collect();
        let mut app = app();
        let mut seen = app.footer_hints();
        app.handle_key(ch('d'));
        assert_eq!(labels(&app), ["the host name", "delete", "cancel"]);
        seen.extend(app.footer_hints());
        app.handle_key(press(KeyCode::Esc));
        app.handle_key(ch('c'));
        assert_eq!(labels(&app), ["close"]);
        seen.extend(app.footer_hints());
        for hint in seen {
            for key in tokens(hint.keys) {
                assert!(documented.contains(&key), "{key:?} is not in the help");
            }
        }
        for key in ["d", "c"] {
            assert!(documented.contains(&key), "{key:?} is not in the help");
        }
    }
}
