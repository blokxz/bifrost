//! Application state and key handling.
//!
//! [`App`] holds everything that decides what is on screen and never touches the
//! terminal: key events go in, state changes come out. Saving goes through the
//! [`super::persist::HostStore`] it was given. Rendering (see [`super::ui`])
//! only reads the state, so all of this is unit-testable.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::effects::{Request, Response};
use super::form::{Form, FormField, FormMode, Outcome};
use super::input::TextInput;
use super::keys::{Copying, FixOutcome, Generation, HostChoice, KeysScreen};
use super::list::{self, ListState, Row};
use super::startup::{Library, Notice, Startup};
use crate::domain::validate::{self, Field};
use crate::domain::{Hosts, HostsError, ValidationError};
use crate::ssh::agent::AgentState;
use crate::ssh::command::{
    KnownHostsTarget, Shell, SshArgs, build_args, build_copy_args, display_command,
    known_hosts_targets,
};
use crate::ssh::connect::{Exit, Outcome as SshOutcome};
use crate::ssh::diagnose::{FailureKind, Verdict, classify, host_key_change};
use crate::ssh::keygen::Removal;
use crate::ssh::keys::{KeysSnapshot, Permissions};
use std::collections::VecDeque;
use std::path::PathBuf;

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
    /// Why the last connection failed, and what to try.
    ConnectError,
    /// The server's key is not the one saved. A blocking screen: aborting is the
    /// default, and removing the old key takes typing the host's name.
    HostKeyChanged,
    /// Everything ssh printed during the last connection.
    SshOutput,
    /// The user's ssh keys, and whether the agent holds them.
    Keys,
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

/// A connection the user asked for. The event loop takes it and hands the
/// terminal to ssh (see [`super::handover`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// The saved host's name.
    pub name: String,
    pub args: SshArgs,
    /// The `known_hosts` names of the host and of its jump hosts.
    pub known_hosts: Vec<KnownHostsTarget>,
}

/// What came of handing the terminal to a program: ssh for a connection,
/// `ssh-keygen` to make a key, `ssh-add` to load one.
#[derive(Debug)]
pub enum HandoverResult {
    /// The program ran and ended.
    Ran(SshOutcome),
    /// It could not be started, or the terminal could not be handed over, or it
    /// was refused before anything ran. The text says why, in plain English.
    Failed(String),
}

/// How a tool run for the keys screen (`ssh-keygen`, `ssh-add`) ended.
#[derive(Debug, PartialEq, Eq)]
enum ToolEnd {
    Done,
    /// The user pressed Ctrl-C.
    Cancelled,
    /// It ran and did not succeed. Holds why, in plain English.
    Failed(String),
    /// It never ran. Holds why, in plain English.
    NotRun(String),
}

impl ToolEnd {
    /// The longest piece of what a tool said that is repeated on screen.
    const SAID: usize = 200;

    fn from(result: HandoverResult, program: &str) -> ToolEnd {
        let outcome = match result {
            HandoverResult::Failed(why) => return ToolEnd::NotRun(why),
            HandoverResult::Ran(outcome) => outcome,
        };
        if outcome.was_interrupted() {
            return ToolEnd::Cancelled;
        }
        match outcome.exit {
            Exit::Code(0) => ToolEnd::Done,
            Exit::Code(code) => {
                // The end of what it said is usually the reason. Raw: the screen
                // cleans it before drawing.
                let said = String::from_utf8_lossy(&outcome.stderr);
                let last = said.lines().map(str::trim).rfind(|line| !line.is_empty());
                ToolEnd::Failed(match last {
                    Some(line) => format!(
                        "{program} ended with status {code}: {}",
                        line.chars().take(Self::SAID).collect::<String>()
                    ),
                    None => format!("{program} ended with status {code}."),
                })
            }
            Exit::Signal(signal) => {
                ToolEnd::Failed(format!("{program} was stopped by signal {signal}."))
            }
        }
    }
}

/// What the last connection left behind: enough to explain a failure and to
/// show what ssh printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionReport {
    /// The saved host's name.
    pub name: String,
    /// Why it failed, when it did.
    pub failure: Option<FailureKind>,
    /// The end of ssh's stderr, raw. Sanitized when shown.
    pub stderr: Vec<u8>,
}

/// What the blocking host key screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChangeView {
    /// The saved host that was being connected to.
    pub name: String,
    /// The kind of the key the server sent, as ssh named it and only if it looks
    /// like one.
    pub key_type: Option<String>,
    /// The fingerprint of that key, only if it is one.
    pub fingerprint: Option<String>,
    /// The file that holds the old key, as ssh printed it.
    pub file: Option<String>,
    pub line: Option<u32>,
    /// The old key that Bifrost can remove, if what ssh said matches a host it
    /// connected through and the default `known_hosts`. `None` means Bifrost
    /// offers no removal.
    pub removal: Option<KnownHostsTarget>,
}

/// The confirmation before removing an old key: the saved host's name has to be
/// typed.
#[derive(Debug)]
pub struct RemovalConfirm {
    pub input: TextInput,
    /// Set when Enter was pressed with something other than the name.
    pub mismatch: bool,
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
    /// How many key rows fit on the keys screen.
    pub keys_rows: usize,
    /// How many host rows fit in the dialog that sends a key.
    pub copy_rows: usize,
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
            row("Enter", "Connect to the selected host"),
            row("/", "Search the hosts"),
            row("K", "Show your ssh keys and what the agent holds"),
            row("o", "Read what ssh printed during the last connection"),
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
        title: "Your ssh keys",
        rows: &[
            row("Up/Down j/k", "Move through the keys"),
            row("PgUp/PgDn", "Move by a screenful"),
            row(
                "f",
                "Set the selected private key's permissions to 0600, after you confirm. \
                 Not offered for a symbolic link",
            ),
            row(
                "g",
                "Make a new ed25519 key with ssh-keygen. Tab switches between the name and \
                 the comment. ssh-keygen asks for a passphrase itself: Bifrost never sees it",
            ),
            row(
                "a",
                "Add the selected key to the ssh agent with ssh-add, which asks for its \
                 passphrase itself",
            ),
            row(
                "c",
                "Send the selected key's public key to a saved host, after you choose one \
                 and confirm. It is added to ~/.ssh/authorized_keys there. ssh asks for the \
                 password itself",
            ),
            row("r", "Read the keys and ask the agent again"),
            row("?", "Open this help, then come back here"),
            row("Esc", "Back to the host list"),
        ],
    },
    HelpSection {
        title: "After a failed connection",
        rows: &[
            row("o", "Read everything ssh printed"),
            row("Enter/Esc", "Go back to where you were"),
            row("Up/Down j/k", "Scroll"),
        ],
    },
    HelpSection {
        title: "When a server's identity changed",
        rows: &[
            row("Enter/Esc", "Abort. This is the safe choice"),
            row("d", "Read what ssh printed"),
            row(
                "r",
                "Remove the old key, after typing the host name. Then connect again",
            ),
            row("Up/Down j/k", "Scroll"),
        ],
    },
    HelpSection {
        title: "What ssh printed",
        rows: &[row("Up/Down j/k", "Scroll"), row("o/Esc/Enter", "Go back")],
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
    /// What the app wants done outside itself, oldest first; taken by the event
    /// loop (see [`super::effects`]).
    requests: VecDeque<Request>,
    /// How the last connection ended.
    report: Option<ConnectionReport>,
    /// The `known_hosts` names of the connection that was last requested.
    pending_known_hosts: Vec<KnownHostsTarget>,
    /// The `known_hosts` file that removing a key edits, when it is known.
    known_hosts_file: Option<PathBuf>,
    key_change: Option<KeyChangeView>,
    key_confirm: Option<RemovalConfirm>,
    /// Where the ssh output goes back to when it is closed.
    output_return: Screen,
    /// Where the help goes back to when it is closed.
    help_return: Screen,
    /// Where the screens for a failed connection go back to: the host list, or the
    /// keys screen when the connection was made to send a key.
    failure_return: Screen,
    /// The keys screen, once it has been opened.
    keys: Option<KeysScreen>,
    /// The key to select once the keys have been read again: the one just made.
    select_key: Option<String>,
    status: Option<Status>,
    help_scroll: usize,
    notices_scroll: usize,
    error_scroll: usize,
    output_scroll: usize,
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
            requests: VecDeque::new(),
            report: None,
            pending_known_hosts: Vec::new(),
            known_hosts_file: None,
            key_change: None,
            key_confirm: None,
            output_return: Screen::List,
            help_return: Screen::List,
            failure_return: Screen::List,
            keys: None,
            select_key: None,
            status: None,
            help_scroll: 0,
            notices_scroll: 0,
            error_scroll: 0,
            output_scroll: 0,
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

    /// The oldest thing the app wants done outside itself, if there is one. It
    /// is returned once: the caller carries it out and reports back with
    /// [`App::handle_response`].
    pub fn take_request(&mut self) -> Option<Request> {
        self.requests.pop_front()
    }

    /// Takes in what came of `request`.
    pub fn handle_response(&mut self, request: &Request, response: Response) {
        match (request, response) {
            (Request::Copy(_), Response::Copied) => {}
            (Request::Connect(request), Response::Connected(result)) => {
                self.connection_ended(&request.name, result);
            }
            (Request::RemoveKey(target), Response::KeyRemoved(result)) => {
                self.key_removal_finished(target, result);
            }
            (Request::LoadKeys, Response::Keys(snapshot)) => self.keys_loaded(snapshot),
            (Request::FixKeyPermissions { file_name }, Response::PermissionsFixed(result)) => {
                self.permissions_fixed(file_name, result);
            }
            (Request::GenerateKey { file_name, .. }, Response::KeyGenerated(result)) => {
                self.key_generated(file_name, result);
            }
            (Request::AddKeyToAgent { file_name }, Response::KeyAdded(result)) => {
                self.key_added(file_name, result);
            }
            (Request::CopyKey { file_name, connect }, Response::KeyCopied(result)) => {
                self.key_copied(file_name, &connect.name, result);
            }
            // Whoever carries requests out answers each with its own kind of
            // response; anything else is a mistake there, and the user is told
            // rather than left waiting for a result that will not come.
            (_, other) => self.set_status(
                StatusKind::Error,
                format!("Internal error: unexpected response {other:?}."),
            ),
        }
    }

    /// Tells the app which `known_hosts` file removing an old key edits: the one
    /// `ssh-keygen -R` uses without being told. Until this is set, no removal is
    /// offered.
    pub fn set_known_hosts_file(&mut self, file: Option<PathBuf>) {
        self.known_hosts_file = file;
    }

    /// What the host key screen shows, while it is the screen.
    pub fn key_change(&self) -> Option<&KeyChangeView> {
        self.key_change.as_ref()
    }

    /// The removal confirmation, while it is showing.
    pub fn key_confirm(&self) -> Option<&RemovalConfirm> {
        self.key_confirm.as_ref()
    }

    /// The keys screen's state, while it is open.
    pub fn keys(&self) -> Option<&KeysScreen> {
        self.keys.as_ref()
    }

    /// How the last connection ended, if there was one.
    pub fn report(&self) -> Option<&ConnectionReport> {
        self.report.as_ref()
    }

    /// Whether the last connection left any ssh output to read.
    fn has_output(&self) -> bool {
        self.report.as_ref().is_some_and(|r| !r.stderr.is_empty())
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
            Screen::ConnectError | Screen::HostKeyChanged => self.error_scroll,
            Screen::SshOutput => self.output_scroll,
            // The keys list scrolls by selection, not as a page.
            Screen::Keys => 0,
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
            Screen::ConnectError => {
                let mut hints = vec![hint("Up/Down j/k", "scroll")];
                if self.has_output() {
                    hints.push(hint("o", "ssh output"));
                }
                hints.push(hint("Enter/Esc", "back"));
                hints.push(hint("q", "quit"));
                hints
            }
            Screen::SshOutput => vec![
                hint("Up/Down j/k", "scroll"),
                hint("o/Esc/Enter", "back"),
                hint("q", "quit"),
            ],
            Screen::Keys => match self.keys.as_ref() {
                Some(keys) if keys.copying().is_some_and(|dialog| dialog.confirming()) => {
                    vec![hint("y", "send the key"), hint("n/Esc", "back")]
                }
                Some(keys) if keys.copying().is_some() => vec![
                    hint("Up/Down j/k", "choose"),
                    hint("Enter", "select"),
                    hint("Esc", "cancel"),
                ],
                Some(keys) if keys.generating().is_some() => vec![
                    hint("Tab", "next field"),
                    hint("Enter", "next / make the key"),
                    hint("Esc", "cancel"),
                ],
                Some(keys) if keys.confirming().is_some() => {
                    vec![hint("y", "change to 0600"), hint("n/Esc", "cancel")]
                }
                keys => {
                    let mut hints = vec![hint("Up/Down j/k", "move")];
                    if keys
                        .and_then(KeysScreen::selected_entry)
                        .is_some_and(|entry| entry.can_fix_permissions())
                    {
                        hints.push(hint("f", "fix permissions"));
                    }
                    hints.push(hint("g", "new key"));
                    if keys
                        .and_then(KeysScreen::selected_entry)
                        .is_some_and(|entry| entry.loaded != Some(true))
                    {
                        hints.push(hint("a", "add to agent"));
                    }
                    if keys.and_then(KeysScreen::selected_entry).is_some() {
                        hints.push(hint("c", "send to host"));
                    }
                    hints.push(hint("r", "refresh"));
                    hints.push(hint("?", "help"));
                    hints.push(hint("Esc", "back"));
                    hints.push(hint("q", "quit"));
                    hints
                }
            },
            Screen::HostKeyChanged if self.key_confirm.is_some() => vec![
                hint("Type", "the host name"),
                hint("Enter", "remove"),
                hint("Esc", "cancel"),
            ],
            // Blocking: aborting is first, and nothing but these does anything.
            Screen::HostKeyChanged => {
                let mut hints = vec![hint("Enter/Esc", "abort (safe)")];
                if self.has_output() {
                    hints.push(hint("d", "ssh output"));
                }
                if self
                    .key_change
                    .as_ref()
                    .is_some_and(|v| v.removal.is_some())
                {
                    hints.push(hint("r", "remove old key..."));
                }
                hints.push(hint("Up/Down j/k", "scroll"));
                hints
            }
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
                        hint("Enter", "connect"),
                        hint("/", "search"),
                        hint("a", "add"),
                        hint("e", "edit"),
                        hint("d", "delete"),
                        hint("f", "favorite"),
                        hint("c", "copy"),
                        hint("K", "keys"),
                    ];
                    if self.has_output() {
                        hints.push(hint("o", "ssh output"));
                    }
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
        if let Some(keys) = &mut self.keys {
            keys.set_visible(metrics.keys_rows);
            keys.set_copy_visible(metrics.copy_rows);
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
            Screen::ConnectError => self.connect_error_key(key),
            Screen::SshOutput => self.output_key(key),
            Screen::HostKeyChanged => self.host_key_key(key),
            Screen::Keys => self.keys_key(key),
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
            Screen::ConnectError | Screen::HostKeyChanged => Some(&mut self.error_scroll),
            Screen::SshOutput => Some(&mut self.output_scroll),
            Screen::Form | Screen::Keys => None,
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
            Screen::ConnectError | Screen::HostKeyChanged => self.error_scroll = 0,
            Screen::SshOutput => self.output_scroll = 0,
            Screen::List | Screen::Form | Screen::Keys => {}
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
            KeyCode::Char('?') | KeyCode::Esc => {
                let back = std::mem::replace(&mut self.help_return, Screen::List);
                self.open(back);
            }
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
            KeyCode::Char('o') => self.show_output(Screen::List),
            // A capital: the lower case k moves the selection up.
            KeyCode::Char('K') => self.requests.push_back(Request::LoadKeys),
            KeyCode::Enter => self.request_connect(),
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

    // ---- connecting ------------------------------------------------------

    /// Asks the event loop to connect to the selected host.
    fn request_connect(&mut self) {
        let Some(hosts) = self.hosts() else {
            return;
        };
        let Some(host) = self.list.selected.as_deref().and_then(|n| hosts.get(n)) else {
            self.set_status(
                StatusKind::Info,
                "There is no host to connect to. Press a to add one.",
            );
            return;
        };
        let name = host.name.clone();
        let built = build_args(host, hosts)
            .and_then(|args| known_hosts_targets(host, hosts).map(|known| (args, known)));
        match built {
            Ok((args, known_hosts)) => {
                self.pending_known_hosts.clone_from(&known_hosts);
                self.requests.push_back(Request::Connect(ConnectRequest {
                    name,
                    args,
                    known_hosts,
                }));
            }
            Err(err) => self.set_status(StatusKind::Error, err.to_string()),
        }
    }

    /// Reports how a connection ended, once the terminal is back.
    ///
    /// A failure gets a screen of its own that explains it and says what to try.
    /// Anything that is not a failure (a normal logout, the remote command's own
    /// exit status, Ctrl-C) is one line at the bottom of the list.
    pub fn connection_ended(&mut self, name: &str, result: HandoverResult) {
        self.failure_return = Screen::List;
        let outcome = match result {
            HandoverResult::Failed(text) => {
                self.report = None;
                self.set_status(StatusKind::Error, text);
                return;
            }
            HandoverResult::Ran(outcome) => outcome,
        };

        let verdict = classify(&outcome);
        self.report = Some(ConnectionReport {
            name: name.to_string(),
            failure: match verdict {
                Verdict::Failed(kind) => Some(kind),
                _ => None,
            },
            stderr: outcome.stderr,
        });
        let (kind, text) = match verdict {
            Verdict::Failed(FailureKind::HostKeyChanged) => {
                self.show_key_change(name);
                return;
            }
            Verdict::Failed(_) => {
                self.open(Screen::ConnectError);
                return;
            }
            Verdict::Ended => (StatusKind::Info, format!("Disconnected from '{name}'.")),
            Verdict::RemoteStatus(code) => (
                StatusKind::Info,
                format!("The session on '{name}' ended with status {code}."),
            ),
            Verdict::Cancelled => (
                StatusKind::Info,
                format!("The connection to '{name}' was cancelled."),
            ),
            Verdict::ClosedByYou => (
                StatusKind::Info,
                format!("The connection to '{name}' was closed."),
            ),
            Verdict::Signalled(signal) => (
                StatusKind::Warning,
                format!("ssh for '{name}' was stopped by signal {signal}."),
            ),
        };
        self.set_status(kind, text);
    }

    /// Opens the blocking host key screen with what ssh said about the change.
    fn show_key_change(&mut self, name: &str) {
        let stderr = self
            .report
            .as_ref()
            .map(|report| report.stderr.as_slice())
            .unwrap_or_default();
        let read = host_key_change(stderr);
        let removal = read
            .removal_target(&self.pending_known_hosts, self.known_hosts_file.as_deref())
            .cloned();
        self.key_change = Some(KeyChangeView {
            name: name.to_string(),
            key_type: read.key_type,
            fingerprint: read.fingerprint,
            file: read.file,
            line: read.line,
            removal,
        });
        self.key_confirm = None;
        self.open(Screen::HostKeyChanged);
    }

    /// Opens the page with everything ssh printed, if there is any. Closing it
    /// goes back to `from`.
    fn show_output(&mut self, from: Screen) {
        if !self.has_output() {
            self.set_status(
                StatusKind::Info,
                "There is no ssh output to show. It appears here after a connection.",
            );
            return;
        }
        self.output_return = from;
        self.open(Screen::SshOutput);
    }

    fn connect_error_key(&mut self, key: KeyEvent) {
        if !Self::is_plain(key) {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Enter | KeyCode::Esc => self.open(self.failure_return),
            KeyCode::Char('o') => self.show_output(Screen::ConnectError),
            _ => {
                self.scroll_key(key);
            }
        }
    }

    fn output_key(&mut self, key: KeyEvent) {
        if !Self::is_plain(key) {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('o') | KeyCode::Esc | KeyCode::Enter => self.open(self.output_return),
            _ => {
                self.scroll_key(key);
            }
        }
    }

    /// The blocking screen. Aborting is the default (Enter or Esc), and no other
    /// key does anything except reading ssh's output, removing the old key and
    /// scrolling. Ctrl+C still quits, as everywhere.
    fn host_key_key(&mut self, key: KeyEvent) {
        if self.key_confirm.is_some() {
            self.removal_confirm_key(key);
            return;
        }
        if !Self::is_plain(key) {
            return;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Esc => self.abort_key_change(),
            KeyCode::Char('d') => self.show_output(Screen::HostKeyChanged),
            KeyCode::Char('r') => {
                if self
                    .key_change
                    .as_ref()
                    .is_some_and(|v| v.removal.is_some())
                {
                    self.key_confirm = Some(RemovalConfirm {
                        input: TextInput::default(),
                        mismatch: false,
                    });
                }
            }
            _ => {
                self.scroll_key(key);
            }
        }
    }

    fn abort_key_change(&mut self) {
        self.key_change = None;
        self.key_confirm = None;
        self.open(self.failure_return);
    }

    fn removal_confirm_key(&mut self, key: KeyEvent) {
        let Some(saved_name) = self
            .key_change
            .as_ref()
            .and_then(|view| view.removal.as_ref())
            .map(|target| target.saved_name.clone())
        else {
            self.key_confirm = None;
            return;
        };
        let Some(confirm) = self.key_confirm.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.key_confirm = None,
            KeyCode::Enter => {
                // The name must match exactly, case included.
                if confirm.input.value() == saved_name {
                    self.key_confirm = None;
                    if let Some(target) = self
                        .key_change
                        .as_ref()
                        .and_then(|view| view.removal.clone())
                    {
                        self.requests.push_back(Request::RemoveKey(target));
                    }
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

    /// Reports what removing the old key did. Success goes back to the list, with
    /// what to do next; anything else stays on the screen so it can be tried
    /// again or aborted.
    pub fn key_removal_finished(&mut self, target: &KnownHostsTarget, result: Removal) {
        match result {
            Removal::Removed => {
                self.key_change = None;
                self.open(self.failure_return);
                let again = if self.failure_return == Screen::Keys {
                    "Send the key again"
                } else {
                    "Connect again"
                };
                self.set_status(
                    StatusKind::Info,
                    format!(
                        "Removed the old key of '{}' from your known_hosts; the previous file \
                         is kept as known_hosts.old. {again}: ssh will show the new key and \
                         ask you to accept it.",
                        target.saved_name
                    ),
                );
            }
            Removal::NotFound => self.set_status(
                StatusKind::Warning,
                format!(
                    "ssh-keygen found no entry for '{}' in your known_hosts, so nothing was \
                     removed.",
                    target.saved_name
                ),
            ),
            Removal::Failed(output) => self.set_status(
                StatusKind::Error,
                format!("The old key was not removed. ssh-keygen said: {output}"),
            ),
        }
    }

    // ---- the keys ------------------------------------------------------------

    /// Takes in the keys that were read. The first time this opens the screen;
    /// after a refresh it keeps the same key selected.
    fn keys_loaded(&mut self, snapshot: KeysSnapshot) {
        let mut screen = KeysScreen::new(snapshot, self.keys.as_ref());
        if let Some(name) = self.select_key.take() {
            screen.select_name(&name);
        }
        self.keys = Some(screen);
        if self.screen != Screen::Keys {
            self.open(Screen::Keys);
        }
    }

    fn keys_key(&mut self, key: KeyEvent) {
        let Some(keys) = self.keys.as_mut() else {
            self.open(Screen::List);
            return;
        };
        if keys.generating().is_some() {
            // Typing goes to the form; the list's keys are letters too.
            match keys.generate_key(key) {
                Generation::Stay | Generation::Close => {}
                Generation::Make { name, comment } => {
                    self.requests.push_back(Request::GenerateKey {
                        file_name: name,
                        comment,
                    });
                }
            }
            return;
        }
        if keys.copying().is_some() {
            if let Copying::Send { key, host } = keys.copy_key(key) {
                self.request_copy_key(&key, &host);
            }
            return;
        }
        if keys.confirming().is_some() {
            // A question with two answers: nothing else does anything.
            match key.code {
                KeyCode::Char('y' | 'Y') if Self::is_plain(key) => {
                    if let Some(file_name) = keys.confirm_fix() {
                        self.requests
                            .push_back(Request::FixKeyPermissions { file_name });
                    }
                }
                KeyCode::Char('n' | 'N') | KeyCode::Esc => keys.cancel_fix(),
                _ => {}
            }
            return;
        }
        if !Self::is_plain(key) {
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => keys.move_by(-1),
            KeyCode::Down | KeyCode::Char('j') => keys.move_by(1),
            KeyCode::PageUp => keys.page(false),
            KeyCode::PageDown => keys.page(true),
            KeyCode::Home => keys.first(),
            KeyCode::End => keys.last(),
            KeyCode::Char('f') => match keys.start_fix() {
                FixOutcome::Asked | FixOutcome::NothingSelected => {}
                FixOutcome::Symlink => self.set_status(
                    StatusKind::Info,
                    "This key is a symbolic link, so Bifrost does not change its permissions: \
                     that would change the file it points to. Change them on that file.",
                ),
                FixOutcome::NotNeeded(Permissions::Unchecked) => self.set_status(
                    StatusKind::Info,
                    "Bifrost cannot check the permissions of this key on this system, so it has \
                     nothing to fix.",
                ),
                FixOutcome::NotNeeded(_) => self.set_status(
                    StatusKind::Info,
                    "The permissions of this key are fine: only you can use it.",
                ),
            },
            KeyCode::Char('g') => {
                if keys.snapshot().dir.as_os_str().is_empty() {
                    self.set_status(
                        StatusKind::Info,
                        "Bifrost does not know where your ssh folder is, so it cannot make a key.",
                    );
                } else {
                    keys.start_generate();
                }
            }
            KeyCode::Char('a') => self.add_selected_to_agent(),
            KeyCode::Char('c') => self.start_copy_key(),
            KeyCode::Char('r') => self.requests.push_back(Request::LoadKeys),
            KeyCode::Char('?') => {
                self.help_return = Screen::Keys;
                self.open(Screen::Help);
            }
            KeyCode::Esc => {
                self.keys = None;
                self.open(Screen::List);
            }
            KeyCode::Char('q') => self.quit = true,
            _ => {}
        }
    }

    /// Opens the dialog that sends the selected key's public key to a saved host.
    fn start_copy_key(&mut self) {
        let Some(hosts) = self.hosts() else {
            self.set_status(
                StatusKind::Info,
                "The saved hosts could not be read, so there is nowhere to send a key.",
            );
            return;
        };
        // In the order of the host list: favorites first, then by name.
        let choices: Vec<HostChoice> = list::rows(hosts, "")
            .into_iter()
            .map(|row| {
                let host = &hosts.as_slice()[row.index];
                let mut destination = host.hostname.clone();
                if let Some(user) = &host.user {
                    destination = format!("{user}@{destination}");
                }
                if let Some(port) = host.port {
                    destination = format!("{destination}:{port}");
                }
                HostChoice {
                    name: host.name.clone(),
                    destination,
                }
            })
            .collect();
        if choices.is_empty() {
            self.set_status(
                StatusKind::Info,
                "There are no saved hosts to send the key to. Go back with Esc and press a to \
                 add one.",
            );
            return;
        }
        if let Some(keys) = self.keys.as_mut() {
            keys.start_copy(choices);
        }
    }

    /// Asks the event loop to send the public key of `file_name` to the saved
    /// host `host`, with the arguments for that and no others.
    fn request_copy_key(&mut self, file_name: &str, host: &str) {
        let Some(hosts) = self.hosts() else {
            return;
        };
        let Some(saved) = hosts.get(host) else {
            self.set_status(
                StatusKind::Error,
                format!("The host '{host}' is not saved any more."),
            );
            return;
        };
        let built = build_copy_args(saved, hosts)
            .and_then(|args| known_hosts_targets(saved, hosts).map(|known| (args, known)));
        match built {
            Ok((args, known_hosts)) => {
                self.pending_known_hosts.clone_from(&known_hosts);
                self.requests.push_back(Request::CopyKey {
                    file_name: file_name.to_string(),
                    connect: ConnectRequest {
                        name: host.to_string(),
                        args,
                        known_hosts,
                    },
                });
            }
            Err(err) => self.set_status(StatusKind::Error, err.to_string()),
        }
    }

    /// Reports how sending a key ended, once the terminal is back.
    ///
    /// The same judgment as for a connection: ssh's own failures (255) are
    /// explained on the same screens, and a changed host key stops everything on
    /// the blocking screen. What differs is what a normal end means: status 0 is
    /// the key sent, and any other status is the server's command failing.
    fn key_copied(&mut self, file_name: &str, host: &str, result: HandoverResult) {
        self.failure_return = Screen::Keys;
        let outcome = match result {
            HandoverResult::Failed(text) => {
                self.report = None;
                self.set_status(StatusKind::Error, text);
                return;
            }
            HandoverResult::Ran(outcome) => outcome,
        };
        let verdict = classify(&outcome);
        self.report = Some(ConnectionReport {
            name: host.to_string(),
            failure: match verdict {
                Verdict::Failed(kind) => Some(kind),
                _ => None,
            },
            stderr: outcome.stderr.clone(),
        });
        let (kind, text) = match verdict {
            Verdict::Failed(FailureKind::HostKeyChanged) => {
                self.show_key_change(host);
                return;
            }
            Verdict::Failed(_) => {
                self.open(Screen::ConnectError);
                return;
            }
            Verdict::Ended => (
                StatusKind::Info,
                format!(
                    "Sent the public key of '{file_name}' to '{host}'. The server added it to \
                     ~/.ssh/authorized_keys, or it was already there."
                ),
            ),
            Verdict::RemoteStatus(code) => {
                // The server ran the command and it failed, so this is not a
                // connection problem: what it said last is the reason. Raw here,
                // cleaned when drawn.
                let said = String::from_utf8_lossy(&outcome.stderr);
                let last = said.lines().map(str::trim).rfind(|line| !line.is_empty());
                let why = last.map_or_else(String::new, |line| {
                    format!(
                        " It said: {}",
                        line.chars().take(ToolEnd::SAID).collect::<String>()
                    )
                });
                (
                    StatusKind::Error,
                    format!(
                        "'{host}' ran the command that adds the key and it failed (status \
                         {code}), so the key was probably not added.{why}"
                    ),
                )
            }
            Verdict::Cancelled => (
                StatusKind::Info,
                "Sending the key was cancelled.".to_string(),
            ),
            Verdict::ClosedByYou => (
                StatusKind::Warning,
                format!(
                    "The connection to '{host}' was closed, so the key may not have been sent."
                ),
            ),
            Verdict::Signalled(signal) => (
                StatusKind::Warning,
                format!("ssh was stopped by signal {signal}, so the key may not have been sent."),
            ),
        };
        self.set_status(kind, text);
    }

    /// Asks for the selected key to be added to the agent, unless that is bound to
    /// fail for a reason Bifrost can already tell, in which case it says why.
    fn add_selected_to_agent(&mut self) {
        let Some(keys) = self.keys.as_ref() else {
            return;
        };
        let Some(entry) = keys.selected_entry() else {
            return;
        };
        let refusal = if entry.loaded == Some(true) {
            Some("This key is already in the agent.")
        } else if entry.can_fix_permissions() {
            Some(
                "ssh-add refuses a private key that other users can read. Press f to fix its \
                 permissions first.",
            )
        } else if entry.permissions.is_too_open() {
            Some(
                "ssh-add refuses a private key that other users can read, and this one is a \
                 symbolic link, so Bifrost does not change it. Change the permissions of the \
                 file it points to.",
            )
        } else {
            match keys.snapshot().agent {
                AgentState::NotStarted | AgentState::Unreachable => Some(
                    "There is no ssh agent answering in this session to add the key to. The note \
                     at the top says how to start one.",
                ),
                _ => None,
            }
        };
        match refusal {
            Some(text) => self.set_status(StatusKind::Info, text),
            None => {
                let file_name = entry.name.clone();
                self.requests
                    .push_back(Request::AddKeyToAgent { file_name });
            }
        }
    }

    /// Reports how making a key ended, and reads the keys again so that the new
    /// one is listed and selected.
    fn key_generated(&mut self, file_name: &str, result: HandoverResult) {
        match ToolEnd::from(result, "ssh-keygen") {
            ToolEnd::Done => {
                self.set_status(
                    StatusKind::Info,
                    format!("Made the key '{file_name}'. Press a to add it to the agent."),
                );
                self.select_key = Some(file_name.to_string());
                self.requests.push_back(Request::LoadKeys);
            }
            ToolEnd::Cancelled => {
                self.set_status(StatusKind::Info, "Making the key was cancelled.");
                self.requests.push_back(Request::LoadKeys);
            }
            ToolEnd::Failed(why) => {
                self.set_status(
                    StatusKind::Error,
                    format!("Could not make the key '{file_name}': {why}"),
                );
                self.requests.push_back(Request::LoadKeys);
            }
            ToolEnd::NotRun(why) => self.set_status(StatusKind::Error, why),
        }
    }

    /// Reports how adding a key to the agent ended, and reads the keys again so
    /// that the screen shows whether the agent holds it now.
    fn key_added(&mut self, file_name: &str, result: HandoverResult) {
        match ToolEnd::from(result, "ssh-add") {
            ToolEnd::Done => {
                self.set_status(
                    StatusKind::Info,
                    format!("Added '{file_name}' to the agent."),
                );
                self.requests.push_back(Request::LoadKeys);
            }
            ToolEnd::Cancelled => {
                self.set_status(StatusKind::Info, "Adding the key was cancelled.");
                self.requests.push_back(Request::LoadKeys);
            }
            ToolEnd::Failed(why) => {
                self.set_status(
                    StatusKind::Error,
                    format!("Could not add '{file_name}' to the agent: {why}"),
                );
                self.requests.push_back(Request::LoadKeys);
            }
            ToolEnd::NotRun(why) => self.set_status(StatusKind::Error, why),
        }
    }

    /// Reports what changing a key's permissions did, and reads the keys again so
    /// that the screen shows how things are now.
    fn permissions_fixed(&mut self, file_name: &str, result: Result<(), String>) {
        match result {
            Ok(()) => {
                self.set_status(
                    StatusKind::Info,
                    format!(
                        "Changed the permissions of '{file_name}' to 0600, so only you can read \
                         and write it."
                    ),
                );
                self.requests.push_back(Request::LoadKeys);
            }
            Err(why) => self.set_status(
                StatusKind::Error,
                format!("Could not change the permissions of '{file_name}': {why}"),
            ),
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
                self.requests.push_back(Request::Copy(text));
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
    use crate::ssh::connect::Exit;
    use crate::tui::effects::testing::{
        take_connect_request, take_copy_request, take_removal_request,
    };
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
                "move", "connect", "search", "add", "edit", "delete", "favorite", "copy", "keys",
                "warnings", "help", "quit"
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
                "connect",
                "search",
                "add",
                "edit",
                "delete",
                "favorite",
                "copy",
                "keys",
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
            take_copy_request(&mut app).as_deref(),
            Some("ssh -l deploy -p 2222 -- web.example.com")
        );
    }

    #[test]
    fn a_copy_request_is_handed_out_once() {
        let (mut app, _) = app_with(deploy_host(), Vec::new());
        app.handle_key(ch('c'));
        assert!(take_copy_request(&mut app).is_some());
        assert!(take_copy_request(&mut app).is_none());
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
        take_copy_request(&mut app);
        app.handle_key(ch('x'));
        assert!(take_copy_request(&mut app).is_none());
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
        assert!(take_copy_request(&mut app).is_none());
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
            assert!(take_copy_request(&mut app).is_none());
        }
    }

    #[test]
    fn d_and_c_are_typed_letters_while_searching() {
        let mut app = app();
        app.handle_key(ch('/'));
        type_text(&mut app, "dc");
        assert_eq!(app.mode(), ListMode::Search);
        assert!(app.delete().is_none() && app.command().is_none());
        assert!(take_copy_request(&mut app).is_none());
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

    // ---- connecting ------------------------------------------------------

    fn ran(exit: Exit, interrupted: bool) -> HandoverResult {
        HandoverResult::Ran(SshOutcome {
            exit,
            stderr: Vec::new(),
            interrupted,
        })
    }

    #[test]
    fn enter_requests_a_connection_to_the_selected_host() {
        let (mut app, _) = app_with(deploy_host(), Vec::new());
        app.handle_key(press(KeyCode::Down));
        assert_eq!(selected(&app), Some("web"));

        app.handle_key(press(KeyCode::Enter));

        let request = take_connect_request(&mut app).expect("a request");
        assert_eq!(request.name, "web");
        assert_eq!(
            request.args.as_slice(),
            ["-l", "deploy", "-p", "2222", "--", "web.example.com"]
        );
        assert!(take_connect_request(&mut app).is_none(), "handed out once");
        assert_eq!(app.screen(), Screen::List);
        assert!(!app.should_quit());
    }

    #[test]
    fn enter_goes_through_the_jump_chain() {
        let mut client = host("client", false);
        client.proxy_jump = Some("bastion".to_string());
        let (mut app, _) = app_with(hosts(vec![host("bastion", false), client]), Vec::new());
        app.handle_key(press(KeyCode::Down));
        assert_eq!(selected(&app), Some("client"));
        app.handle_key(press(KeyCode::Enter));
        let request = take_connect_request(&mut app).unwrap();
        assert!(request.args.as_slice().contains(&"-J".to_string()));
    }

    #[test]
    fn enter_with_no_host_says_so() {
        let (mut app, _) = app_with(hosts(Vec::new()), Vec::new());
        app.handle_key(press(KeyCode::Enter));
        assert!(take_connect_request(&mut app).is_none());
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert!(status.text.contains("no host to connect to"));
    }

    #[test]
    fn enter_does_not_connect_when_it_means_something_else() {
        // Searching: Enter keeps the filter.
        let mut app = app();
        app.handle_key(ch('/'));
        app.handle_key(press(KeyCode::Enter));
        assert!(take_connect_request(&mut app).is_none());
        assert_eq!(app.mode(), ListMode::Browse);

        // Deleting: Enter confirms (or refuses) the typed name.
        let mut app = app_with(sample(), Vec::new()).0;
        app.handle_key(ch('d'));
        app.handle_key(press(KeyCode::Enter));
        assert!(take_connect_request(&mut app).is_none());

        // The command view: any key closes it. (Showing it queued a copy, which
        // the event loop would have carried out after that key.)
        let mut app = app_with(sample(), Vec::new()).0;
        app.handle_key(ch('c'));
        assert!(take_copy_request(&mut app).is_some());
        app.handle_key(press(KeyCode::Enter));
        assert!(take_connect_request(&mut app).is_none());

        // The help and the warnings pages.
        let mut app = app_with(sample(), vec![Notice::warning("careful")]).0;
        app.handle_key(ch('?'));
        app.handle_key(press(KeyCode::Enter));
        assert!(take_connect_request(&mut app).is_none());
        assert_eq!(app.screen(), Screen::Help);

        // Without hosts there is nothing to connect to.
        let mut app = unavailable();
        app.handle_key(press(KeyCode::Enter));
        assert!(take_connect_request(&mut app).is_none());
    }

    #[test]
    fn what_is_not_a_failure_is_one_line_on_the_list() {
        let cases = [
            (
                ran(Exit::Code(0), false),
                StatusKind::Info,
                "Disconnected from 'web'.",
            ),
            (
                ran(Exit::Code(1), false),
                StatusKind::Info,
                "The session on 'web' ended with status 1.",
            ),
            (
                ran(Exit::Signal(9), false),
                StatusKind::Warning,
                "ssh for 'web' was stopped by signal 9.",
            ),
            (
                ran(Exit::Signal(2), false),
                StatusKind::Info,
                "The connection to 'web' was cancelled.",
            ),
            (
                ran(Exit::Code(255), true),
                StatusKind::Info,
                "The connection to 'web' was cancelled.",
            ),
            (
                ran_with(255, "Connection to 192.0.2.1 closed.\r\n"),
                StatusKind::Info,
                "The connection to 'web' was closed.",
            ),
            (
                HandoverResult::Failed("Could not start ssh: no".to_string()),
                StatusKind::Error,
                "Could not start ssh: no",
            ),
        ];
        for (result, kind, text) in cases {
            let mut app = app();
            app.connection_ended("web", result);
            assert_eq!(app.screen(), Screen::List, "{text}");
            let status = app.status().unwrap();
            assert_eq!((status.kind, status.text.as_str()), (kind, text));
        }
    }

    fn ran_with(code: i32, stderr: &str) -> HandoverResult {
        HandoverResult::Ran(SshOutcome {
            exit: Exit::Code(code),
            stderr: stderr.as_bytes().to_vec(),
            interrupted: false,
        })
    }

    const REFUSED: &str = "ssh: connect to host 192.0.2.1 port 22: Connection refused\r\n";

    /// An app that has just seen a connection to `web` fail with `stderr`.
    fn app_after_failure(stderr: &str) -> App {
        let mut app = app();
        app.connection_ended("web", ran_with(255, stderr));
        app
    }

    #[test]
    fn a_failure_opens_the_error_screen_and_keeps_what_ssh_printed() {
        let mut app = app();
        app.connection_ended("web", ran_with(255, REFUSED));

        assert_eq!(app.screen(), Screen::ConnectError);
        assert!(app.status().is_none(), "the screen says it, not a status");
        let report = app.report().unwrap();
        assert_eq!(report.name, "web");
        assert_eq!(report.failure, Some(FailureKind::ConnectionRefused));
        assert_eq!(report.stderr, REFUSED.as_bytes());
    }

    #[test]
    fn a_remote_exit_status_is_not_a_failure_even_with_error_text_on_stderr() {
        let mut app = app();
        app.connection_ended("web", ran_with(1, REFUSED));
        assert_eq!(app.screen(), Screen::List);
        assert_eq!(app.report().unwrap().failure, None);
        assert!(!app.report().unwrap().stderr.is_empty(), "still viewable");
    }

    #[test]
    fn the_error_screen_goes_back_with_enter_or_esc_and_o_reads_the_output() {
        for back in [KeyCode::Enter, KeyCode::Esc] {
            let mut app = app();
            app.connection_ended("web", ran_with(255, REFUSED));
            app.handle_key(press(back));
            assert_eq!(app.screen(), Screen::List);
            assert!(!app.should_quit());
        }

        let mut app = app();
        app.connection_ended("web", ran_with(255, REFUSED));
        app.handle_key(ch('o'));
        assert_eq!(app.screen(), Screen::SshOutput);
        // Back goes to where it came from: the error, not the list.
        app.handle_key(ch('o'));
        assert_eq!(app.screen(), Screen::ConnectError);
        app.handle_key(ch('o'));
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::ConnectError);
        app.handle_key(ch('o'));
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.screen(), Screen::ConnectError);
    }

    #[test]
    fn q_quits_from_both_new_screens_and_ctrl_c_too() {
        let mut on_error = app_after_failure(REFUSED);
        on_error.handle_key(ch('q'));
        assert!(on_error.should_quit());

        let mut on_output = app_after_failure(REFUSED);
        on_output.handle_key(ch('o'));
        on_output.handle_key(ch('q'));
        assert!(on_output.should_quit());

        let mut ctrl_c = app_after_failure(REFUSED);
        ctrl_c.handle_key(ch('o'));
        ctrl_c.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(ctrl_c.should_quit());
    }

    #[test]
    fn o_on_the_list_reads_the_output_of_the_last_connection() {
        let mut app = app();
        app.connection_ended("web", ran_with(0, "Warning: Permanently added 'x'.\r\n"));
        assert_eq!(app.screen(), Screen::List);

        app.handle_key(ch('o'));
        assert_eq!(app.screen(), Screen::SshOutput);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::List, "back to the list it came from");
        assert!(!app.should_quit());
    }

    #[test]
    fn o_with_nothing_to_show_says_so_and_stays() {
        // Never connected.
        let mut app = app();
        app.handle_key(ch('o'));
        assert_eq!(app.screen(), Screen::List);
        assert!(app.status().unwrap().text.contains("no ssh output"));

        // Connected, but ssh printed nothing.
        let mut quiet = self::app();
        quiet.connection_ended("web", ran(Exit::Code(0), false));
        quiet.handle_key(ch('o'));
        assert_eq!(quiet.screen(), Screen::List);
        assert!(quiet.status().unwrap().text.contains("no ssh output"));
    }

    #[test]
    fn a_connection_that_could_not_start_forgets_the_previous_output() {
        let mut app = app();
        app.connection_ended("web", ran_with(0, "old output\r\n"));
        app.connection_ended("web", HandoverResult::Failed("no ssh".to_string()));
        assert!(app.report().is_none(), "the output was of another run");
    }

    #[test]
    fn the_new_screens_scroll_and_reopening_starts_at_the_top() {
        let long: String = (0..60).map(|n| format!("line {n}\r\n")).collect();
        let mut app = app();
        app.connection_ended("web", ran_with(255, &long));
        app.handle_key(ch('o'));
        app.apply_metrics(Metrics {
            max_scroll: 40,
            ..Metrics::default()
        });
        for _ in 0..5 {
            app.handle_key(ch('j'));
        }
        assert_eq!(app.scroll(), 5);
        app.handle_key(ch('o'));
        app.handle_key(ch('o'));
        assert_eq!(app.scroll(), 0, "opened again from the top");
    }

    #[test]
    fn the_footer_of_each_new_screen_lists_its_keys() {
        let mut app = app();
        app.connection_ended("web", ran_with(255, REFUSED));
        assert_eq!(labels(&app), ["scroll", "ssh output", "back", "quit"]);
        app.handle_key(ch('o'));
        assert_eq!(labels(&app), ["scroll", "back", "quit"]);

        // Nothing to read: no offer to.
        let silent = app_after_failure("");
        assert_eq!(silent.screen(), Screen::ConnectError);
        assert_eq!(labels(&silent), ["scroll", "back", "quit"]);
    }

    #[test]
    fn the_list_offers_o_only_when_there_is_output() {
        let mut app = app();
        assert!(!labels(&app).contains(&"ssh output"));
        app.connection_ended("web", ran_with(0, "something\r\n"));
        assert!(labels(&app).contains(&"ssh output"));
    }

    #[test]
    fn the_message_goes_away_with_the_next_key() {
        let mut app = app();
        app.connection_ended("web", ran(Exit::Code(0), false));
        assert!(app.status().is_some());
        app.handle_key(ch('j'));
        assert!(app.status().is_none());
    }

    // ---- a changed host key ----------------------------------------------

    const DEFAULT_KNOWN_HOSTS: &str = "/home/dev/.ssh/known_hosts";
    const FINGERPRINT: &str = "SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// What ssh prints for a changed key of `host`, whose old key is in `file`.
    fn changed_key_output(host: &str, file: &str) -> String {
        format!(
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n\
             The fingerprint for the ED25519 key sent by the remote host is\r\n\
             {FINGERPRINT}.\r\n\
             Offending ED25519 key in {file}:12\r\n\
             Host key for {host} has changed and you have requested strict checking.\r\n\
             Host key verification failed.\r\n"
        )
    }

    /// An app that asked to connect to the selected host (`backup`) and was told
    /// its key had changed, with `known_hosts` as the file the output names.
    fn app_with_changed_key(hosts: Hosts, host: &str, file: &str) -> App {
        let mut app = app_with(hosts, Vec::new()).0;
        app.set_known_hosts_file(Some(PathBuf::from(DEFAULT_KNOWN_HOSTS)));
        app.handle_key(press(KeyCode::Enter));
        let request = take_connect_request(&mut app).expect("a request");
        app.connection_ended(
            &request.name,
            ran_with(255, &changed_key_output(host, file)),
        );
        app
    }

    fn removable_key_change() -> App {
        app_with_changed_key(sample(), "backup.example.com", DEFAULT_KNOWN_HOSTS)
    }

    fn type_name(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_key(ch(c));
        }
    }

    #[test]
    fn a_changed_key_opens_the_blocking_screen_with_what_ssh_reported() {
        let app = removable_key_change();
        assert_eq!(app.screen(), Screen::HostKeyChanged);
        assert!(app.status().is_none());
        let view = app.key_change().unwrap();
        assert_eq!(view.name, "backup");
        assert_eq!(view.key_type.as_deref(), Some("ED25519"));
        assert_eq!(view.fingerprint.as_deref(), Some(FINGERPRINT));
        assert_eq!(view.file.as_deref(), Some(DEFAULT_KNOWN_HOSTS));
        assert_eq!(view.line, Some(12));
        let target = view.removal.as_ref().expect("removable");
        assert_eq!(target.entry, "backup.example.com");
        assert_eq!(target.saved_name, "backup");
        assert!(app.report().is_some(), "ssh's output is kept");
    }

    #[test]
    fn a_rejected_key_is_not_this_screen() {
        let mut app = app();
        app.handle_key(press(KeyCode::Enter));
        take_connect_request(&mut app);
        app.connection_ended("backup", ran_with(255, "Host key verification failed.\r\n"));
        assert_eq!(app.screen(), Screen::ConnectError);
        assert!(app.key_change().is_none());
    }

    #[test]
    fn removal_is_offered_only_when_ssh_s_words_match_the_connection() {
        // A host Bifrost did not connect through: what a server could print.
        let forged = app_with_changed_key(sample(), "other.example.com", DEFAULT_KNOWN_HOSTS);
        // A file Bifrost does not edit.
        let elsewhere =
            app_with_changed_key(sample(), "backup.example.com", "/etc/ssh/ssh_known_hosts");
        // A file that is not the one ssh-keygen edits by default.
        let authorized = app_with_changed_key(
            sample(),
            "backup.example.com",
            "/home/dev/.ssh/authorized_keys",
        );
        for (what, app) in [
            ("host", forged),
            ("file", elsewhere),
            ("authorized", authorized),
        ] {
            assert_eq!(app.screen(), Screen::HostKeyChanged, "{what}");
            assert!(app.key_change().unwrap().removal.is_none(), "{what}");
        }

        // The default file is not known: nothing is offered.
        let mut unknown = app_with(sample(), Vec::new()).0;
        unknown.handle_key(press(KeyCode::Enter));
        let request = take_connect_request(&mut unknown).unwrap();
        unknown.connection_ended(
            &request.name,
            ran_with(
                255,
                &changed_key_output("backup.example.com", DEFAULT_KNOWN_HOSTS),
            ),
        );
        assert!(unknown.key_change().unwrap().removal.is_none());

        // Details ssh did not give.
        let mut bare = app_with(sample(), Vec::new()).0;
        bare.set_known_hosts_file(Some(PathBuf::from(DEFAULT_KNOWN_HOSTS)));
        bare.handle_key(press(KeyCode::Enter));
        take_connect_request(&mut bare);
        bare.connection_ended(
            "backup",
            ran_with(
                255,
                "REMOTE HOST IDENTIFICATION HAS CHANGED!\r\nHost key verification failed.\r\n",
            ),
        );
        assert_eq!(bare.screen(), Screen::HostKeyChanged);
        assert!(bare.key_change().unwrap().removal.is_none());
    }

    #[test]
    fn a_jump_host_s_changed_key_asks_for_the_jump_host_s_name() {
        let mut client = host("client", false);
        client.proxy_jump = Some("bastion".to_string());
        let hosts = hosts(vec![host("bastion", false), client]);
        let mut app = app_with(hosts, Vec::new()).0;
        app.set_known_hosts_file(Some(PathBuf::from(DEFAULT_KNOWN_HOSTS)));
        app.handle_key(press(KeyCode::Down)); // bastion, client: the client
        assert_eq!(selected(&app), Some("client"));
        app.handle_key(press(KeyCode::Enter));
        let request = take_connect_request(&mut app).unwrap();
        app.connection_ended(
            &request.name,
            ran_with(
                255,
                &changed_key_output("bastion.example.com", DEFAULT_KNOWN_HOSTS),
            ),
        );

        let view = app.key_change().unwrap();
        assert_eq!(view.name, "client");
        assert_eq!(view.removal.as_ref().unwrap().saved_name, "bastion");
        app.handle_key(ch('r'));
        type_name(&mut app, "client");
        app.handle_key(press(KeyCode::Enter));
        assert!(
            take_removal_request(&mut app).is_none(),
            "the client's name is not it"
        );
        for _ in 0..6 {
            app.handle_key(press(KeyCode::Backspace));
        }
        type_name(&mut app, "bastion");
        app.handle_key(press(KeyCode::Enter));
        let target = take_removal_request(&mut app).expect("confirmed");
        assert_eq!(target.entry, "bastion.example.com");
    }

    #[test]
    fn enter_and_esc_abort_and_nothing_is_removed() {
        for abort in [KeyCode::Enter, KeyCode::Esc] {
            let mut app = removable_key_change();
            app.handle_key(press(abort));
            assert_eq!(app.screen(), Screen::List);
            assert!(app.key_change().is_none());
            assert!(take_removal_request(&mut app).is_none());
            assert!(!app.should_quit());
        }
    }

    #[test]
    fn no_other_key_does_anything_on_the_blocking_screen() {
        for key in ['q', '?', 'e', 'a', 'f', 'c', 'w', '/', 'x', 'y', 't', ' '] {
            let mut app = removable_key_change();
            app.handle_key(ch(key));
            assert_eq!(app.screen(), Screen::HostKeyChanged, "{key:?}");
            assert!(!app.should_quit(), "{key:?}");
            assert!(app.key_confirm().is_none(), "{key:?}");
            assert!(take_removal_request(&mut app).is_none(), "{key:?}");
            assert!(take_connect_request(&mut app).is_none(), "{key:?}");
            assert!(take_copy_request(&mut app).is_none(), "{key:?}");
        }
        // Keys with modifiers do not act as their plain letter.
        for key in [
            with(KeyCode::Char('r'), KeyModifiers::ALT),
            with(KeyCode::Char('d'), KeyModifiers::ALT),
        ] {
            let mut app = removable_key_change();
            app.handle_key(key);
            assert_eq!(app.screen(), Screen::HostKeyChanged);
            assert!(app.key_confirm().is_none());
        }
    }

    #[test]
    fn ctrl_c_still_quits_from_the_blocking_screen_and_from_the_confirmation() {
        let mut app = removable_key_change();
        app.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit());

        let mut app = removable_key_change();
        app.handle_key(ch('r'));
        app.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit());
        assert!(take_removal_request(&mut app).is_none());
    }

    #[test]
    fn scrolling_is_allowed_on_the_blocking_screen() {
        let mut app = removable_key_change();
        app.apply_metrics(Metrics {
            max_scroll: 10,
            ..Metrics::default()
        });
        app.handle_key(ch('j'));
        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.scroll(), 2);
        app.handle_key(ch('k'));
        assert_eq!(app.scroll(), 1);
        assert_eq!(app.screen(), Screen::HostKeyChanged);
    }

    #[test]
    fn d_reads_the_output_and_comes_back_to_the_blocking_screen() {
        let mut app = removable_key_change();
        app.handle_key(ch('d'));
        assert_eq!(app.screen(), Screen::SshOutput);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::HostKeyChanged, "not the list");
        assert!(app.key_change().is_some());
    }

    #[test]
    fn r_asks_for_the_name_and_only_the_exact_name_removes() {
        let mut app = removable_key_change();
        app.handle_key(ch('r'));
        assert!(app.key_confirm().is_some());

        // Letters are typed, not commands.
        type_name(&mut app, "q?d");
        assert_eq!(app.screen(), Screen::HostKeyChanged);
        assert!(!app.should_quit());
        assert_eq!(app.key_confirm().unwrap().input.value(), "q?d");
        for _ in 0..3 {
            app.handle_key(press(KeyCode::Backspace));
        }

        // Wrong: case counts, and so does a part of it.
        for wrong in ["Backup", "back", "backup ", ""] {
            type_name(&mut app, wrong);
            app.handle_key(press(KeyCode::Enter));
            assert!(app.key_confirm().unwrap().mismatch, "{wrong:?}");
            assert!(take_removal_request(&mut app).is_none(), "{wrong:?}");
            for _ in 0..wrong.len() {
                app.handle_key(press(KeyCode::Backspace));
            }
        }

        type_name(&mut app, "backup");
        assert!(
            !app.key_confirm().unwrap().mismatch,
            "typing clears the complaint"
        );
        app.handle_key(press(KeyCode::Enter));
        assert!(app.key_confirm().is_none());
        let target = take_removal_request(&mut app).expect("confirmed");
        assert_eq!(target.entry, "backup.example.com");
        assert!(take_removal_request(&mut app).is_none(), "handed out once");
    }

    #[test]
    fn esc_cancels_the_confirmation_and_stays_on_the_screen() {
        let mut app = removable_key_change();
        app.handle_key(ch('r'));
        type_name(&mut app, "backup");
        app.handle_key(press(KeyCode::Esc));
        assert!(app.key_confirm().is_none());
        assert_eq!(app.screen(), Screen::HostKeyChanged);
        assert!(take_removal_request(&mut app).is_none());
        // Asking again starts empty.
        app.handle_key(ch('r'));
        assert_eq!(app.key_confirm().unwrap().input.value(), "");
    }

    #[test]
    fn r_does_nothing_when_no_removal_is_offered() {
        let mut app = app_with_changed_key(sample(), "other.example.com", DEFAULT_KNOWN_HOSTS);
        app.handle_key(ch('r'));
        assert!(app.key_confirm().is_none());
        assert!(take_removal_request(&mut app).is_none());
        assert_eq!(app.screen(), Screen::HostKeyChanged);
    }

    fn target() -> KnownHostsTarget {
        KnownHostsTarget {
            entry: "backup.example.com".to_string(),
            saved_name: "backup".to_string(),
        }
    }

    #[test]
    fn a_removal_goes_back_to_the_list_and_says_what_to_do_next() {
        let mut app = removable_key_change();
        app.key_removal_finished(&target(), Removal::Removed);
        assert_eq!(app.screen(), Screen::List);
        assert!(app.key_change().is_none());
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert!(status.text.contains("known_hosts.old"), "{}", status.text);
        assert!(status.text.contains("Connect again"), "{}", status.text);
    }

    #[test]
    fn a_removal_that_did_not_happen_stays_on_the_screen_and_can_be_retried() {
        for result in [
            Removal::NotFound,
            Removal::Failed("Cannot stat known_hosts".to_string()),
        ] {
            let mut app = removable_key_change();
            app.handle_key(ch('r'));
            type_name(&mut app, "backup");
            app.handle_key(press(KeyCode::Enter));
            take_removal_request(&mut app).unwrap();
            app.key_removal_finished(&target(), result.clone());

            assert_eq!(app.screen(), Screen::HostKeyChanged, "{result:?}");
            let status = app.status().unwrap();
            assert_ne!(status.kind, StatusKind::Info, "{result:?}");
            app.handle_key(ch('r'));
            assert!(app.key_confirm().is_some(), "can ask again");
        }
    }

    #[test]
    fn the_footer_of_the_blocking_screen_puts_abort_first() {
        let mut app = removable_key_change();
        assert_eq!(
            labels(&app),
            ["abort (safe)", "ssh output", "remove old key...", "scroll"]
        );
        app.handle_key(ch('r'));
        assert_eq!(labels(&app), ["the host name", "remove", "cancel"]);
        app.handle_key(press(KeyCode::Esc));

        let no_removal = app_with_changed_key(sample(), "other.example.com", DEFAULT_KNOWN_HOSTS);
        assert_eq!(
            labels(&no_removal),
            ["abort (safe)", "ssh output", "scroll"]
        );
    }

    #[test]
    fn a_new_connection_forgets_the_previous_known_hosts_names() {
        // A later failure must be judged against the connection it belongs to.
        let mut app = app_with(sample(), Vec::new()).0;
        app.set_known_hosts_file(Some(PathBuf::from(DEFAULT_KNOWN_HOSTS)));
        app.handle_key(press(KeyCode::Enter)); // backup
        take_connect_request(&mut app);
        app.connection_ended("backup", ran(Exit::Code(0), false));
        app.handle_key(press(KeyCode::Down)); // db
        app.handle_key(press(KeyCode::Enter));
        let request = take_connect_request(&mut app).unwrap();
        assert_eq!(request.name, "db");
        // ssh names backup: not what this connection went to.
        app.connection_ended(
            "db",
            ran_with(
                255,
                &changed_key_output("backup.example.com", DEFAULT_KNOWN_HOSTS),
            ),
        );
        assert!(app.key_change().unwrap().removal.is_none());
    }

    #[test]
    fn the_request_carries_the_known_hosts_names_of_the_chain() {
        let mut client = host("client", false);
        client.proxy_jump = Some("bastion".to_string());
        client.port = Some(2222);
        let mut app = app_with(hosts(vec![host("bastion", false), client]), Vec::new()).0;
        app.handle_key(press(KeyCode::Down));
        app.handle_key(press(KeyCode::Enter));
        let request = take_connect_request(&mut app).unwrap();
        let entries: Vec<_> = request
            .known_hosts
            .iter()
            .map(|t| t.entry.as_str())
            .collect();
        assert_eq!(
            entries,
            ["[client.example.com]:2222", "bastion.example.com"]
        );
    }

    // ---- the queue of requests -----------------------------------------------

    #[test]
    fn requests_are_handed_out_oldest_first_and_once() {
        let mut app = removable_key_change_after_list();
        // `c` queues a copy; Enter closes the command view; Enter again connects.
        app.handle_key(ch('c'));
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(press(KeyCode::Enter));

        assert!(matches!(app.take_request(), Some(Request::Copy(_))));
        assert!(matches!(app.take_request(), Some(Request::Connect(_))));
        assert!(app.take_request().is_none());
    }

    /// An app back on the list, with nothing queued.
    fn removable_key_change_after_list() -> App {
        let mut app = removable_key_change();
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::List);
        app
    }

    #[test]
    fn a_response_of_the_wrong_kind_is_reported_and_changes_nothing_else() {
        let mut app = app();
        let request = Request::Copy("ssh -- web".to_string());
        app.handle_response(&request, Response::KeyRemoved(Removal::Removed));
        let status = app.status().expect("the mistake is shown");
        assert_eq!(status.kind, StatusKind::Error);
        assert!(
            status.text.contains("unexpected response"),
            "{}",
            status.text
        );
        assert_eq!(app.screen(), Screen::List);
    }

    #[test]
    fn responses_reach_the_matching_handler() {
        let mut app = app();
        let connect = Request::Connect(ConnectRequest {
            name: "web".to_string(),
            args: build_args(&host("web", false), &sample()).unwrap(),
            known_hosts: Vec::new(),
        });
        app.handle_response(&connect, Response::Connected(ran(Exit::Code(0), false)));
        assert_eq!(app.status().unwrap().text, "Disconnected from 'web'.");

        // A copy has nothing to report.
        let mut quiet = self::app();
        quiet.handle_response(&Request::Copy("x".to_string()), Response::Copied);
        assert!(quiet.status().is_none());
    }

    // ---- the keys screen -----------------------------------------------------

    use crate::tui::keys::testing::{entry as key_entry, snapshot as key_snapshot};

    fn open_keys(keys: Vec<crate::ssh::keys::KeyEntry>) -> App {
        let mut app = app();
        app.handle_key(ch('K'));
        let request = app.take_request().expect("the keys are asked for");
        app.handle_response(&request, Response::Keys(key_snapshot(keys)));
        app
    }

    fn too_open(name: &str) -> crate::ssh::keys::KeyEntry {
        key_entry(name, Permissions::TooOpen { mode: 0o644 }, false)
    }

    fn fine_key(name: &str) -> crate::ssh::keys::KeyEntry {
        key_entry(name, Permissions::Fine, false)
    }

    #[test]
    fn a_capital_k_asks_for_the_keys_and_the_screen_opens_when_they_arrive() {
        let mut app = app();
        app.handle_key(ch('K'));
        assert_eq!(app.screen(), Screen::List, "nothing to show yet");
        let request = app.take_request().unwrap();
        assert_eq!(request, Request::LoadKeys);

        app.handle_response(&request, Response::Keys(key_snapshot(vec![fine_key("a")])));
        assert_eq!(app.screen(), Screen::Keys);
        assert_eq!(app.keys().unwrap().snapshot().keys.len(), 1);
    }

    #[test]
    fn a_lower_case_k_still_moves_the_selection_up_on_the_list() {
        let mut app = app();
        app.handle_key(press(KeyCode::Down));
        let moved = selected(&app).map(str::to_string);
        app.handle_key(ch('k'));
        assert_ne!(selected(&app).map(str::to_string), moved);
        assert!(app.take_request().is_none(), "k is not the keys key");
    }

    #[test]
    fn the_keys_key_is_not_offered_without_hosts_to_show_and_not_with_modifiers() {
        let mut broken = unavailable();
        broken.handle_key(ch('K'));
        assert!(broken.take_request().is_none());

        let mut app = app();
        app.handle_key(with(KeyCode::Char('K'), KeyModifiers::CONTROL));
        app.handle_key(with(KeyCode::Char('K'), KeyModifiers::ALT));
        assert!(app.take_request().is_none());
    }

    #[test]
    fn the_selection_moves_with_the_usual_keys_and_stays_inside_the_list() {
        let mut app = open_keys(vec![fine_key("a"), fine_key("b"), fine_key("c")]);
        let at = |app: &App| app.keys().unwrap().selected();
        app.handle_key(ch('j'));
        app.handle_key(press(KeyCode::Down));
        app.handle_key(press(KeyCode::Down));
        assert_eq!(at(&app), 2);
        app.handle_key(ch('k'));
        assert_eq!(at(&app), 1);
        app.handle_key(press(KeyCode::Home));
        assert_eq!(at(&app), 0);
        app.handle_key(press(KeyCode::End));
        assert_eq!(at(&app), 2);
        app.handle_key(press(KeyCode::Up));
        app.handle_key(press(KeyCode::PageUp));
        assert_eq!(at(&app), 0);
        app.handle_key(press(KeyCode::PageDown));
        assert!(at(&app) > 0);
    }

    #[test]
    fn f_on_a_key_that_is_too_open_asks_and_only_y_changes_it() {
        let mut app = open_keys(vec![fine_key("a"), too_open("b")]);
        app.handle_key(ch('j'));
        assert_eq!(
            labels(&app),
            [
                "move",
                "fix permissions",
                "new key",
                "add to agent",
                "send to host",
                "refresh",
                "help",
                "back",
                "quit"
            ]
        );

        app.handle_key(ch('f'));
        assert_eq!(app.keys().unwrap().confirming(), Some("b"));
        assert_eq!(labels(&app), ["change to 0600", "cancel"]);
        assert!(app.take_request().is_none(), "asking is not doing");

        app.handle_key(ch('y'));
        assert_eq!(
            app.take_request(),
            Some(Request::FixKeyPermissions {
                file_name: "b".to_string()
            })
        );
        assert!(app.keys().unwrap().confirming().is_none());
    }

    #[test]
    fn n_and_esc_cancel_and_nothing_is_changed() {
        for answer in [ch('n'), ch('N'), press(KeyCode::Esc)] {
            let mut app = open_keys(vec![too_open("a")]);
            app.handle_key(ch('f'));
            app.handle_key(answer);
            assert!(app.keys().unwrap().confirming().is_none());
            assert!(app.take_request().is_none());
            assert_eq!(app.screen(), Screen::Keys, "Esc answered the question only");
        }
    }

    #[test]
    fn while_the_question_shows_nothing_else_does_anything() {
        let mut app = open_keys(vec![too_open("a"), fine_key("b")]);
        app.handle_key(ch('f'));
        for key in [
            ch('q'),
            ch('j'),
            ch('r'),
            ch('?'),
            ch('f'),
            press(KeyCode::Enter),
            press(KeyCode::Down),
        ] {
            app.handle_key(key);
            assert_eq!(app.keys().unwrap().confirming(), Some("a"), "{key:?}");
            assert!(!app.should_quit());
            assert!(app.take_request().is_none());
        }
        assert_eq!(app.keys().unwrap().selected(), 0);
        // Only a plain y confirms.
        app.handle_key(with(KeyCode::Char('y'), KeyModifiers::ALT));
        assert!(app.take_request().is_none());
    }

    #[test]
    fn ctrl_c_quits_from_the_keys_screen_and_from_the_question() {
        let mut app = open_keys(vec![too_open("a")]);
        app.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit());

        let mut asking = open_keys(vec![too_open("a")]);
        asking.handle_key(ch('f'));
        asking.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(asking.should_quit());
        assert!(asking.take_request().is_none());
    }

    #[test]
    fn f_says_why_when_there_is_nothing_to_fix_or_it_is_not_allowed() {
        let mut app = open_keys(vec![
            fine_key("fine"),
            key_entry("link", Permissions::TooOpen { mode: 0o644 }, true),
            key_entry("unchecked", Permissions::Unchecked, false),
        ]);
        let says = |app: &mut App, expected: &str| {
            app.handle_key(ch('f'));
            let status = app.status().expect("a message").text.clone();
            assert!(status.contains(expected), "{status}");
            assert!(app.keys().unwrap().confirming().is_none());
            assert!(app.take_request().is_none());
        };
        says(&mut app, "permissions of this key are fine");
        app.handle_key(ch('j'));
        says(&mut app, "symbolic link");
        app.handle_key(ch('j'));
        says(&mut app, "cannot check the permissions");
    }

    #[test]
    fn f_with_no_keys_does_nothing() {
        let mut app = open_keys(Vec::new());
        app.handle_key(ch('f'));
        assert!(app.status().is_none());
        assert!(app.take_request().is_none());
    }

    #[test]
    fn the_fix_footer_is_offered_only_for_a_key_that_can_be_fixed() {
        let mut app = open_keys(vec![
            fine_key("fine"),
            key_entry("link", Permissions::TooOpen { mode: 0o644 }, true),
            too_open("open"),
        ]);
        assert!(!labels(&app).contains(&"fix permissions"));
        app.handle_key(ch('j'));
        assert!(!labels(&app).contains(&"fix permissions"), "not for a link");
        app.handle_key(ch('j'));
        assert!(labels(&app).contains(&"fix permissions"));
    }

    #[test]
    fn a_fixed_key_is_reported_and_the_keys_are_read_again() {
        let mut app = open_keys(vec![too_open("a b")]);
        let request = Request::FixKeyPermissions {
            file_name: "a b".to_string(),
        };
        app.handle_response(&request, Response::PermissionsFixed(Ok(())));
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert!(
            status.text.contains("'a b'") && status.text.contains("0600"),
            "{}",
            status.text
        );
        assert_eq!(app.take_request(), Some(Request::LoadKeys));
    }

    #[test]
    fn a_fix_that_failed_says_why_and_reads_nothing_again() {
        let mut app = open_keys(vec![too_open("a")]);
        let request = Request::FixKeyPermissions {
            file_name: "a".to_string(),
        };
        app.handle_response(
            &request,
            Response::PermissionsFixed(Err("Operation not permitted".to_string())),
        );
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert!(
            status.text.contains("Operation not permitted"),
            "{}",
            status.text
        );
        assert!(app.take_request().is_none());
        assert_eq!(app.screen(), Screen::Keys);
    }

    #[test]
    fn r_reads_the_keys_again_and_keeps_the_selected_key() {
        let mut app = open_keys(vec![fine_key("a"), fine_key("b"), fine_key("c")]);
        app.handle_key(ch('j'));
        app.handle_key(ch('j'));
        app.handle_key(ch('r'));
        let request = app.take_request().unwrap();
        assert_eq!(request, Request::LoadKeys);
        app.handle_response(
            &request,
            Response::Keys(key_snapshot(vec![
                fine_key("new"),
                fine_key("a"),
                fine_key("b"),
                fine_key("c"),
            ])),
        );
        assert_eq!(app.screen(), Screen::Keys, "still there, not reopened");
        assert_eq!(app.keys().unwrap().selected_entry().unwrap().name, "c");
    }

    #[test]
    fn esc_goes_back_to_the_list_and_q_quits() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::List);
        assert!(app.keys().is_none());
        assert!(!app.should_quit());

        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn the_help_opened_from_the_keys_comes_back_to_the_keys() {
        let mut app = open_keys(vec![fine_key("a"), fine_key("b")]);
        app.handle_key(ch('j'));
        app.handle_key(ch('?'));
        assert_eq!(app.screen(), Screen::Help);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::Keys);
        assert_eq!(app.keys().unwrap().selected(), 1, "where it was");

        // And the help opened from the list still goes back to the list.
        let mut from_list = self::app();
        from_list.handle_key(ch('?'));
        from_list.handle_key(ch('?'));
        assert_eq!(from_list.screen(), Screen::List);
    }

    #[test]
    fn keys_with_modifiers_do_not_act_as_their_plain_letter() {
        let mut app = open_keys(vec![too_open("a")]);
        for key in [
            with(KeyCode::Char('f'), KeyModifiers::ALT),
            with(KeyCode::Char('r'), KeyModifiers::ALT),
            with(KeyCode::Char('q'), KeyModifiers::CONTROL),
        ] {
            app.handle_key(key);
        }
        assert!(app.keys().unwrap().confirming().is_none());
        assert!(app.take_request().is_none());
        assert!(!app.should_quit());
    }

    #[test]
    fn the_help_and_the_footer_cover_the_keys_screen() {
        let documented: Vec<&str> = HELP
            .iter()
            .flat_map(|section| section.rows)
            .flat_map(|row| tokens(row.keys))
            .collect();
        let mut app = open_keys(vec![too_open("a")]);
        let mut seen = app.footer_hints();
        app.handle_key(ch('f'));
        seen.extend(app.footer_hints());
        app.handle_key(press(KeyCode::Esc));
        app.handle_key(ch('g'));
        seen.extend(app.footer_hints());
        for hint in seen {
            for key in tokens(hint.keys) {
                assert!(documented.contains(&key), "{key:?} is not in the help");
            }
        }
        assert!(documented.contains(&"K"), "the key that opens it");
    }

    #[test]
    fn the_host_list_footer_offers_the_keys() {
        assert!(labels(&app()).contains(&"keys"));
    }

    // ---- making a key and adding it to the agent -------------------------------

    fn open_keys_with_agent(keys: Vec<crate::ssh::keys::KeyEntry>, agent: AgentState) -> App {
        let mut app = app();
        app.handle_key(ch('K'));
        let request = app.take_request().expect("the keys are asked for");
        let mut snapshot = key_snapshot(keys);
        snapshot.agent = agent;
        app.handle_response(&request, Response::Keys(snapshot));
        app
    }

    fn running() -> AgentState {
        AgentState::Running { hashes: Vec::new() }
    }

    /// Empties the field that has the focus.
    fn empty_field(app: &mut App) {
        for _ in 0..100 {
            app.handle_key(press(KeyCode::Backspace));
        }
    }

    fn form_of(app: &App) -> &crate::tui::keys::GenerateForm {
        app.keys().unwrap().generating().expect("the form is open")
    }

    #[test]
    fn g_opens_the_form_with_a_free_name_in_it() {
        let mut app = open_keys(vec![fine_key("id_ed25519")]);
        app.handle_key(ch('g'));
        assert_eq!(form_of(&app).name().value(), "id_ed25519_2");
        assert_eq!(form_of(&app).comment().value(), "");
        assert!(
            app.take_request().is_none(),
            "opening the form asks for nothing"
        );
        assert_eq!(
            labels(&app),
            ["next field", "next / make the key", "cancel"]
        );
    }

    #[test]
    fn while_the_form_is_open_every_key_goes_to_the_form_and_none_to_the_list() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('g'));
        empty_field(&mut app);
        type_text(&mut app, "qjkgarfK?");
        assert_eq!(form_of(&app).name().value(), "qjkgarfK?");
        assert!(!app.should_quit());
        assert_eq!(app.screen(), Screen::Keys);
        assert!(app.take_request().is_none());
    }

    #[test]
    fn enter_goes_to_the_comment_and_then_asks_for_the_key() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('g'));
        empty_field(&mut app);
        type_text(&mut app, "work");
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(
            form_of(&app).focus(),
            crate::tui::keys::GenerateField::Comment
        );
        assert!(
            app.take_request().is_none(),
            "the first Enter only moves on"
        );

        type_text(&mut app, "me on my laptop");
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(
            app.take_request(),
            Some(Request::GenerateKey {
                file_name: "work".to_string(),
                comment: Some("me on my laptop".to_string()),
            })
        );
        assert!(
            app.keys().unwrap().generating().is_none(),
            "the form is over"
        );
        assert!(app.take_request().is_none());
    }

    #[test]
    fn an_empty_comment_is_no_comment() {
        let mut app = open_keys(vec![]);
        app.handle_key(ch('g'));
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(
            app.take_request(),
            Some(Request::GenerateKey {
                file_name: "id_ed25519".to_string(),
                comment: None,
            })
        );
    }

    #[test]
    fn a_name_that_is_not_allowed_is_refused_on_its_field_and_the_edit_clears_the_complaint() {
        for bad in [
            "",
            "two words",
            "-oProxyCommand=x",
            ".hidden",
            "key.pub",
            "config",
            "known_hosts",
            "caf\u{e9}",
            "../up",
            &"x".repeat(65),
        ] {
            let mut app = open_keys(vec![fine_key("a")]);
            app.handle_key(ch('g'));
            empty_field(&mut app);
            type_text(&mut app, bad);
            app.handle_key(press(KeyCode::Enter));
            let form = form_of(&app);
            let (field, message) = form
                .error()
                .unwrap_or_else(|| panic!("{bad:?} was accepted"));
            assert_eq!(field, crate::tui::keys::GenerateField::Name, "{bad:?}");
            assert!(!message.is_empty());
            assert_eq!(
                form.focus(),
                crate::tui::keys::GenerateField::Name,
                "{bad:?}"
            );
            assert!(app.take_request().is_none(), "{bad:?}");

            // Typing on the field is an answer to the complaint.
            app.handle_key(ch('x'));
            assert!(form_of(&app).error().is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_name_that_is_listed_is_refused_whatever_its_case() {
        let mut app = open_keys(vec![fine_key("Work")]);
        app.handle_key(ch('g'));
        empty_field(&mut app);
        type_text(&mut app, "work");
        app.handle_key(press(KeyCode::Enter));
        let (_, message) = form_of(&app).error().expect("refused");
        assert!(message.contains("already a key"), "{message}");
        assert!(app.take_request().is_none());
    }

    #[test]
    fn a_comment_that_is_not_allowed_is_refused_on_the_comment() {
        for bad in [
            " padded".to_string(),
            "padded ".to_string(),
            "x".repeat(101),
            "right-to-left \u{202e}override".to_string(),
        ] {
            let mut app = open_keys(vec![]);
            app.handle_key(ch('g'));
            app.handle_key(press(KeyCode::Enter));
            type_text(&mut app, &bad);
            app.handle_key(press(KeyCode::Enter));
            let (field, _) = form_of(&app)
                .error()
                .unwrap_or_else(|| panic!("{bad:?} was accepted"));
            assert_eq!(field, crate::tui::keys::GenerateField::Comment, "{bad:?}");
            assert!(app.take_request().is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_bad_name_is_still_caught_when_enter_is_pressed_on_the_comment() {
        let mut app = open_keys(vec![]);
        app.handle_key(ch('g'));
        app.handle_key(press(KeyCode::Enter));
        // Back to the name, spoil it, and go straight to the comment and on.
        app.handle_key(press(KeyCode::BackTab));
        app.handle_key(ch(' '));
        app.handle_key(press(KeyCode::Tab));
        app.handle_key(press(KeyCode::Enter));
        let (field, _) = form_of(&app).error().expect("refused");
        assert_eq!(field, crate::tui::keys::GenerateField::Name);
        assert_eq!(form_of(&app).focus(), crate::tui::keys::GenerateField::Name);
        assert!(app.take_request().is_none());
    }

    #[test]
    fn tab_and_the_arrows_switch_fields_and_typing_edits_the_focused_one() {
        let mut app = open_keys(vec![]);
        app.handle_key(ch('g'));
        for key in [press(KeyCode::Tab), press(KeyCode::Down)] {
            let before = form_of(&app).focus();
            app.handle_key(key);
            assert_ne!(form_of(&app).focus(), before, "{key:?}");
        }
        app.handle_key(press(KeyCode::Up));
        assert_eq!(
            form_of(&app).focus(),
            crate::tui::keys::GenerateField::Comment
        );
        type_text(&mut app, "hi");
        assert_eq!(form_of(&app).comment().value(), "hi");
        assert_eq!(form_of(&app).name().value(), "id_ed25519");
    }

    #[test]
    fn esc_closes_the_form_and_asks_for_nothing_and_stays_on_the_keys() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('g'));
        type_text(&mut app, "zzz");
        app.handle_key(press(KeyCode::Esc));
        assert!(app.keys().unwrap().generating().is_none());
        assert_eq!(app.screen(), Screen::Keys);
        assert!(app.take_request().is_none());
        // A form opened again starts fresh.
        app.handle_key(ch('g'));
        assert_eq!(form_of(&app).name().value(), "id_ed25519");
    }

    #[test]
    fn ctrl_c_quits_from_the_form() {
        let mut app = open_keys(vec![]);
        app.handle_key(ch('g'));
        app.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit());
        assert!(app.take_request().is_none());
    }

    #[test]
    fn keys_with_ctrl_or_alt_do_not_type_into_the_form() {
        let mut app = open_keys(vec![]);
        app.handle_key(ch('g'));
        app.handle_key(with(KeyCode::Char('x'), KeyModifiers::CONTROL));
        app.handle_key(with(KeyCode::Char('x'), KeyModifiers::ALT));
        assert_eq!(form_of(&app).name().value(), "id_ed25519");
    }

    #[test]
    fn without_an_ssh_folder_there_is_no_form() {
        let mut app = app();
        app.handle_key(ch('K'));
        let request = app.take_request().unwrap();
        app.handle_response(
            &request,
            Response::Keys(KeysSnapshot::unavailable("no home")),
        );
        app.handle_key(ch('g'));
        assert!(app.keys().unwrap().generating().is_none());
        assert!(app.status().unwrap().text.contains("ssh folder"));
    }

    #[test]
    fn a_asks_for_the_selected_key_to_go_into_the_agent() {
        let mut app = open_keys_with_agent(vec![fine_key("a"), fine_key("b")], running());
        app.handle_key(ch('j'));
        app.handle_key(ch('a'));
        assert_eq!(
            app.take_request(),
            Some(Request::AddKeyToAgent {
                file_name: "b".to_string()
            })
        );
        assert!(app.status().is_none());
    }

    #[test]
    fn a_tries_when_the_agent_could_not_be_told_about() {
        for agent in [
            AgentState::Unavailable("slow".to_string()),
            AgentState::Unknown("odd".to_string()),
        ] {
            let mut app = open_keys_with_agent(vec![fine_key("a")], agent);
            app.handle_key(ch('a'));
            assert!(matches!(
                app.take_request(),
                Some(Request::AddKeyToAgent { .. })
            ));
        }
    }

    #[test]
    fn a_says_why_it_will_not_when_the_attempt_is_bound_to_fail() {
        let mut loaded = fine_key("loaded");
        loaded.loaded = Some(true);
        let mut app = open_keys_with_agent(
            vec![
                loaded,
                too_open("open"),
                key_entry("link", Permissions::TooOpen { mode: 0o644 }, true),
            ],
            running(),
        );
        let says = |app: &mut App, expected: &str| {
            app.handle_key(ch('a'));
            let status = app.status().expect("a message").text.clone();
            assert!(status.contains(expected), "{status}");
            assert!(app.take_request().is_none());
        };
        says(&mut app, "already in the agent");
        app.handle_key(ch('j'));
        says(&mut app, "Press f");
        app.handle_key(ch('j'));
        says(&mut app, "symbolic link");

        for agent in [AgentState::NotStarted, AgentState::Unreachable] {
            let mut app = open_keys_with_agent(vec![fine_key("a")], agent);
            says(&mut app, "no ssh agent");
        }
    }

    #[test]
    fn a_with_no_keys_does_nothing() {
        let mut app = open_keys_with_agent(vec![], running());
        app.handle_key(ch('a'));
        assert!(app.status().is_none());
        assert!(app.take_request().is_none());
    }

    #[test]
    fn the_footer_offers_a_new_key_always_and_adding_only_for_a_key_the_agent_lacks() {
        let mut loaded = fine_key("loaded");
        loaded.loaded = Some(true);
        let mut app = open_keys_with_agent(vec![fine_key("missing"), loaded], running());
        assert!(labels(&app).contains(&"new key"));
        assert!(labels(&app).contains(&"add to agent"));
        app.handle_key(ch('j'));
        assert!(labels(&app).contains(&"new key"));
        assert!(!labels(&app).contains(&"add to agent"));
        assert!(labels(&open_keys(vec![])).contains(&"new key"));
    }

    fn generated(app: &mut App, name: &str, result: HandoverResult) {
        let request = Request::GenerateKey {
            file_name: name.to_string(),
            comment: None,
        };
        app.handle_response(&request, Response::KeyGenerated(result));
    }

    fn added(app: &mut App, name: &str, result: HandoverResult) {
        let request = Request::AddKeyToAgent {
            file_name: name.to_string(),
        };
        app.handle_response(&request, Response::KeyAdded(result));
    }

    #[test]
    fn a_made_key_is_reported_listed_and_selected() {
        let mut app = open_keys(vec![fine_key("a"), fine_key("c")]);
        generated(&mut app, "b", ran(Exit::Code(0), false));
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert!(status.text.contains("'b'") && status.text.contains("Press a"));
        let request = app.take_request().unwrap();
        assert_eq!(request, Request::LoadKeys);

        app.handle_response(
            &request,
            Response::Keys(key_snapshot(vec![
                fine_key("a"),
                fine_key("b"),
                fine_key("c"),
            ])),
        );
        assert_eq!(app.keys().unwrap().selected_entry().unwrap().name, "b");
        // Only once: the next refresh keeps whatever is selected then.
        app.handle_key(ch('j'));
        app.handle_key(ch('r'));
        let request = app.take_request().unwrap();
        app.handle_response(
            &request,
            Response::Keys(key_snapshot(vec![
                fine_key("a"),
                fine_key("b"),
                fine_key("c"),
            ])),
        );
        assert_eq!(app.keys().unwrap().selected_entry().unwrap().name, "c");
    }

    #[test]
    fn a_cancelled_key_is_said_to_be_cancelled_and_the_keys_are_read_again() {
        for result in [ran(Exit::Signal(2), false), ran(Exit::Code(1), true)] {
            let mut app = open_keys(vec![fine_key("a")]);
            generated(&mut app, "b", result);
            let status = app.status().unwrap();
            assert_eq!(status.kind, StatusKind::Info);
            assert!(status.text.contains("cancelled"), "{}", status.text);
            assert_eq!(app.take_request(), Some(Request::LoadKeys));
        }
    }

    #[test]
    fn a_key_that_failed_says_what_the_tool_said_last_and_selects_nothing_new() {
        let mut app = open_keys(vec![fine_key("a"), fine_key("c")]);
        generated(
            &mut app,
            "b",
            ran_with(1, "warning: first\nsomething went wrong\n\n"),
        );
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert!(
            status.text.contains("'b'")
                && status.text.contains("status 1")
                && status.text.contains("something went wrong")
                && !status.text.contains("first"),
            "{}",
            status.text
        );
        let request = app.take_request().unwrap();
        app.handle_response(
            &request,
            Response::Keys(key_snapshot(vec![
                fine_key("a"),
                fine_key("b"),
                fine_key("c"),
            ])),
        );
        assert_eq!(app.keys().unwrap().selected_entry().unwrap().name, "a");
    }

    #[test]
    fn a_failure_without_words_or_stopped_by_a_signal_or_never_started_is_still_plain() {
        let mut app = open_keys(vec![]);
        generated(&mut app, "b", ran_with(3, ""));
        assert!(app.status().unwrap().text.ends_with("status 3."));

        generated(&mut app, "b", ran(Exit::Signal(9), false));
        assert!(app.status().unwrap().text.contains("stopped by signal 9"));

        // Never started: nothing changed, so nothing is read again.
        let mut app = open_keys(vec![]);
        app.take_request();
        generated(
            &mut app,
            "b",
            HandoverResult::Failed("Could not start ssh-keygen: no".to_string()),
        );
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert_eq!(status.text, "Could not start ssh-keygen: no");
        assert!(app.take_request().is_none());
    }

    #[test]
    fn what_a_tool_said_is_cut_to_a_line_of_reasonable_length() {
        let mut app = open_keys(vec![]);
        generated(&mut app, "b", ran_with(1, &"x".repeat(5000)));
        assert!(app.status().unwrap().text.len() < 400);
    }

    #[test]
    fn an_added_key_is_reported_and_the_agent_is_asked_again() {
        let mut app = open_keys_with_agent(vec![fine_key("a")], running());
        added(&mut app, "a", ran(Exit::Code(0), false));
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert_eq!(status.text, "Added 'a' to the agent.");
        assert_eq!(app.take_request(), Some(Request::LoadKeys));
    }

    #[test]
    fn a_cancelled_or_failed_add_is_told_apart_and_reads_again() {
        let mut app = open_keys_with_agent(vec![fine_key("a")], running());
        added(&mut app, "a", ran(Exit::Code(1), true));
        assert!(app.status().unwrap().text.contains("cancelled"));
        assert_eq!(app.take_request(), Some(Request::LoadKeys));

        added(
            &mut app,
            "a",
            ran_with(1, "Bad passphrase, try again for /x\n"),
        );
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert!(
            status.text.contains("'a'") && status.text.contains("Bad passphrase"),
            "{}",
            status.text
        );
        assert_eq!(app.take_request(), Some(Request::LoadKeys));

        added(
            &mut app,
            "a",
            HandoverResult::Failed("Could not start ssh-add: no".to_string()),
        );
        assert_eq!(app.status().unwrap().kind, StatusKind::Error);
        assert!(app.take_request().is_none());
    }

    #[test]
    fn the_help_documents_making_and_adding_keys() {
        let text: Vec<&str> = HELP
            .iter()
            .filter(|section| section.title == "Your ssh keys")
            .flat_map(|section| section.rows)
            .flat_map(|row| tokens(row.keys))
            .collect();
        assert!(text.contains(&"g") && text.contains(&"a"), "{text:?}");
    }

    // ---- sending a public key to a host ----------------------------------------

    fn open_keys_in(mut app: App, keys: Vec<crate::ssh::keys::KeyEntry>) -> App {
        app.handle_key(ch('K'));
        let request = app.take_request().expect("the keys are asked for");
        app.handle_response(&request, Response::Keys(key_snapshot(keys)));
        app
    }

    fn dialog_of(app: &App) -> &crate::tui::keys::CopyDialog {
        app.keys().unwrap().copying().expect("the dialog is open")
    }

    fn choice_names(app: &App) -> Vec<&str> {
        dialog_of(app)
            .choices()
            .iter()
            .map(|choice| choice.name.as_str())
            .collect()
    }

    /// Opens the dialog for key `a`, picks the first host and confirms: the state
    /// in which the question is showing.
    fn asking_to_send() -> App {
        let mut app = open_keys(vec![fine_key("a"), fine_key("b")]);
        app.handle_key(ch('c'));
        app.handle_key(press(KeyCode::Enter));
        assert!(dialog_of(&app).confirming());
        app
    }

    fn take_copy_key_request(app: &mut App) -> (String, ConnectRequest) {
        match app.take_request() {
            Some(Request::CopyKey { file_name, connect }) => (file_name, connect),
            other => panic!("expected a request to send a key, got {other:?}"),
        }
    }

    #[test]
    fn c_opens_the_hosts_for_the_selected_key_in_the_order_of_the_host_list() {
        let mut app = open_keys(vec![fine_key("a"), fine_key("b")]);
        app.handle_key(ch('j'));
        app.handle_key(ch('c'));
        assert_eq!(dialog_of(&app).key(), "b");
        // Favorites first, then by name: as on the host list.
        assert_eq!(choice_names(&app), ["backup", "db", "web"]);
        assert!(!dialog_of(&app).confirming());
        assert_eq!(labels(&app), ["choose", "select", "cancel"]);
        assert!(app.take_request().is_none(), "opening asks for nothing");
    }

    #[test]
    fn where_a_host_is_says_its_user_and_port_only_when_they_are_set() {
        let mut plain = host("plain", false);
        plain.user = None;
        let mut full = host("full", false);
        full.user = Some("deploy".to_string());
        full.port = Some(2222);
        let mut port_only = host("port", false);
        port_only.port = Some(2200);
        let mut app = open_keys_in(
            app_with(hosts(vec![plain, full, port_only]), Vec::new()).0,
            vec![fine_key("a")],
        );
        app.handle_key(ch('c'));
        let destinations: Vec<&str> = dialog_of(&app)
            .choices()
            .iter()
            .map(|choice| choice.destination.as_str())
            .collect();
        assert_eq!(
            destinations,
            [
                "deploy@full.example.com:2222",
                "plain.example.com",
                "port.example.com:2200"
            ]
        );
    }

    #[test]
    fn c_needs_a_key_and_a_host_and_says_so_when_there_is_no_host() {
        let mut none_selected = open_keys(Vec::new());
        none_selected.handle_key(ch('c'));
        assert!(none_selected.keys().unwrap().copying().is_none());

        let mut no_hosts = open_keys_in(
            app_with(hosts(Vec::new()), Vec::new()).0,
            vec![fine_key("a")],
        );
        no_hosts.handle_key(ch('c'));
        assert!(no_hosts.keys().unwrap().copying().is_none());
        assert!(
            no_hosts.status().unwrap().text.contains("no saved hosts"),
            "{:?}",
            no_hosts.status()
        );
    }

    #[test]
    fn while_the_hosts_are_showing_the_lists_keys_do_not_act() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('c'));
        for key in [
            ch('q'),
            ch('g'),
            ch('a'),
            ch('r'),
            ch('f'),
            ch('?'),
            ch('K'),
            ch('c'),
        ] {
            app.handle_key(key);
            assert!(
                dialog_of(&app).key() == "a" && !app.should_quit(),
                "{key:?}"
            );
            assert!(app.take_request().is_none(), "{key:?}");
            assert_eq!(app.screen(), Screen::Keys);
        }
    }

    #[test]
    fn the_hosts_are_moved_through_and_the_selection_stays_inside() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('c'));
        let at = |app: &App| dialog_of(app).selected();
        app.handle_key(press(KeyCode::Up));
        assert_eq!(at(&app), 0);
        app.handle_key(ch('j'));
        app.handle_key(press(KeyCode::Down));
        app.handle_key(press(KeyCode::Down));
        assert_eq!(at(&app), 2);
        app.handle_key(ch('k'));
        assert_eq!(at(&app), 1);
        app.handle_key(press(KeyCode::Home));
        assert_eq!(at(&app), 0);
        app.handle_key(press(KeyCode::End));
        assert_eq!(at(&app), 2);
        app.handle_key(press(KeyCode::PageUp));
        assert_eq!(at(&app), 1, "a page is at least one row");
        app.handle_key(press(KeyCode::PageDown));
        assert_eq!(at(&app), 2);
    }

    #[test]
    fn esc_on_the_hosts_closes_the_dialog_and_asks_for_nothing() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('c'));
        app.handle_key(press(KeyCode::Esc));
        assert!(app.keys().unwrap().copying().is_none());
        assert_eq!(app.screen(), Screen::Keys);
        assert!(app.take_request().is_none());
    }

    #[test]
    fn choosing_a_host_asks_a_question_and_sends_nothing_yet() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.handle_key(ch('c'));
        app.handle_key(ch('j'));
        app.handle_key(press(KeyCode::Enter));
        let dialog = dialog_of(&app);
        assert!(dialog.confirming());
        assert_eq!(dialog.selected_choice().unwrap().name, "db");
        assert_eq!(labels(&app), ["send the key", "back"]);
        assert!(app.take_request().is_none(), "asking is not doing");
    }

    #[test]
    fn only_a_plain_y_sends_and_then_the_dialog_is_over() {
        for answer in [ch('y'), ch('Y')] {
            let mut app = asking_to_send();
            app.handle_key(answer);
            let (file_name, connect) = take_copy_key_request(&mut app);
            assert_eq!(file_name, "a");
            assert_eq!(connect.name, "backup");
            assert!(app.keys().unwrap().copying().is_none());
            assert!(app.take_request().is_none());
        }
    }

    #[test]
    fn nothing_but_y_sends() {
        let mut app = asking_to_send();
        for key in [
            press(KeyCode::Enter),
            ch('j'),
            ch('q'),
            ch(' '),
            ch('a'),
            with(KeyCode::Char('y'), KeyModifiers::CONTROL),
            with(KeyCode::Char('y'), KeyModifiers::ALT),
            with(KeyCode::Char('Y'), KeyModifiers::CONTROL),
        ] {
            app.handle_key(key);
            assert!(dialog_of(&app).confirming(), "{key:?}");
            assert!(app.take_request().is_none(), "{key:?}");
            assert!(!app.should_quit(), "{key:?}");
        }
    }

    #[test]
    fn n_and_esc_at_the_question_go_back_to_the_hosts_and_send_nothing() {
        for answer in [ch('n'), ch('N'), press(KeyCode::Esc)] {
            let mut app = asking_to_send();
            app.handle_key(answer);
            assert!(!dialog_of(&app).confirming(), "{answer:?}");
            assert!(app.take_request().is_none());
            assert_eq!(labels(&app), ["choose", "select", "cancel"]);
        }
    }

    #[test]
    fn ctrl_c_quits_from_every_step_of_the_dialog() {
        let mut choosing = open_keys(vec![fine_key("a")]);
        choosing.handle_key(ch('c'));
        choosing.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(choosing.should_quit());

        let mut asking = asking_to_send();
        asking.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(asking.should_quit());
        assert!(asking.take_request().is_none());
    }

    #[test]
    fn the_request_carries_the_arguments_for_sending_a_key_and_no_others() {
        let mut app = asking_to_send();
        app.handle_key(ch('y'));
        let (_, connect) = take_copy_key_request(&mut app);
        assert!(connect.args.is_key_copy());
        let backup = host("backup", true);
        let expected = build_copy_args(&backup, &sample()).unwrap();
        assert_eq!(connect.args, expected);
        assert_ne!(connect.args, build_args(&backup, &sample()).unwrap());
        assert_eq!(connect.known_hosts.len(), 1);
        assert_eq!(connect.known_hosts[0].saved_name, "backup");
    }

    #[test]
    fn a_host_with_forwards_and_agent_forwarding_gets_none_of_them_when_a_key_is_sent() {
        let mut busy = host("busy", true);
        busy.forward_agent = true;
        busy.local_forwards.push(crate::domain::Forward {
            listen_port: 8080,
            dest_host: "localhost".to_string(),
            dest_port: 80,
        });
        let mut app = open_keys_in(
            app_with(hosts(vec![busy]), Vec::new()).0,
            vec![fine_key("a")],
        );
        app.handle_key(ch('c'));
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(ch('y'));
        let (_, connect) = take_copy_key_request(&mut app);
        let args = connect.args.as_slice();
        assert!(
            !args.iter().any(|a| a == "-A" || a == "-L" || a == "-R"),
            "{args:?}"
        );
    }

    fn copied(app: &mut App, result: HandoverResult) {
        let request = Request::CopyKey {
            file_name: "a".to_string(),
            connect: ConnectRequest {
                name: "web".to_string(),
                args: build_copy_args(&host("web", false), &sample()).unwrap(),
                known_hosts: Vec::new(),
            },
        };
        app.handle_response(&request, Response::KeyCopied(result));
    }

    #[test]
    fn a_key_that_was_sent_is_reported_on_the_keys_screen_and_nothing_is_read_again() {
        let mut app = open_keys(vec![fine_key("a")]);
        copied(&mut app, ran(Exit::Code(0), false));
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Info);
        assert!(
            status.text.contains("'a'") && status.text.contains("'web'"),
            "{}",
            status.text
        );
        assert_eq!(app.screen(), Screen::Keys);
        assert!(app.take_request().is_none());
    }

    #[test]
    fn the_servers_own_failure_is_told_apart_from_a_connection_failure() {
        let mut app = open_keys(vec![fine_key("a")]);
        copied(
            &mut app,
            ran_with(
                1,
                "mkdir: cannot create directory '.ssh': Permission denied\n",
            ),
        );
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert!(
            status.text.contains("'web' ran the command")
                && status.text.contains("status 1")
                && status.text.contains("probably not added")
                && status
                    .text
                    .contains("It said: mkdir: cannot create directory"),
            "{}",
            status.text
        );
        assert_eq!(
            app.screen(),
            Screen::Keys,
            "not the connection error screen"
        );

        copied(&mut app, ran_with(127, ""));
        let text = app.status().unwrap().text.clone();
        assert!(
            text.contains("status 127") && !text.contains("It said"),
            "{text}"
        );

        copied(&mut app, ran_with(1, &"y".repeat(5000)));
        assert!(app.status().unwrap().text.len() < 400);
    }

    #[test]
    fn cancelled_stopped_and_closed_are_said_plainly_and_do_not_claim_success() {
        let mut app = open_keys(vec![fine_key("a")]);
        copied(&mut app, ran(Exit::Code(1), true));
        assert!(app.status().unwrap().text.contains("cancelled"));
        copied(&mut app, ran(Exit::Signal(9), false));
        let stopped = app.status().unwrap();
        assert_eq!(stopped.kind, StatusKind::Warning);
        assert!(stopped.text.contains("signal 9") && stopped.text.contains("may not"));
        copied(&mut app, ran_with(255, "Connection to web closed.\r\n"));
        assert!(
            app.status()
                .unwrap()
                .text
                .contains("may not have been sent")
        );
        assert_eq!(app.screen(), Screen::Keys);
    }

    #[test]
    fn a_key_that_was_not_sent_because_nothing_could_run_says_why_and_leaves_no_report() {
        let mut app = open_keys(vec![fine_key("a")]);
        copied(
            &mut app,
            HandoverResult::Failed("The public key /x.pub is not a regular file.".to_string()),
        );
        let status = app.status().unwrap();
        assert_eq!(status.kind, StatusKind::Error);
        assert_eq!(status.text, "The public key /x.pub is not a regular file.");
        assert!(app.report().is_none());
        assert_eq!(app.screen(), Screen::Keys);
    }

    #[test]
    fn a_connection_that_failed_is_explained_on_the_same_screen_and_goes_back_to_the_keys() {
        let mut app = open_keys(vec![fine_key("a")]);
        copied(
            &mut app,
            ran_with(
                255,
                "deploy@web: Permission denied (publickey,password).\r\n",
            ),
        );
        assert_eq!(app.screen(), Screen::ConnectError);
        assert_eq!(app.report().unwrap().name, "web");
        assert_eq!(
            app.report().unwrap().failure,
            Some(FailureKind::PermissionDenied)
        );
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::Keys, "where the key was sent from");
        assert!(app.keys().is_some());

        copied(
            &mut app,
            ran_with(
                255,
                "ssh: connect to host web port 22: Connection refused\r\n",
            ),
        );
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.screen(), Screen::Keys);
    }

    #[test]
    fn the_output_page_opened_from_that_screen_comes_back_to_it() {
        let mut app = open_keys(vec![fine_key("a")]);
        copied(
            &mut app,
            ran_with(
                255,
                "ssh: connect to host web port 22: Connection refused\r\n",
            ),
        );
        app.handle_key(ch('o'));
        assert_eq!(app.screen(), Screen::SshOutput);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::ConnectError);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::Keys);
    }

    #[test]
    fn a_changed_host_key_stops_everything_on_the_blocking_screen_even_when_sending_a_key() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.set_known_hosts_file(Some(PathBuf::from(DEFAULT_KNOWN_HOSTS)));
        // The dialog is how the connection was asked for, so the hosts it may
        // remove an old key of are those of that request.
        app.handle_key(ch('c'));
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(ch('y'));
        let (file_name, connect) = take_copy_key_request(&mut app);
        let request = Request::CopyKey {
            file_name,
            connect: connect.clone(),
        };
        app.handle_response(
            &request,
            Response::KeyCopied(ran_with(
                255,
                &changed_key_output("backup.example.com", DEFAULT_KNOWN_HOSTS),
            )),
        );
        assert_eq!(app.screen(), Screen::HostKeyChanged);
        assert_eq!(app.key_change().unwrap().name, "backup");
        assert!(app.key_change().unwrap().removal.is_some());
        assert!(
            app.take_request().is_none(),
            "nothing is sent or removed by itself"
        );

        // Aborting is the safe way out, and it goes back to the keys.
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.screen(), Screen::Keys);
        assert!(app.key_change().is_none());
    }

    #[test]
    fn after_removing_the_old_key_the_advice_is_to_send_the_key_again() {
        let mut app = open_keys(vec![fine_key("a")]);
        app.set_known_hosts_file(Some(PathBuf::from(DEFAULT_KNOWN_HOSTS)));
        app.handle_key(ch('c'));
        app.handle_key(press(KeyCode::Enter));
        app.handle_key(ch('y'));
        let (file_name, connect) = take_copy_key_request(&mut app);
        let request = Request::CopyKey { file_name, connect };
        app.handle_response(
            &request,
            Response::KeyCopied(ran_with(
                255,
                &changed_key_output("backup.example.com", DEFAULT_KNOWN_HOSTS),
            )),
        );
        app.handle_key(ch('r'));
        type_name(&mut app, "backup");
        app.handle_key(press(KeyCode::Enter));
        let Some(Request::RemoveKey(target)) = app.take_request() else {
            panic!("the removal was asked for");
        };
        app.key_removal_finished(&target, Removal::Removed);
        assert_eq!(app.screen(), Screen::Keys);
        let text = app.status().unwrap().text.clone();
        assert!(
            text.contains("Send the key again") && !text.contains("Connect again"),
            "{text}"
        );
    }

    #[test]
    fn a_connection_from_the_list_still_goes_back_to_the_list_after_a_key_was_sent() {
        let mut app = open_keys(vec![fine_key("a")]);
        copied(
            &mut app,
            ran_with(
                255,
                "ssh: connect to host web port 22: Connection refused\r\n",
            ),
        );
        app.handle_key(press(KeyCode::Esc)); // to the keys
        app.handle_key(press(KeyCode::Esc)); // to the list
        assert_eq!(app.screen(), Screen::List);

        app.handle_key(press(KeyCode::Enter));
        take_connect_request(&mut app);
        app.connection_ended(
            "backup",
            ran_with(
                255,
                "ssh: connect to host backup port 22: Connection refused\r\n",
            ),
        );
        assert_eq!(app.screen(), Screen::ConnectError);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::List, "not the keys");
    }

    #[test]
    fn the_help_documents_sending_a_key_and_the_footer_offers_it_for_a_selected_key() {
        let documented: Vec<&str> = HELP
            .iter()
            .filter(|section| section.title == "Your ssh keys")
            .flat_map(|section| section.rows)
            .flat_map(|row| tokens(row.keys))
            .collect();
        assert!(documented.contains(&"c"), "{documented:?}");
        assert!(labels(&open_keys(vec![fine_key("a")])).contains(&"send to host"));
        assert!(!labels(&open_keys(Vec::new())).contains(&"send to host"));
    }
}
