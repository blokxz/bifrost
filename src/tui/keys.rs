//! The keys screen's state: the keys found, which one is selected, and whether
//! the user is being asked to confirm a permission fix.
//!
//! Pure state, like the rest of the app's logic: loading the keys and changing
//! permissions are requests (see [`super::effects`]), and this only holds what
//! came back.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::input::TextInput;
use super::list::window_start;
use crate::ssh::keys::{
    KeyEntry, KeysSnapshot, Permissions, suggest_key_name, validate_comment, validate_key_name,
};

/// What pressing the fix key on the selected key does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixOutcome {
    /// The user is now being asked to confirm.
    Asked,
    /// The key is not too open, or nothing is selected.
    NotNeeded(Permissions),
    /// The key is too open, but it is a symbolic link: changing it would change
    /// what it points to, so Bifrost does not offer.
    Symlink,
    /// There is no key selected.
    NothingSelected,
}

/// The two fields of the generate form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateField {
    Name,
    Comment,
}

/// What a key pressed in the generate form led to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Generation {
    /// Nothing for the caller to do: the form took the key, or said what is wrong.
    Stay,
    /// The user gave up.
    Close,
    /// Everything is valid: make this key. The comment is `None` when it was left
    /// empty.
    Make {
        name: String,
        comment: Option<String>,
    },
}

/// The form that asks what to call a new key and what to say about it. The
/// passphrase is not asked here or anywhere in Bifrost: `ssh-keygen` asks for it
/// itself, once the terminal is handed over.
#[derive(Debug)]
pub struct GenerateForm {
    name: TextInput,
    comment: TextInput,
    focus: GenerateField,
    /// The complaint about a field, shown until that field is edited.
    error: Option<(GenerateField, String)>,
}

impl GenerateForm {
    /// A form with `suggested` in the name field.
    pub fn new(suggested: &str) -> Self {
        GenerateForm {
            name: TextInput::new(suggested),
            comment: TextInput::default(),
            focus: GenerateField::Name,
            error: None,
        }
    }

    pub fn name(&self) -> &TextInput {
        &self.name
    }

    pub fn comment(&self) -> &TextInput {
        &self.comment
    }

    pub fn focus(&self) -> GenerateField {
        self.focus
    }

    pub fn error(&self) -> Option<(GenerateField, &str)> {
        self.error
            .as_ref()
            .map(|(field, message)| (*field, message.as_str()))
    }

    /// Moves to the other field.
    fn switch_field(&mut self) {
        self.focus = match self.focus {
            GenerateField::Name => GenerateField::Comment,
            GenerateField::Comment => GenerateField::Name,
        };
    }

    /// Gives a key to the focused field. Returns whether the text changed, in
    /// which case its complaint, if it had one, is gone.
    fn edit(&mut self, key: KeyEvent) -> bool {
        let input = match self.focus {
            GenerateField::Name => &mut self.name,
            GenerateField::Comment => &mut self.comment,
        };
        let changed = input.handle_key(key);
        if changed
            && self
                .error
                .as_ref()
                .is_some_and(|(field, _)| *field == self.focus)
        {
            self.error = None;
        }
        changed
    }

    fn fail(&mut self, field: GenerateField, message: String) -> Generation {
        self.focus = field;
        self.error = Some((field, message));
        Generation::Stay
    }

    fn check_name(&self, taken: &[&str]) -> Result<(), String> {
        validate_key_name(self.name.value())?;
        if taken
            .iter()
            .any(|name| name.eq_ignore_ascii_case(self.name.value()))
        {
            return Err("There is already a key with that name. Choose another.".to_string());
        }
        Ok(())
    }

    /// Enter: from the name it checks the name and moves to the comment; from the
    /// comment it checks everything.
    fn enter(&mut self, taken: &[&str]) -> Generation {
        if let Err(why) = self.check_name(taken) {
            return self.fail(GenerateField::Name, why);
        }
        if self.focus == GenerateField::Name {
            self.focus = GenerateField::Comment;
            return Generation::Stay;
        }
        if let Err(why) = validate_comment(self.comment.value()) {
            return self.fail(GenerateField::Comment, why);
        }
        let comment = self.comment.value();
        Generation::Make {
            name: self.name.value().to_string(),
            comment: (!comment.is_empty()).then(|| comment.to_string()),
        }
    }

    /// Applies a key. `taken` are the names of the keys already listed.
    pub fn handle_key(&mut self, key: KeyEvent, taken: &[&str]) -> Generation {
        match key.code {
            KeyCode::Esc => Generation::Close,
            KeyCode::Enter => self.enter(taken),
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                self.switch_field();
                Generation::Stay
            }
            _ => {
                self.edit(key);
                Generation::Stay
            }
        }
    }
}

/// A saved host that a key can be sent to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChoice {
    /// The saved name.
    pub name: String,
    /// Where it is, as a person reads it: `user@hostname:port`, leaving out what
    /// is not set.
    pub destination: String,
}

/// What a key pressed in the send-a-key dialog led to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Copying {
    /// Nothing for the caller to do.
    Stay,
    /// The user gave up.
    Close,
    /// The user confirmed: send the public key of `key` to the saved host `host`.
    Send { key: String, host: String },
}

/// The dialog that sends a public key to a saved host: first which host, then a
/// question, because this lets whoever holds the private key log in there.
#[derive(Debug)]
pub struct CopyDialog {
    key: String,
    choices: Vec<HostChoice>,
    selected: usize,
    offset: usize,
    /// How many host rows fit, as last reported by rendering.
    visible: usize,
    confirming: bool,
}

impl CopyDialog {
    /// The private key's file name, whose public key is sent.
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn choices(&self) -> &[HostChoice] {
        &self.choices
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn selected_choice(&self) -> Option<&HostChoice> {
        self.choices.get(self.selected)
    }

    /// The first visible host.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Whether the question is showing, and not the list of hosts.
    pub fn confirming(&self) -> bool {
        self.confirming
    }

    pub fn set_visible(&mut self, rows: usize) {
        self.visible = rows;
        self.keep_selection_visible();
    }

    fn keep_selection_visible(&mut self) {
        self.offset = window_start(
            self.offset,
            Some(self.selected),
            self.visible,
            self.choices.len(),
        );
    }

    fn select(&mut self, position: usize) {
        self.selected = position.min(self.choices.len().saturating_sub(1));
        self.keep_selection_visible();
    }

    fn move_by(&mut self, delta: isize) {
        self.select(self.selected.saturating_add_signed(delta));
    }

    /// Applies a key. Only plain keys count; Ctrl and Alt belong to the terminal.
    pub fn handle_key(&mut self, key: KeyEvent) -> Copying {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return Copying::Stay;
        }
        if self.confirming {
            return match key.code {
                KeyCode::Char('y' | 'Y') => match self.selected_choice() {
                    Some(choice) => Copying::Send {
                        key: self.key.clone(),
                        host: choice.name.clone(),
                    },
                    None => Copying::Close,
                },
                // Back to choosing, not out: the question is about this host.
                KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                    self.confirming = false;
                    Copying::Stay
                }
                _ => Copying::Stay,
            };
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::PageUp | KeyCode::PageDown => {
                let step = isize::try_from(self.visible.saturating_sub(1).max(1)).unwrap_or(1);
                self.move_by(if key.code == KeyCode::PageDown {
                    step
                } else {
                    -step
                });
            }
            KeyCode::Home => self.select(0),
            KeyCode::End => self.select(usize::MAX),
            KeyCode::Enter => self.confirming = self.selected_choice().is_some(),
            KeyCode::Esc => return Copying::Close,
            _ => {}
        }
        Copying::Stay
    }
}

/// The question asked before a key is deleted, answered by typing its name.
#[derive(Debug)]
pub struct DeleteQuestion {
    /// The private key's file name, which is what has to be typed.
    pub key: String,
    /// The two files that would be removed, as they are written for the user.
    pub private: String,
    pub public: String,
    /// The private file is a symbolic link: only the link is removed.
    pub symlink: bool,
    /// The saved hosts that have this key as their identity file.
    pub used_by: Vec<String>,
    /// The agent holds the key, and goes on holding it.
    pub loaded: bool,
    pub input: TextInput,
    /// What was typed was not the name.
    pub mismatch: bool,
}

/// What a key pressed in the delete question led to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deletion {
    Stay,
    /// The user gave up.
    Cancel,
    /// The name was typed: delete this key.
    Delete {
        key: String,
    },
}

impl DeleteQuestion {
    /// Applies a key. Only the exact name confirms, case included, as for a host.
    pub fn handle_key(&mut self, key: KeyEvent) -> Deletion {
        let plain = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc if plain => Deletion::Cancel,
            KeyCode::Enter if plain => {
                if self.input.value() == self.key {
                    Deletion::Delete {
                        key: self.key.clone(),
                    }
                } else {
                    self.mismatch = true;
                    Deletion::Stay
                }
            }
            _ => {
                if self.input.handle_key(key) {
                    self.mismatch = false;
                }
                Deletion::Stay
            }
        }
    }
}

/// The question asked once a key was sent to a host: use it for that host from
/// now on? Answering yes sets the host's identity file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseKeyQuestion {
    /// The private key's file name.
    pub key: String,
    /// The saved host the key was sent to.
    pub host: String,
    /// What would be stored as the host's identity file (`~/.ssh/name`).
    pub value: String,
    /// What the host has as its identity file now, when it has one: yes replaces it.
    pub replaces: Option<String>,
}

#[derive(Debug)]
pub struct KeysScreen {
    snapshot: KeysSnapshot,
    selected: usize,
    offset: usize,
    /// How many rows of the list fit, as last reported by rendering.
    visible: usize,
    /// The key whose permissions the user is being asked about.
    confirm_fix: Option<String>,
    /// The form for a new key, while it is open.
    generate: Option<GenerateForm>,
    /// The dialog that sends a public key to a host, while it is open.
    copy: Option<CopyDialog>,
    /// The question about using a key that was just sent, while it is open.
    use_key: Option<UseKeyQuestion>,
    /// The question before deleting a key, while it is open.
    delete: Option<DeleteQuestion>,
}

impl KeysScreen {
    /// The screen for `snapshot`. If `previous` was showing, the same key stays
    /// selected when it is still there, so that refreshing does not lose the
    /// user's place.
    pub fn new(snapshot: KeysSnapshot, previous: Option<&KeysScreen>) -> Self {
        let mut screen = KeysScreen {
            snapshot,
            selected: 0,
            offset: 0,
            visible: previous.map_or(0, |p| p.visible),
            confirm_fix: None,
            generate: None,
            copy: None,
            use_key: None,
            delete: None,
        };
        if let Some(name) = previous.and_then(|p| p.selected_entry()).map(|e| &e.name)
            && let Some(position) = screen.snapshot.keys.iter().position(|k| &k.name == name)
        {
            screen.selected = position;
        } else if let Some(previous) = previous {
            // The key that was selected is gone (deleted): stay about where it was,
            // rather than jump to the top.
            screen.selected = previous
                .selected
                .min(screen.snapshot.keys.len().saturating_sub(1));
        }
        screen.keep_selection_visible();
        screen
    }

    pub fn snapshot(&self) -> &KeysSnapshot {
        &self.snapshot
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn selected_entry(&self) -> Option<&KeyEntry> {
        self.snapshot.keys.get(self.selected)
    }

    /// The first visible row.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The form for a new key, while it is open.
    pub fn generating(&self) -> Option<&GenerateForm> {
        self.generate.as_ref()
    }

    /// The question before deleting a key, while it is open.
    pub fn deleting(&self) -> Option<&DeleteQuestion> {
        self.delete.as_ref()
    }

    /// Opens the question.
    pub fn ask_delete(&mut self, question: DeleteQuestion) {
        self.delete = Some(question);
    }

    /// Gives a key to the question. It closes when the user gives up and when they
    /// have typed the name.
    pub fn delete_key(&mut self, key: KeyEvent) -> Deletion {
        let Some(question) = self.delete.as_mut() else {
            return Deletion::Stay;
        };
        let outcome = question.handle_key(key);
        if outcome != Deletion::Stay {
            self.delete = None;
        }
        outcome
    }

    /// The question about using a key that was just sent, while it is open.
    pub fn using(&self) -> Option<&UseKeyQuestion> {
        self.use_key.as_ref()
    }

    /// Opens the question.
    pub fn ask_use_key(&mut self, question: UseKeyQuestion) {
        self.use_key = Some(question);
    }

    /// The question is over, whatever the answer: gives it back to be acted on.
    pub fn close_use_key(&mut self) -> Option<UseKeyQuestion> {
        self.use_key.take()
    }

    /// The dialog that sends a public key to a host, while it is open.
    pub fn copying(&self) -> Option<&CopyDialog> {
        self.copy.as_ref()
    }

    /// Opens the dialog for sending the selected key's public key to one of
    /// `choices`. Returns whether it opened: it needs a key and a host.
    pub fn start_copy(&mut self, choices: Vec<HostChoice>) -> bool {
        let Some(entry) = self.selected_entry() else {
            return false;
        };
        if choices.is_empty() {
            return false;
        }
        self.copy = Some(CopyDialog {
            key: entry.name.clone(),
            choices,
            selected: 0,
            offset: 0,
            visible: 0,
            confirming: false,
        });
        true
    }

    /// Gives a key to the send-a-key dialog. It closes when the user gives up and
    /// when they confirm.
    pub fn copy_key(&mut self, key: KeyEvent) -> Copying {
        let Some(dialog) = self.copy.as_mut() else {
            return Copying::Stay;
        };
        let outcome = dialog.handle_key(key);
        if outcome != Copying::Stay {
            self.copy = None;
        }
        outcome
    }

    /// How many host rows the dialog has room for, as last drawn.
    /// Zero means the dialog is not showing its hosts (it shows the question), and
    /// leaves what was last known.
    pub fn set_copy_visible(&mut self, rows: usize) {
        if let (Some(dialog), true) = (self.copy.as_mut(), rows > 0) {
            dialog.set_visible(rows);
        }
    }

    /// Opens the form for a new key, with a name that is not in use.
    pub fn start_generate(&mut self) {
        let names: Vec<&str> = self.snapshot.keys.iter().map(|k| k.name.as_str()).collect();
        self.generate = Some(GenerateForm::new(&suggest_key_name(&names)));
    }

    /// Gives a key to the generate form. The form closes when the user gives up
    /// and when they ask for the key to be made.
    pub fn generate_key(&mut self, key: KeyEvent) -> Generation {
        let taken: Vec<&str> = self.snapshot.keys.iter().map(|k| k.name.as_str()).collect();
        let Some(form) = self.generate.as_mut() else {
            return Generation::Stay;
        };
        let outcome = form.handle_key(key, &taken);
        if outcome != Generation::Stay {
            self.generate = None;
        }
        outcome
    }

    /// Selects the key called `name`, if it is listed.
    pub fn select_name(&mut self, name: &str) {
        if let Some(position) = self.snapshot.keys.iter().position(|k| k.name == name) {
            self.select(position);
        }
    }

    /// The name of the key being asked about, while the question is showing.
    pub fn confirming(&self) -> Option<&str> {
        self.confirm_fix.as_deref()
    }

    pub fn set_visible(&mut self, rows: usize) {
        self.visible = rows;
        self.keep_selection_visible();
    }

    fn keep_selection_visible(&mut self) {
        self.offset = window_start(
            self.offset,
            Some(self.selected),
            self.visible,
            self.snapshot.keys.len(),
        );
    }

    fn select(&mut self, position: usize) {
        self.selected = position.min(self.snapshot.keys.len().saturating_sub(1));
        self.keep_selection_visible();
    }

    pub fn move_by(&mut self, delta: isize) {
        self.select(self.selected.saturating_add_signed(delta));
    }

    pub fn first(&mut self) {
        self.select(0);
    }

    pub fn last(&mut self) {
        self.select(usize::MAX);
    }

    /// One screenful up or down.
    pub fn page(&mut self, down: bool) {
        let step = self.visible.saturating_sub(1).max(1);
        let step = isize::try_from(step).unwrap_or(isize::MAX);
        self.move_by(if down { step } else { -step });
    }

    /// The fix key: asks for confirmation when there is something to fix.
    pub fn start_fix(&mut self) -> FixOutcome {
        let Some(entry) = self.selected_entry() else {
            return FixOutcome::NothingSelected;
        };
        if entry.can_fix_permissions() {
            self.confirm_fix = Some(entry.name.clone());
            FixOutcome::Asked
        } else if entry.permissions.is_too_open() {
            FixOutcome::Symlink
        } else {
            FixOutcome::NotNeeded(entry.permissions)
        }
    }

    /// The user said no.
    pub fn cancel_fix(&mut self) {
        self.confirm_fix = None;
    }

    /// The user said yes: the name of the key to fix, and the question is over.
    pub fn confirm_fix(&mut self) -> Option<String> {
        self.confirm_fix.take()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Keys and snapshots for tests of this screen and of what draws it.

    use std::path::PathBuf;

    use crate::ssh::agent::AgentState;
    use crate::ssh::keys::{Fingerprint, KeyEntry, KeysSnapshot, Permissions};

    pub(crate) fn entry(name: &str, permissions: Permissions, symlink: bool) -> KeyEntry {
        KeyEntry {
            name: name.to_string(),
            private: PathBuf::from(format!("/home/dev/.ssh/{name}")),
            public: PathBuf::from(format!("/home/dev/.ssh/{name}.pub")),
            fingerprint: Ok(Fingerprint {
                bits: 256,
                hash: "SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw".to_string(),
                comment: Some("dev laptop".to_string()),
                key_type: "ED25519".to_string(),
            }),
            permissions,
            symlink,
            loaded: Some(false),
        }
    }

    pub(crate) fn snapshot(keys: Vec<KeyEntry>) -> KeysSnapshot {
        KeysSnapshot {
            dir: PathBuf::from("/home/dev/.ssh"),
            keys,
            agent: AgentState::NotStarted,
            missing_dir: false,
            truncated: false,
            problem: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{entry, snapshot};
    use super::*;

    fn fine(name: &str) -> KeyEntry {
        entry(name, Permissions::Fine, false)
    }

    fn many(count: usize) -> KeysScreen {
        KeysScreen::new(
            snapshot((0..count).map(|n| fine(&format!("key{n:02}"))).collect()),
            None,
        )
    }

    #[test]
    fn selection_stays_inside_the_list() {
        let mut screen = many(3);
        screen.move_by(-1);
        assert_eq!(screen.selected(), 0);
        screen.move_by(1);
        screen.move_by(1);
        screen.move_by(1);
        assert_eq!(screen.selected(), 2);
        screen.first();
        assert_eq!(screen.selected(), 0);
        screen.last();
        assert_eq!(screen.selected(), 2);
    }

    #[test]
    fn an_empty_list_has_nothing_to_select_and_nothing_breaks() {
        let mut screen = many(0);
        screen.move_by(1);
        screen.last();
        screen.page(true);
        assert_eq!(screen.selected(), 0);
        assert!(screen.selected_entry().is_none());
        assert_eq!(screen.start_fix(), FixOutcome::NothingSelected);
    }

    #[test]
    fn the_window_follows_the_selection() {
        let mut screen = many(30);
        screen.set_visible(5);
        for _ in 0..10 {
            screen.move_by(1);
        }
        assert_eq!(screen.selected(), 10);
        assert!(screen.offset() <= 10 && 10 < screen.offset() + 5);
        screen.first();
        assert_eq!(screen.offset(), 0);
        screen.last();
        assert_eq!(screen.offset(), 25, "no blank space below the last key");
    }

    #[test]
    fn a_page_moves_by_a_screenful_less_one() {
        let mut screen = many(30);
        screen.set_visible(6);
        screen.page(true);
        assert_eq!(screen.selected(), 5);
        screen.page(false);
        assert_eq!(screen.selected(), 0);
    }

    #[test]
    fn refreshing_keeps_the_same_key_selected_when_it_is_still_there() {
        let mut screen = many(5);
        screen.set_visible(3);
        screen.move_by(3);
        assert_eq!(screen.selected_entry().unwrap().name, "key03");

        // A new key appears before it: the position changes, the key does not.
        let mut keys: Vec<KeyEntry> = (0..5).map(|n| fine(&format!("key{n:02}"))).collect();
        keys.insert(0, fine("aaa"));
        let refreshed = KeysScreen::new(snapshot(keys), Some(&screen));
        assert_eq!(refreshed.selected_entry().unwrap().name, "key03");
        assert_eq!(refreshed.selected(), 4);

        // The key is gone: back to the first.
        let gone = KeysScreen::new(snapshot(vec![fine("other")]), Some(&screen));
        assert_eq!(gone.selected(), 0);
    }

    #[test]
    fn a_refresh_forgets_a_question_that_was_being_asked() {
        let mut screen = KeysScreen::new(
            snapshot(vec![entry(
                "k",
                Permissions::TooOpen { mode: 0o644 },
                false,
            )]),
            None,
        );
        assert_eq!(screen.start_fix(), FixOutcome::Asked);
        let refreshed = KeysScreen::new(screen.snapshot().clone(), Some(&screen));
        assert!(refreshed.confirming().is_none());
    }

    #[test]
    fn the_fix_asks_only_for_a_key_that_is_too_open_and_not_a_link() {
        let open = Permissions::TooOpen { mode: 0o644 };
        let mut screen = KeysScreen::new(
            snapshot(vec![
                entry("fine", Permissions::Fine, false),
                entry("link", open, true),
                entry("open", open, false),
                entry("unchecked", Permissions::Unchecked, false),
            ]),
            None,
        );
        assert_eq!(screen.start_fix(), FixOutcome::NotNeeded(Permissions::Fine));
        assert!(screen.confirming().is_none());
        screen.move_by(1);
        assert_eq!(screen.start_fix(), FixOutcome::Symlink);
        assert!(screen.confirming().is_none());
        screen.move_by(1);
        assert_eq!(screen.start_fix(), FixOutcome::Asked);
        assert_eq!(screen.confirming(), Some("open"));
        screen.cancel_fix();
        assert!(screen.confirming().is_none());
        screen.move_by(1);
        assert_eq!(
            screen.start_fix(),
            FixOutcome::NotNeeded(Permissions::Unchecked)
        );
    }

    #[test]
    fn confirming_hands_out_the_name_once() {
        let mut screen = KeysScreen::new(
            snapshot(vec![entry(
                "open",
                Permissions::TooOpen { mode: 0o666 },
                false,
            )]),
            None,
        );
        screen.start_fix();
        assert_eq!(screen.confirm_fix().as_deref(), Some("open"));
        assert_eq!(screen.confirm_fix(), None);
        assert!(screen.confirming().is_none());
    }
}
