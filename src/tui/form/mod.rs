//! The add/edit form: a state machine with no rendering and no I/O.
//!
//! Keys go in ([`Form::handle_key`]), state comes out, and the app decides what
//! to do with the [`Outcome`] (save, close). Every rule comes from
//! [`crate::domain::validate`] through [`fields`], so the form can never accept
//! what the store would refuse.
//!
//! - One column of fields. Tab and Shift+Tab (or Down and Up) move between
//!   them, and a field is checked when the focus leaves it.
//! - The last four fields sit in a collapsed "Advanced" section.
//! - The jump host is picked from a list of saved hosts that would be valid.
//! - The identity file is picked from a list of the keys found in the ssh
//!   directory, with "none" and "another file" (typing a path) alongside. The form
//!   does no I/O, so it asks for the list ([`Outcome::NeedKeys`]) the first time it
//!   is wanted and keeps it.
//! - Saving is blocked while any field is invalid.

use std::collections::HashMap;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::input::TextInput;
use crate::domain::validate::Field;
use crate::domain::{Host, Hosts};

pub mod fields;

pub use fields::{ADVANCED, AGENT_WARNING, BASIC, FormField};

/// The fields typed into a text box, in form order.
const TEXT_FIELDS: [FormField; 9] = [
    FormField::Name,
    FormField::Hostname,
    FormField::User,
    FormField::Port,
    FormField::IdentityFile,
    FormField::Tags,
    FormField::Notes,
    FormField::LocalForwards,
    FormField::RemoteForwards,
];

/// What the form asks the app to do after a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing for the app to do.
    Stay,
    /// The user asked to save.
    Save,
    /// The user asked to choose a key file and the form has no list of keys yet.
    /// The app reads them and gives them back with [`Form::open_key_picker`].
    NeedKeys,
    /// The form is finished without saving.
    Close,
}

/// The list of saved hosts a jump host is chosen from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picker {
    /// `None` is "no jump host".
    pub options: Vec<Option<String>>,
    pub selected: usize,
}

/// A key that can be chosen as a host's identity file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChoice {
    /// The private key's file name. Raw: sanitize before showing.
    pub name: String,
    /// What is stored as the identity file (`~/.ssh/name`).
    pub value: String,
    /// The same file spelled in full, so that a host that has it written that way
    /// is shown as having this key.
    pub full_path: String,
    /// The type as a person reads it (`ed25519`, `rsa 3072`), when `ssh-keygen`
    /// could tell.
    pub kind: Option<String>,
}

/// The keys the identity file can be chosen from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyList {
    pub choices: Vec<KeyChoice>,
    /// What to tell the user when the list is not what they would expect: no keys,
    /// or a folder that could not be read. Raw: sanitize before showing.
    pub note: Option<String>,
}

/// One line of the list of key files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPick {
    /// No identity file: ssh uses its default keys.
    None,
    Key(KeyChoice),
    /// A file that is not in the list: the user types its path.
    Typed,
}

/// The list of key files an identity file is chosen from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPicker {
    pub options: Vec<KeyPick>,
    pub selected: usize,
    pub note: Option<String>,
    /// The path already typed, when it is not one of the keys: shown on the
    /// "another file" line so that it is clear it is kept.
    pub typed: Option<String>,
}

/// What the keys do right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormMode {
    Editing,
    PickJump(Picker),
    PickKey(KeyPicker),
    /// Asking whether to throw away unsaved changes.
    ConfirmDiscard,
}

/// Everything the user can change, for telling whether anything changed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    texts: Vec<String>,
    jump: Option<String>,
    forward_agent: bool,
}

#[derive(Debug)]
pub struct Form {
    /// The host being edited as it was stored; `None` when adding.
    original: Option<Host>,
    inputs: HashMap<FormField, TextInput>,
    jump: Option<String>,
    forward_agent: bool,
    advanced_open: bool,
    focus: FormField,
    errors: HashMap<FormField, String>,
    initial: Snapshot,
    /// The keys the identity file can be chosen from, once they have been read.
    keys: Option<KeyList>,
    /// A message about the form as a whole (for example why saving failed).
    notice: Option<String>,
    mode: FormMode,
    /// The first visible line of the form, as last reported by rendering.
    pub scroll: usize,
}

impl Form {
    fn from_parts(original: Option<Host>, host: &Host) -> Form {
        let mut inputs = HashMap::new();
        for (field, text) in [
            (FormField::Name, host.name.clone()),
            (FormField::Hostname, host.hostname.clone()),
            (FormField::User, host.user.clone().unwrap_or_default()),
            (
                FormField::Port,
                host.port.map(|p| p.to_string()).unwrap_or_default(),
            ),
            (
                FormField::IdentityFile,
                host.identity_file.clone().unwrap_or_default(),
            ),
            (FormField::Tags, fields::format_tags(&host.tags)),
            (
                FormField::Notes,
                fields::format_notes(host.notes.as_deref()),
            ),
            (
                FormField::LocalForwards,
                fields::format_forwards(&host.local_forwards),
            ),
            (
                FormField::RemoteForwards,
                fields::format_forwards(&host.remote_forwards),
            ),
        ] {
            inputs.insert(field, TextInput::new(text));
        }
        let advanced_open = host.proxy_jump.is_some()
            || !host.local_forwards.is_empty()
            || !host.remote_forwards.is_empty()
            || host.forward_agent;
        let mut form = Form {
            original,
            inputs,
            jump: host.proxy_jump.clone(),
            forward_agent: host.forward_agent,
            advanced_open,
            focus: FormField::Name,
            errors: HashMap::new(),
            initial: Snapshot {
                texts: Vec::new(),
                jump: None,
                forward_agent: false,
            },
            keys: None,
            notice: None,
            mode: FormMode::Editing,
            scroll: 0,
        };
        form.initial = form.snapshot();
        form
    }

    /// An empty form for a new host.
    pub fn add() -> Form {
        Form::from_parts(None, &Host::new("", ""))
    }

    /// A form filled in with an existing host.
    pub fn edit(host: &Host) -> Form {
        Form::from_parts(Some(host.clone()), host)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            texts: TEXT_FIELDS
                .iter()
                .map(|field| self.inputs[field].value().to_string())
                .collect(),
            jump: self.jump.clone(),
            forward_agent: self.forward_agent,
        }
    }

    // ---- what the screen needs to know ------------------------------------

    pub fn title(&self) -> String {
        match &self.original {
            Some(host) => format!("Edit host '{}'", host.name),
            None => "Add host".to_string(),
        }
    }

    /// The name the host had when the form opened, when editing.
    pub fn original_name(&self) -> Option<&str> {
        self.original.as_ref().map(|host| host.name.as_str())
    }

    pub fn focus(&self) -> FormField {
        self.focus
    }

    pub fn mode(&self) -> &FormMode {
        &self.mode
    }

    pub fn advanced_open(&self) -> bool {
        self.advanced_open
    }

    /// The rows shown, in order.
    pub fn fields(&self) -> Vec<FormField> {
        let mut rows = BASIC.to_vec();
        rows.push(FormField::Advanced);
        if self.advanced_open {
            rows.extend(ADVANCED);
        }
        rows
    }

    pub fn input(&self, field: FormField) -> Option<&TextInput> {
        self.inputs.get(&field)
    }

    pub fn jump(&self) -> Option<&str> {
        self.jump.as_deref()
    }

    pub fn forward_agent(&self) -> bool {
        self.forward_agent
    }

    pub fn error(&self, field: FormField) -> Option<&str> {
        self.errors.get(&field).map(String::as_str)
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub fn set_notice(&mut self, text: impl Into<String>) {
        self.notice = Some(text.into());
    }

    /// Whether anything differs from when the form opened.
    pub fn is_dirty(&self) -> bool {
        self.snapshot() != self.initial
    }

    // ---- validation --------------------------------------------------------

    fn text(&self, field: FormField) -> &str {
        self.inputs[&field].value()
    }

    /// Whether `name` belongs to another host than the one being edited.
    fn name_taken(&self, name: &str, hosts: &Hosts) -> bool {
        match hosts.get(name) {
            None => false,
            Some(existing) => match &self.original {
                Some(original) => !existing.name.eq_ignore_ascii_case(&original.name),
                None => true,
            },
        }
    }

    /// Checks one text field. Returns the message to show next to it.
    fn check(&self, field: FormField, hosts: &Hosts) -> Result<(), String> {
        let text = self.text(field);
        match field {
            FormField::Name => {
                let name = fields::parse_name(text)?;
                if self.name_taken(&name, hosts) {
                    return Err(format!(
                        "A host named '{name}' already exists (names are not case-sensitive)."
                    ));
                }
                Ok(())
            }
            FormField::Hostname => fields::parse_hostname(text).map(drop),
            FormField::User => fields::parse_user(text).map(drop),
            FormField::Port => fields::parse_port(text).map(drop),
            FormField::IdentityFile => fields::parse_identity_file(text).map(drop),
            FormField::Tags => fields::parse_tags(text).map(drop),
            FormField::Notes => fields::parse_notes(text).map(drop),
            FormField::LocalForwards => fields::parse_forwards(text, Field::LocalForward).map(drop),
            FormField::RemoteForwards => {
                fields::parse_forwards(text, Field::RemoteForward).map(drop)
            }
            FormField::Advanced | FormField::ProxyJump | FormField::ForwardAgent => Ok(()),
        }
    }

    fn validate_field(&mut self, field: FormField, hosts: &Hosts) {
        if !field.is_text() {
            return;
        }
        match self.check(field, hosts) {
            Ok(()) => {
                self.errors.remove(&field);
            }
            Err(message) => {
                self.errors.insert(field, message);
            }
        }
    }

    /// Shows a problem next to a field and moves the focus to it, opening the
    /// Advanced section if the field is in it.
    pub fn show_error(&mut self, field: FormField, message: impl Into<String>) {
        self.errors.insert(field, message.into());
        if field.is_advanced() {
            self.advanced_open = true;
        }
        self.focus = field;
    }

    /// Builds the host from the form, or lists every problem. Every field is
    /// checked and marked, and the focus goes to the first one that is wrong.
    pub fn build(&mut self, hosts: &Hosts) -> Result<Host, Vec<(FormField, String)>> {
        let mut problems = Vec::new();
        let mut host = self.original.clone().unwrap_or_else(|| Host::new("", ""));

        let mut note = |field: FormField, result: Result<(), String>| {
            if let Err(message) = result {
                problems.push((field, message));
            }
        };
        for field in TEXT_FIELDS {
            note(field, self.check(field, hosts));
        }

        if problems.is_empty() {
            // Every field parsed above, so these cannot fail; they are read
            // again here to get the values.
            host.name = fields::parse_name(self.text(FormField::Name)).unwrap_or_default();
            host.hostname =
                fields::parse_hostname(self.text(FormField::Hostname)).unwrap_or_default();
            host.user = fields::parse_user(self.text(FormField::User)).unwrap_or_default();
            host.port = fields::parse_port(self.text(FormField::Port)).unwrap_or_default();
            host.identity_file =
                fields::parse_identity_file(self.text(FormField::IdentityFile)).unwrap_or_default();
            host.tags = fields::parse_tags(self.text(FormField::Tags)).unwrap_or_default();
            host.notes = fields::parse_notes(self.text(FormField::Notes)).unwrap_or_default();
            host.local_forwards =
                fields::parse_forwards(self.text(FormField::LocalForwards), Field::LocalForward)
                    .unwrap_or_default();
            host.remote_forwards =
                fields::parse_forwards(self.text(FormField::RemoteForwards), Field::RemoteForward)
                    .unwrap_or_default();
            host.proxy_jump = self.jump.clone();
            host.forward_agent = self.forward_agent;
            self.errors.clear();
            return Ok(host);
        }

        self.errors.clear();
        for (field, message) in &problems {
            self.errors.insert(*field, message.clone());
        }
        if let Some((field, _)) = problems.first() {
            let field = *field;
            if field.is_advanced() {
                self.advanced_open = true;
            }
            self.focus = field;
        }
        Err(problems)
    }

    // ---- keys --------------------------------------------------------------

    /// Ctrl+C. Returns whether the app should quit. With unsaved changes it
    /// asks for confirmation first; pressing it again quits.
    pub fn ctrl_c(&mut self) -> bool {
        if self.mode == FormMode::ConfirmDiscard || !self.is_dirty() {
            return true;
        }
        self.mode = FormMode::ConfirmDiscard;
        false
    }

    /// Applies a key press. `hosts` are the saved hosts, for checking that a
    /// name is free and for the jump host list.
    pub fn handle_key(&mut self, key: KeyEvent, hosts: &Hosts) -> Outcome {
        self.notice = None;
        match self.mode {
            FormMode::ConfirmDiscard => return self.confirm_key(key),
            FormMode::PickJump(_) => {
                self.pick_key(key);
                return Outcome::Stay;
            }
            FormMode::PickKey(_) => {
                self.pick_key_file(key);
                return Outcome::Stay;
            }
            FormMode::Editing => {}
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return if key.code == KeyCode::Char('s') {
                Outcome::Save
            } else {
                Outcome::Stay
            };
        }
        if key.modifiers.contains(KeyModifiers::ALT) {
            return Outcome::Stay;
        }

        match key.code {
            KeyCode::Esc => {
                if !self.is_dirty() {
                    return Outcome::Close;
                }
                self.mode = FormMode::ConfirmDiscard;
            }
            KeyCode::BackTab | KeyCode::Up => self.move_focus(-1, hosts),
            KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.move_focus(-1, hosts);
            }
            KeyCode::Tab | KeyCode::Down => self.move_focus(1, hosts),
            KeyCode::Enter => return self.activate(hosts),
            KeyCode::Char(' ') if !self.focus.is_text() => return self.activate(hosts),
            _ => {
                let changed = self
                    .inputs
                    .get_mut(&self.focus)
                    .is_some_and(|input| input.handle_key(key));
                if changed {
                    // What was wrong is being fixed; check again on leaving.
                    self.errors.remove(&self.focus);
                }
            }
        }
        Outcome::Stay
    }

    fn move_focus(&mut self, step: isize, hosts: &Hosts) {
        self.validate_field(self.focus, hosts);
        let order = self.fields();
        let at = order.iter().position(|f| *f == self.focus).unwrap_or(0);
        let len = isize::try_from(order.len()).unwrap_or(1);
        let next = (isize::try_from(at).unwrap_or(0) + step).rem_euclid(len);
        self.focus = order[usize::try_from(next).unwrap_or(0)];
    }

    /// Enter (or Space on a row that is not a text box).
    fn activate(&mut self, hosts: &Hosts) -> Outcome {
        match self.focus {
            FormField::IdentityFile => {
                return if self.keys.is_some() {
                    self.open_key_list();
                    Outcome::Stay
                } else {
                    Outcome::NeedKeys
                };
            }
            FormField::Advanced => self.advanced_open = !self.advanced_open,
            FormField::ForwardAgent => self.forward_agent = !self.forward_agent,
            FormField::ProxyJump => {
                let options: Vec<Option<String>> = std::iter::once(None)
                    .chain(
                        jump_candidates(hosts, self.original_name())
                            .into_iter()
                            .map(Some),
                    )
                    .collect();
                let selected = options
                    .iter()
                    .position(|option| option.as_deref() == self.jump.as_deref())
                    .unwrap_or(0);
                self.mode = FormMode::PickJump(Picker { options, selected });
            }
            _ => self.move_focus(1, hosts),
        }
        Outcome::Stay
    }

    /// Gives the form the keys that were read, and opens the list of them. Only
    /// while the identity file is what the form is on: a list that arrives after
    /// the user moved on is kept for next time and not shown.
    ///
    /// A key whose path the form would refuse (for example one that starts with
    /// `-`) is left out, so the list never offers what saving would then reject.
    pub fn open_key_picker(&mut self, mut list: KeyList) {
        list.choices
            .retain(|choice| fields::parse_identity_file(&choice.value).is_ok());
        self.keys = Some(list);
        if self.mode == FormMode::Editing && self.focus == FormField::IdentityFile {
            self.open_key_list();
        }
    }

    /// Opens the list of keys, with what is typed now selected.
    fn open_key_list(&mut self) {
        let list = self.keys.clone().unwrap_or_default();
        let text = self.text(FormField::IdentityFile).trim().to_string();
        let mut options = vec![KeyPick::None];
        options.extend(list.choices.iter().cloned().map(KeyPick::Key));
        options.push(KeyPick::Typed);
        let another = options.len() - 1;
        let selected = if text.is_empty() {
            0
        } else {
            list.choices
                .iter()
                .position(|choice| choice.value == text || choice.full_path == text)
                .map_or(another, |at| at + 1)
        };
        self.mode = FormMode::PickKey(KeyPicker {
            typed: (selected == another && !text.is_empty()).then_some(text),
            options,
            selected,
            note: list.note,
        });
    }

    fn pick_key_file(&mut self, key: KeyEvent) {
        let FormMode::PickKey(picker) = &mut self.mode else {
            return;
        };
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => picker.selected = picker.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                picker.selected = (picker.selected + 1).min(picker.options.len() - 1);
            }
            KeyCode::Home => picker.selected = 0,
            KeyCode::End => picker.selected = picker.options.len() - 1,
            KeyCode::Enter => {
                let chosen = picker.options[picker.selected].clone();
                self.mode = FormMode::Editing;
                match chosen {
                    KeyPick::None => {
                        self.inputs
                            .insert(FormField::IdentityFile, TextInput::new(""));
                    }
                    KeyPick::Key(choice) => {
                        self.inputs
                            .insert(FormField::IdentityFile, TextInput::new(choice.value));
                    }
                    // Back to the text box as it was, to type in.
                    KeyPick::Typed => {}
                }
                self.errors.remove(&FormField::IdentityFile);
            }
            KeyCode::Esc => self.mode = FormMode::Editing,
            _ => {}
        }
    }

    fn pick_key(&mut self, key: KeyEvent) {
        let FormMode::PickJump(picker) = &mut self.mode else {
            return;
        };
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => picker.selected = picker.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                picker.selected = (picker.selected + 1).min(picker.options.len() - 1);
            }
            KeyCode::Home => picker.selected = 0,
            KeyCode::End => picker.selected = picker.options.len() - 1,
            KeyCode::Enter => {
                self.jump = picker.options[picker.selected].clone();
                self.errors.remove(&FormField::ProxyJump);
                self.mode = FormMode::Editing;
            }
            KeyCode::Esc => self.mode = FormMode::Editing,
            _ => {}
        }
    }

    fn confirm_key(&mut self, key: KeyEvent) -> Outcome {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return Outcome::Stay;
        }
        match key.code {
            KeyCode::Char('y' | 'Y') => Outcome::Close,
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                self.mode = FormMode::Editing;
                Outcome::Stay
            }
            _ => Outcome::Stay,
        }
    }
}

/// The saved hosts that can be chosen as this host's jump host: those for which
/// the result would still be valid (no loops, chains within the limit, and no
/// pushing a host that hops through this one past the limit).
///
/// `editing` is the stored name of the host being edited, or `None` when adding.
/// Each candidate is tried against the real validation, so this can never offer
/// a choice that saving would then refuse.
pub fn jump_candidates(hosts: &Hosts, editing: Option<&str>) -> Vec<String> {
    let mut names: Vec<&str> = hosts
        .iter()
        .map(|host| host.name.as_str())
        .filter(|name| editing.is_none_or(|own| !name.eq_ignore_ascii_case(own)))
        .collect();
    names.sort_by_cached_key(|name| name.to_lowercase());

    let probe_name = (0..)
        .map(|n| format!("bifrost-probe-{n}"))
        .find(|name| hosts.get(name).is_none())
        .unwrap_or_default();

    names
        .into_iter()
        .filter(|candidate| {
            let mut trial = hosts.clone();
            match editing.and_then(|own| hosts.get(own)) {
                Some(own) => {
                    let mut changed = own.clone();
                    changed.proxy_jump = Some((*candidate).to_string());
                    trial.update(&own.name, changed).is_ok()
                }
                None => {
                    let mut probe = Host::new(probe_name.clone(), "probe.invalid");
                    probe.proxy_jump = Some((*candidate).to_string());
                    trial.add(probe).is_ok()
                }
            }
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ch(c: char) -> KeyEvent {
        press(KeyCode::Char(c))
    }

    fn with(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn host(name: &str) -> Host {
        Host::new(name, format!("{name}.example.com"))
    }

    fn hosts(list: Vec<Host>) -> Hosts {
        Hosts::from_vec(list).unwrap()
    }

    fn sample() -> Hosts {
        hosts(vec![host("web"), host("db"), host("bastion")])
    }

    fn type_text(form: &mut Form, hosts: &Hosts, text: &str) {
        for c in text.chars() {
            form.handle_key(ch(c), hosts);
        }
    }

    fn tab(form: &mut Form, hosts: &Hosts) {
        form.handle_key(press(KeyCode::Tab), hosts);
    }

    /// Fills a new form with a valid minimal host, leaving the focus on Notes.
    fn fill_minimal(form: &mut Form, hosts: &Hosts) {
        type_text(form, hosts, "app");
        tab(form, hosts);
        type_text(form, hosts, "app.example.com");
    }

    fn focus_on(form: &mut Form, hosts: &Hosts, field: FormField) {
        for _ in 0..20 {
            if form.focus() == field {
                return;
            }
            tab(form, hosts);
        }
        panic!("could not reach {field:?}");
    }

    // ---- start -------------------------------------------------------------

    #[test]
    fn a_new_form_is_empty_clean_and_focused_on_the_name() {
        let form = Form::add();
        assert_eq!(form.title(), "Add host");
        assert_eq!(form.focus(), FormField::Name);
        assert_eq!(form.mode(), &FormMode::Editing);
        assert!(!form.is_dirty());
        assert!(!form.advanced_open());
        assert_eq!(form.original_name(), None);
        for field in TEXT_FIELDS {
            assert!(form.input(field).unwrap().is_empty(), "{field:?}");
        }
    }

    #[test]
    fn an_edit_form_is_filled_in_from_the_host() {
        let mut h = host("web");
        h.user = Some("deploy".to_string());
        h.port = Some(2222);
        h.identity_file = Some("~/.ssh/id_ed25519".to_string());
        h.tags = vec!["prod".to_string(), "eu".to_string()];
        h.notes = Some("line one\nline two".to_string());
        let form = Form::edit(&h);

        assert_eq!(form.title(), "Edit host 'web'");
        assert_eq!(form.original_name(), Some("web"));
        assert_eq!(form.input(FormField::Name).unwrap().value(), "web");
        assert_eq!(form.input(FormField::User).unwrap().value(), "deploy");
        assert_eq!(form.input(FormField::Port).unwrap().value(), "2222");
        assert_eq!(form.input(FormField::Tags).unwrap().value(), "prod, eu");
        assert_eq!(
            form.input(FormField::Notes).unwrap().value(),
            "line one\\nline two"
        );
        assert!(!form.is_dirty(), "opening a form changes nothing");
    }

    // ---- navigation --------------------------------------------------------

    #[test]
    fn the_collapsed_form_has_seven_fields_and_the_advanced_row() {
        let form = Form::add();
        let rows = form.fields();
        assert_eq!(rows.len(), 8);
        assert_eq!(rows[..7], BASIC);
        assert_eq!(rows[7], FormField::Advanced);
    }

    #[test]
    fn tab_and_shift_tab_move_through_the_fields_in_order() {
        let hosts = sample();
        let mut form = Form::add();
        let mut seen = vec![form.focus()];
        for _ in 0..7 {
            tab(&mut form, &hosts);
            seen.push(form.focus());
        }
        assert_eq!(seen[..7], BASIC);
        assert_eq!(seen[7], FormField::Advanced);

        for expected in seen.iter().rev().skip(1) {
            form.handle_key(press(KeyCode::BackTab), &hosts);
            assert_eq!(form.focus(), *expected);
        }
    }

    #[test]
    fn shift_tab_can_also_arrive_as_tab_with_shift() {
        let hosts = sample();
        let mut form = Form::add();
        tab(&mut form, &hosts);
        form.handle_key(with(KeyCode::Tab, KeyModifiers::SHIFT), &hosts);
        assert_eq!(form.focus(), FormField::Name);
    }

    #[test]
    fn navigation_wraps_around_at_both_ends() {
        let hosts = sample();
        let mut form = Form::add();
        form.handle_key(press(KeyCode::BackTab), &hosts);
        assert_eq!(
            form.focus(),
            FormField::Advanced,
            "back from the first goes to the last"
        );
        tab(&mut form, &hosts);
        assert_eq!(form.focus(), FormField::Name);
    }

    #[test]
    fn up_and_down_work_like_shift_tab_and_tab() {
        let hosts = sample();
        let mut form = Form::add();
        form.handle_key(press(KeyCode::Down), &hosts);
        assert_eq!(form.focus(), FormField::Hostname);
        form.handle_key(press(KeyCode::Up), &hosts);
        assert_eq!(form.focus(), FormField::Name);
    }

    #[test]
    fn enter_in_a_text_field_moves_to_the_next_one() {
        let hosts = sample();
        let mut form = Form::add();
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert_eq!(form.focus(), FormField::Hostname);
    }

    #[test]
    fn typing_goes_to_the_focused_field_only() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "web1");
        tab(&mut form, &hosts);
        type_text(&mut form, &hosts, "h");
        assert_eq!(form.input(FormField::Name).unwrap().value(), "web1");
        assert_eq!(form.input(FormField::Hostname).unwrap().value(), "h");
        assert!(form.input(FormField::User).unwrap().is_empty());
    }

    #[test]
    fn editing_keys_work_inside_a_field() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "webb");
        form.handle_key(press(KeyCode::Backspace), &hosts);
        form.handle_key(press(KeyCode::Home), &hosts);
        type_text(&mut form, &hosts, "x");
        assert_eq!(form.input(FormField::Name).unwrap().value(), "xweb");
        assert_eq!(form.focus(), FormField::Name, "Home stays in the field");
    }

    #[test]
    fn typing_makes_the_form_dirty_and_undoing_it_makes_it_clean_again() {
        let hosts = sample();
        let mut form = Form::add();
        assert!(!form.is_dirty());
        type_text(&mut form, &hosts, "a");
        assert!(form.is_dirty());
        form.handle_key(press(KeyCode::Backspace), &hosts);
        assert!(!form.is_dirty());
    }

    // ---- validation on leaving a field -------------------------------------

    #[test]
    fn a_field_is_checked_when_the_focus_leaves_it() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "bad name");
        assert_eq!(form.error(FormField::Name), None, "not while typing");
        tab(&mut form, &hosts);
        let error = form.error(FormField::Name).unwrap();
        assert!(error.contains("may only contain"), "{error}");
    }

    #[test]
    fn a_required_field_left_empty_is_an_error() {
        let hosts = sample();
        let mut form = Form::add();
        tab(&mut form, &hosts);
        assert!(
            form.error(FormField::Name)
                .unwrap()
                .contains("cannot be empty")
        );
    }

    #[test]
    fn an_error_disappears_as_soon_as_the_user_edits_the_field() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "bad name");
        tab(&mut form, &hosts);
        form.handle_key(press(KeyCode::BackTab), &hosts);
        assert!(form.error(FormField::Name).is_some());
        form.handle_key(press(KeyCode::Backspace), &hosts);
        assert_eq!(form.error(FormField::Name), None);
    }

    #[test]
    fn a_fixed_field_is_clean_after_leaving_it_again() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "bad name");
        tab(&mut form, &hosts);
        form.handle_key(press(KeyCode::BackTab), &hosts);
        for _ in 0.."bad name".len() {
            form.handle_key(press(KeyCode::Backspace), &hosts);
        }
        type_text(&mut form, &hosts, "good-name");
        tab(&mut form, &hosts);
        assert_eq!(form.error(FormField::Name), None);
    }

    #[test]
    fn each_field_reports_its_own_error() {
        let hosts = sample();
        let mut form = Form::add();
        fill_minimal(&mut form, &hosts);
        focus_on(&mut form, &hosts, FormField::Port);
        type_text(&mut form, &hosts, "99999");
        tab(&mut form, &hosts);
        assert!(
            form.error(FormField::Port)
                .unwrap()
                .contains("between 1 and 65535")
        );
        assert_eq!(form.error(FormField::Name), None);
        assert_eq!(form.error(FormField::Hostname), None);
    }

    #[test]
    fn a_name_that_is_already_taken_is_reported_when_leaving_the_field() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "WEB");
        tab(&mut form, &hosts);
        let error = form.error(FormField::Name).unwrap();
        assert!(error.contains("already exists"), "{error}");
        assert!(error.contains("not case-sensitive"), "{error}");
    }

    #[test]
    fn a_host_may_keep_its_own_name_or_change_only_its_case() {
        let hosts = sample();
        let mut form = Form::edit(hosts.get("web").unwrap());
        tab(&mut form, &hosts);
        assert_eq!(
            form.error(FormField::Name),
            None,
            "its own name is not a clash"
        );

        form.handle_key(press(KeyCode::BackTab), &hosts);
        form.handle_key(press(KeyCode::Home), &hosts);
        form.handle_key(press(KeyCode::Delete), &hosts);
        type_text(&mut form, &hosts, "W");
        tab(&mut form, &hosts);
        assert_eq!(form.error(FormField::Name), None, "Web is still web");
    }

    #[test]
    fn renaming_to_another_hosts_name_is_a_clash() {
        let hosts = sample();
        let mut form = Form::edit(hosts.get("web").unwrap());
        for _ in 0..3 {
            form.handle_key(press(KeyCode::Backspace), &hosts);
        }
        type_text(&mut form, &hosts, "db");
        tab(&mut form, &hosts);
        assert!(
            form.error(FormField::Name)
                .unwrap()
                .contains("already exists")
        );
    }

    // ---- saving ------------------------------------------------------------

    #[test]
    fn saving_is_blocked_while_any_field_is_invalid() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "app");
        // The hostname was never filled in.
        let problems = form.build(&hosts).unwrap_err();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].0, FormField::Hostname);
        assert_eq!(
            form.focus(),
            FormField::Hostname,
            "the focus goes to the problem"
        );
        assert!(form.error(FormField::Hostname).is_some());
    }

    #[test]
    fn every_invalid_field_is_marked_at_once() {
        let hosts = sample();
        let mut form = Form::add();
        focus_on(&mut form, &hosts, FormField::Port);
        type_text(&mut form, &hosts, "abc");
        let problems = form.build(&hosts).unwrap_err();
        let fields: Vec<_> = problems.iter().map(|(f, _)| *f).collect();
        assert_eq!(
            fields,
            [FormField::Name, FormField::Hostname, FormField::Port]
        );
        for field in fields {
            assert!(form.error(field).is_some(), "{field:?}");
        }
        assert_eq!(
            form.focus(),
            FormField::Name,
            "the first problem in form order"
        );
    }

    #[test]
    fn a_valid_form_builds_the_host() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, " app ");
        tab(&mut form, &hosts);
        type_text(&mut form, &hosts, "app.example.com");
        tab(&mut form, &hosts);
        type_text(&mut form, &hosts, "deploy");
        tab(&mut form, &hosts);
        type_text(&mut form, &hosts, "2222");
        tab(&mut form, &hosts);
        type_text(&mut form, &hosts, "~/.ssh/id_ed25519");
        tab(&mut form, &hosts);
        type_text(&mut form, &hosts, "prod, web");
        tab(&mut form, &hosts);
        type_text(&mut form, &hosts, "one\\ntwo");

        let host = form.build(&hosts).unwrap();

        assert_eq!(host.name, "app", "surrounding spaces are dropped");
        assert_eq!(host.hostname, "app.example.com");
        assert_eq!(host.user.as_deref(), Some("deploy"));
        assert_eq!(host.port, Some(2222));
        assert_eq!(host.identity_file.as_deref(), Some("~/.ssh/id_ed25519"));
        assert_eq!(host.tags, ["prod", "web"]);
        assert_eq!(host.notes.as_deref(), Some("one\ntwo"));
        assert!(!host.favorite);
        assert!(!form.has_errors());
    }

    #[test]
    fn optional_fields_left_empty_are_not_set() {
        let hosts = sample();
        let mut form = Form::add();
        fill_minimal(&mut form, &hosts);
        let host = form.build(&hosts).unwrap();
        assert_eq!(host.user, None);
        assert_eq!(host.port, None);
        assert_eq!(host.identity_file, None);
        assert!(host.tags.is_empty());
        assert_eq!(host.notes, None);
        assert_eq!(host.proxy_jump, None);
        assert!(host.local_forwards.is_empty() && host.remote_forwards.is_empty());
        assert!(!host.forward_agent);
    }

    #[test]
    fn editing_keeps_what_the_form_does_not_show() {
        let mut original = host("web");
        original.favorite = true;
        let hosts = hosts(vec![original.clone()]);
        let mut form = Form::edit(&original);
        type_text(&mut form, &hosts, "2");
        let edited = form.build(&hosts).unwrap();
        assert_eq!(edited.name, "web2");
        assert!(edited.favorite, "the favorite flag is not lost");
    }

    #[test]
    fn ctrl_s_asks_to_save_and_other_ctrl_and_alt_keys_do_nothing() {
        let hosts = sample();
        let mut form = Form::add();
        assert_eq!(
            form.handle_key(with(KeyCode::Char('s'), KeyModifiers::CONTROL), &hosts),
            Outcome::Save
        );
        for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            assert_eq!(
                form.handle_key(with(KeyCode::Char('x'), modifiers), &hosts),
                Outcome::Stay
            );
        }
        assert!(form.input(FormField::Name).unwrap().is_empty());
    }

    // ---- cancelling --------------------------------------------------------

    #[test]
    fn esc_closes_a_form_with_no_changes_at_once() {
        let hosts = sample();
        let mut form = Form::add();
        assert_eq!(form.handle_key(press(KeyCode::Esc), &hosts), Outcome::Close);
    }

    #[test]
    fn esc_with_unsaved_changes_asks_first() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "app");
        assert_eq!(form.handle_key(press(KeyCode::Esc), &hosts), Outcome::Stay);
        assert_eq!(form.mode(), &FormMode::ConfirmDiscard);
    }

    #[test]
    fn answering_n_or_esc_keeps_editing_with_the_input_intact() {
        let hosts = sample();
        for answer in [ch('n'), ch('N'), press(KeyCode::Esc)] {
            let mut form = Form::add();
            type_text(&mut form, &hosts, "app");
            form.handle_key(press(KeyCode::Esc), &hosts);
            assert_eq!(form.handle_key(answer, &hosts), Outcome::Stay);
            assert_eq!(form.mode(), &FormMode::Editing);
            assert_eq!(form.input(FormField::Name).unwrap().value(), "app");
        }
    }

    #[test]
    fn answering_y_discards_the_changes() {
        let hosts = sample();
        for answer in [ch('y'), ch('Y')] {
            let mut form = Form::add();
            type_text(&mut form, &hosts, "app");
            form.handle_key(press(KeyCode::Esc), &hosts);
            assert_eq!(form.handle_key(answer, &hosts), Outcome::Close);
        }
    }

    #[test]
    fn other_keys_are_ignored_while_asking_to_discard() {
        let hosts = sample();
        let mut form = Form::add();
        type_text(&mut form, &hosts, "app");
        form.handle_key(press(KeyCode::Esc), &hosts);
        for key in [ch('x'), press(KeyCode::Enter), press(KeyCode::Tab), ch('q')] {
            assert_eq!(form.handle_key(key, &hosts), Outcome::Stay);
        }
        assert_eq!(form.mode(), &FormMode::ConfirmDiscard);
        assert_eq!(form.input(FormField::Name).unwrap().value(), "app");
    }

    #[test]
    fn ctrl_c_quits_a_clean_form_but_asks_about_a_dirty_one() {
        let hosts = sample();
        let mut clean = Form::add();
        assert!(clean.ctrl_c());

        let mut dirty = Form::add();
        type_text(&mut dirty, &hosts, "app");
        assert!(!dirty.ctrl_c(), "the first Ctrl+C only asks");
        assert_eq!(dirty.mode(), &FormMode::ConfirmDiscard);
        assert!(dirty.ctrl_c(), "the second one means it");
    }

    // ---- the advanced section ----------------------------------------------

    #[test]
    fn enter_on_the_advanced_row_shows_and_hides_the_section() {
        let hosts = sample();
        let mut form = Form::add();
        focus_on(&mut form, &hosts, FormField::Advanced);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert!(form.advanced_open());
        assert_eq!(form.fields().len(), 12);
        assert_eq!(form.fields()[8..], ADVANCED);
        assert_eq!(
            form.focus(),
            FormField::Advanced,
            "the focus stays on the row"
        );
        form.handle_key(ch(' '), &hosts);
        assert!(!form.advanced_open());
        assert_eq!(form.fields().len(), 8);
    }

    #[test]
    fn tab_reaches_the_advanced_fields_only_when_they_are_shown() {
        let hosts = sample();
        let mut form = Form::add();
        focus_on(&mut form, &hosts, FormField::Advanced);
        tab(&mut form, &hosts);
        assert_eq!(
            form.focus(),
            FormField::Name,
            "collapsed: back to the start"
        );

        focus_on(&mut form, &hosts, FormField::Advanced);
        form.handle_key(press(KeyCode::Enter), &hosts);
        tab(&mut form, &hosts);
        assert_eq!(form.focus(), FormField::ProxyJump);
    }

    #[test]
    fn a_host_with_advanced_settings_opens_with_the_section_shown() {
        let mut h = host("web");
        h.forward_agent = true;
        assert!(Form::edit(&h).advanced_open());
        let mut h = host("web");
        h.local_forwards = vec![crate::domain::Forward {
            listen_port: 8080,
            dest_host: "localhost".to_string(),
            dest_port: 80,
        }];
        assert!(Form::edit(&h).advanced_open());
        assert!(!Form::edit(&host("web")).advanced_open());
    }

    #[test]
    fn an_error_in_an_advanced_field_opens_the_section_and_focuses_it() {
        let hosts = sample();
        let mut form = Form::add();
        form.show_error(FormField::ProxyJump, "The jump host does not exist.");
        assert!(form.advanced_open());
        assert_eq!(form.focus(), FormField::ProxyJump);
        assert!(form.error(FormField::ProxyJump).is_some());
        let _ = hosts;
    }

    #[test]
    fn forwards_are_validated_when_leaving_their_field() {
        let hosts = sample();
        let mut form = Form::add();
        focus_on(&mut form, &hosts, FormField::Advanced);
        form.handle_key(press(KeyCode::Enter), &hosts);
        focus_on(&mut form, &hosts, FormField::LocalForwards);
        type_text(&mut form, &hosts, "8080");
        tab(&mut form, &hosts);
        assert!(
            form.error(FormField::LocalForwards)
                .unwrap()
                .contains("listen-port:host:port")
        );
    }

    #[test]
    fn forwards_and_agent_forwarding_end_up_in_the_host() {
        let hosts = sample();
        let mut form = Form::add();
        fill_minimal(&mut form, &hosts);
        focus_on(&mut form, &hosts, FormField::Advanced);
        form.handle_key(press(KeyCode::Enter), &hosts);
        focus_on(&mut form, &hosts, FormField::LocalForwards);
        type_text(&mut form, &hosts, "8080:localhost:80");
        focus_on(&mut form, &hosts, FormField::RemoteForwards);
        type_text(&mut form, &hosts, "9000:localhost:3000");
        focus_on(&mut form, &hosts, FormField::ForwardAgent);
        form.handle_key(ch(' '), &hosts);

        let host = form.build(&hosts).unwrap();

        assert_eq!(host.local_forwards.len(), 1);
        assert_eq!(host.local_forwards[0].listen_port, 8080);
        assert_eq!(host.remote_forwards[0].dest_port, 3000);
        assert!(host.forward_agent);
    }

    #[test]
    fn forward_agent_is_off_by_default_and_toggles_with_space_or_enter() {
        let hosts = sample();
        let mut form = Form::add();
        assert!(!form.forward_agent());
        focus_on(&mut form, &hosts, FormField::Advanced);
        form.handle_key(press(KeyCode::Enter), &hosts);
        focus_on(&mut form, &hosts, FormField::ForwardAgent);
        form.handle_key(ch(' '), &hosts);
        assert!(form.forward_agent());
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert!(!form.forward_agent());
        assert_eq!(
            form.focus(),
            FormField::ForwardAgent,
            "toggling does not move"
        );
    }

    // ---- the jump host list ------------------------------------------------

    fn open_picker(form: &mut Form, hosts: &Hosts) {
        focus_on(form, hosts, FormField::Advanced);
        form.handle_key(press(KeyCode::Enter), hosts);
        focus_on(form, hosts, FormField::ProxyJump);
        form.handle_key(press(KeyCode::Enter), hosts);
    }

    fn picker(form: &Form) -> &Picker {
        match form.mode() {
            FormMode::PickJump(picker) => picker,
            other => panic!("expected the picker, got {other:?}"),
        }
    }

    #[test]
    fn the_jump_host_is_picked_from_a_list_of_saved_hosts() {
        let hosts = sample();
        let mut form = Form::add();
        open_picker(&mut form, &hosts);
        let options = picker(&form).options.clone();
        assert_eq!(
            options,
            [
                None,
                Some("bastion".to_string()),
                Some("db".to_string()),
                Some("web".to_string())
            ]
        );
        assert_eq!(picker(&form).selected, 0, "(none) is selected first");
    }

    #[test]
    fn choosing_from_the_list_sets_the_jump_host() {
        let hosts = sample();
        let mut form = Form::add();
        fill_minimal(&mut form, &hosts);
        open_picker(&mut form, &hosts);
        form.handle_key(press(KeyCode::Down), &hosts);
        assert_eq!(picker(&form).selected, 1);
        form.handle_key(press(KeyCode::Enter), &hosts);

        assert_eq!(form.mode(), &FormMode::Editing);
        assert_eq!(form.jump(), Some("bastion"));
        assert_eq!(
            form.build(&hosts).unwrap().proxy_jump.as_deref(),
            Some("bastion")
        );
        assert!(form.is_dirty());
    }

    #[test]
    fn the_list_keys_j_and_k_and_home_end_move_the_choice() {
        let hosts = sample();
        let mut form = Form::add();
        open_picker(&mut form, &hosts);
        form.handle_key(ch('j'), &hosts);
        form.handle_key(ch('j'), &hosts);
        assert_eq!(picker(&form).selected, 2);
        form.handle_key(ch('k'), &hosts);
        assert_eq!(picker(&form).selected, 1);
        form.handle_key(press(KeyCode::End), &hosts);
        assert_eq!(picker(&form).selected, 3);
        form.handle_key(press(KeyCode::Down), &hosts);
        assert_eq!(picker(&form).selected, 3, "stops at the end");
        form.handle_key(press(KeyCode::Home), &hosts);
        form.handle_key(press(KeyCode::Up), &hosts);
        assert_eq!(picker(&form).selected, 0, "stops at the start");
    }

    #[test]
    fn esc_closes_the_list_without_changing_anything() {
        let hosts = sample();
        let mut form = Form::add();
        open_picker(&mut form, &hosts);
        form.handle_key(press(KeyCode::Down), &hosts);
        assert_eq!(form.handle_key(press(KeyCode::Esc), &hosts), Outcome::Stay);
        assert_eq!(form.mode(), &FormMode::Editing);
        assert_eq!(form.jump(), None);
    }

    #[test]
    fn typed_letters_do_nothing_in_the_list() {
        let hosts = sample();
        let mut form = Form::add();
        open_picker(&mut form, &hosts);
        for key in [ch('x'), ch('q'), press(KeyCode::Tab)] {
            form.handle_key(key, &hosts);
        }
        assert_eq!(picker(&form).selected, 0);
        assert!(matches!(form.mode(), FormMode::PickJump(_)));
    }

    #[test]
    fn the_current_jump_host_is_selected_when_the_list_opens() {
        let mut edited = host("app");
        edited.proxy_jump = Some("db".to_string());
        let hosts = hosts(vec![host("web"), host("db"), edited.clone()]);
        let mut form = Form::edit(&edited);
        assert!(form.advanced_open());
        focus_on(&mut form, &hosts, FormField::ProxyJump);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert_eq!(
            picker(&form).options[picker(&form).selected].as_deref(),
            Some("db")
        );
    }

    #[test]
    fn choosing_none_clears_the_jump_host() {
        let mut edited = host("app");
        edited.proxy_jump = Some("db".to_string());
        let hosts = hosts(vec![host("db"), edited.clone()]);
        let mut form = Form::edit(&edited);
        focus_on(&mut form, &hosts, FormField::ProxyJump);
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.handle_key(press(KeyCode::Home), &hosts);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert_eq!(form.jump(), None);
    }

    #[test]
    fn a_host_is_never_offered_as_its_own_jump_host() {
        let hosts = sample();
        assert!(!jump_candidates(&hosts, Some("web")).contains(&"web".to_string()));
        assert!(!jump_candidates(&hosts, Some("WEB")).contains(&"web".to_string()));
        assert_eq!(jump_candidates(&hosts, Some("web")), ["bastion", "db"]);
    }

    #[test]
    fn hosts_that_would_make_a_loop_are_not_offered() {
        // b hops through a. Editing a: offering b would make a loop.
        let mut b = host("b");
        b.proxy_jump = Some("a".to_string());
        let hosts = hosts(vec![host("a"), b, host("c")]);
        assert_eq!(jump_candidates(&hosts, Some("a")), ["c"]);
        // Adding a new host: every host is fine.
        assert_eq!(jump_candidates(&hosts, None), ["a", "b", "c"]);
    }

    #[test]
    fn a_chain_that_would_be_too_long_is_not_offered() {
        // h0 <- h1 <- h2 <- h3 <- h4 <- h5 (each hops through the previous one).
        let mut list = vec![host("h0")];
        for n in 1..=5 {
            let mut h = host(&format!("h{n}"));
            h.proxy_jump = Some(format!("h{}", n - 1));
            list.push(h);
        }
        let hosts = hosts(list);
        // A new host behind h5 would need six hops.
        assert!(!jump_candidates(&hosts, None).contains(&"h5".to_string()));
        assert!(jump_candidates(&hosts, None).contains(&"h4".to_string()));
    }

    #[test]
    fn a_jump_choice_that_would_push_a_dependent_over_the_limit_is_not_offered() {
        // x hops through y. Editing y: if y hopped through a 5-hop chain, x
        // would have six. Only hosts that keep everything valid are offered.
        let mut list = vec![host("h0")];
        for n in 1..=4 {
            let mut h = host(&format!("h{n}"));
            h.proxy_jump = Some(format!("h{}", n - 1));
            list.push(h);
        }
        let mut y = host("y");
        y.proxy_jump = None;
        let mut x = host("x");
        x.proxy_jump = Some("y".to_string());
        list.push(y);
        list.push(x);
        let hosts = hosts(list);
        let offered = jump_candidates(&hosts, Some("y"));
        assert!(offered.contains(&"h0".to_string()));
        assert!(!offered.contains(&"h4".to_string()), "{offered:?}");
    }

    #[test]
    fn with_no_other_hosts_the_only_choice_is_none() {
        let hosts = hosts(vec![host("web")]);
        assert!(jump_candidates(&hosts, Some("web")).is_empty());
        let mut form = Form::edit(hosts.get("web").unwrap());
        focus_on(&mut form, &hosts, FormField::Advanced);
        form.handle_key(press(KeyCode::Enter), &hosts);
        focus_on(&mut form, &hosts, FormField::ProxyJump);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert_eq!(picker(&form).options, [None]);
    }

    #[test]
    fn a_probe_name_never_clashes_with_a_real_host() {
        let hosts = hosts(vec![host("bifrost-probe-0"), host("web")]);
        assert_eq!(jump_candidates(&hosts, None), ["bifrost-probe-0", "web"]);
    }

    // ---- messages ----------------------------------------------------------

    #[test]
    fn a_notice_lasts_until_the_next_key() {
        let hosts = sample();
        let mut form = Form::add();
        form.set_notice("Could not save.");
        assert_eq!(form.notice(), Some("Could not save."));
        form.handle_key(ch('a'), &hosts);
        assert_eq!(form.notice(), None);
    }

    // ---- the list of key files -------------------------------------------------

    fn key(name: &str, kind: Option<&str>) -> KeyChoice {
        KeyChoice {
            name: name.to_string(),
            value: format!("~/.ssh/{name}"),
            full_path: format!("/home/dev/.ssh/{name}"),
            kind: kind.map(str::to_string),
        }
    }

    fn two_keys() -> KeyList {
        KeyList {
            choices: vec![
                key("id_ed25519", Some("ed25519")),
                key("id_rsa_old", Some("rsa 3072")),
            ],
            note: None,
        }
    }

    /// A form on the identity file, with the keys given and the list open.
    fn with_key_list(list: KeyList) -> (Form, Hosts) {
        let hosts = sample();
        let mut form = Form::add();
        focus_on(&mut form, &hosts, FormField::IdentityFile);
        assert_eq!(
            form.handle_key(press(KeyCode::Enter), &hosts),
            Outcome::NeedKeys
        );
        form.open_key_picker(list);
        (form, hosts)
    }

    fn key_picker(form: &Form) -> &KeyPicker {
        match form.mode() {
            FormMode::PickKey(picker) => picker,
            other => panic!("{other:?}"),
        }
    }

    fn type_identity(form: &mut Form, hosts: &Hosts, text: &str) {
        focus_on(form, hosts, FormField::IdentityFile);
        for c in text.chars() {
            form.handle_key(ch(c), hosts);
        }
    }

    #[test]
    fn enter_on_the_identity_file_asks_for_the_keys_and_on_other_fields_still_moves_on() {
        let hosts = sample();
        let mut form = Form::add();
        // Enter on the other text fields is what it was: to the next field.
        for field in [
            FormField::Name,
            FormField::Hostname,
            FormField::User,
            FormField::Port,
        ] {
            focus_on(&mut form, &hosts, field);
            assert_eq!(
                form.handle_key(press(KeyCode::Enter), &hosts),
                Outcome::Stay
            );
            assert_ne!(form.focus(), field, "{field:?} moved on");
        }
        assert_eq!(form.focus(), FormField::IdentityFile);
        // Here it asks for the keys, and stays put.
        assert_eq!(
            form.handle_key(press(KeyCode::Enter), &hosts),
            Outcome::NeedKeys
        );
        assert_eq!(form.focus(), FormField::IdentityFile);
        assert_eq!(form.mode(), &FormMode::Editing);
        // Tab still moves on, as always.
        form.handle_key(press(KeyCode::Tab), &hosts);
        assert_eq!(form.focus(), FormField::Tags);
    }

    #[test]
    fn the_list_offers_none_each_key_and_another_file_in_that_order() {
        let (form, _) = with_key_list(two_keys());
        let picker = key_picker(&form);
        assert_eq!(
            picker.options,
            [
                KeyPick::None,
                KeyPick::Key(key("id_ed25519", Some("ed25519"))),
                KeyPick::Key(key("id_rsa_old", Some("rsa 3072"))),
                KeyPick::Typed,
            ]
        );
        assert_eq!(picker.selected, 0, "none is selected when nothing is set");
        assert_eq!(picker.typed, None);
    }

    #[test]
    fn the_list_opens_on_the_key_the_field_already_has_however_it_is_spelled() {
        for text in [
            "~/.ssh/id_rsa_old",
            "/home/dev/.ssh/id_rsa_old",
            "  ~/.ssh/id_rsa_old  ",
        ] {
            let hosts = sample();
            let mut form = Form::add();
            type_identity(&mut form, &hosts, text);
            assert_eq!(
                form.handle_key(press(KeyCode::Enter), &hosts),
                Outcome::NeedKeys
            );
            form.open_key_picker(two_keys());
            assert_eq!(key_picker(&form).selected, 2, "{text:?}");
            assert_eq!(key_picker(&form).typed, None);
        }
    }

    #[test]
    fn a_path_that_is_not_one_of_the_keys_is_kept_on_the_another_file_line() {
        let hosts = sample();
        let mut form = Form::add();
        type_identity(&mut form, &hosts, "/elsewhere/key");
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.open_key_picker(two_keys());
        let picker = key_picker(&form);
        assert_eq!(picker.selected, 3);
        assert_eq!(picker.typed.as_deref(), Some("/elsewhere/key"));
    }

    #[test]
    fn the_keys_are_asked_for_once_and_kept_for_the_rest_of_the_form() {
        let (mut form, hosts) = with_key_list(two_keys());
        form.handle_key(press(KeyCode::Esc), &hosts);
        assert_eq!(form.mode(), &FormMode::Editing);
        // No second question: the list opens at once.
        assert_eq!(
            form.handle_key(press(KeyCode::Enter), &hosts),
            Outcome::Stay
        );
        assert!(matches!(form.mode(), FormMode::PickKey(_)));
    }

    #[test]
    fn choosing_a_key_puts_its_path_in_the_field_and_the_host_gets_it() {
        let (mut form, hosts) = with_key_list(two_keys());
        form.handle_key(ch('j'), &hosts);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert_eq!(form.mode(), &FormMode::Editing);
        assert_eq!(
            form.input(FormField::IdentityFile).unwrap().value(),
            "~/.ssh/id_ed25519"
        );
        assert_eq!(form.focus(), FormField::IdentityFile);
        assert!(form.is_dirty());

        let mut named = form;
        type_into_name(&mut named, &hosts);
        assert_eq!(
            named.build(&hosts).unwrap().identity_file.as_deref(),
            Some("~/.ssh/id_ed25519")
        );
    }

    /// Fills the name and hostname so that the form can be built.
    fn type_into_name(form: &mut Form, hosts: &Hosts) {
        focus_on(form, hosts, FormField::Name);
        for c in "app".chars() {
            form.handle_key(ch(c), hosts);
        }
        focus_on(form, hosts, FormField::Hostname);
        for c in "app.example.com".chars() {
            form.handle_key(ch(c), hosts);
        }
    }

    #[test]
    fn choosing_none_clears_the_identity_file() {
        let hosts = sample();
        let mut form = Form::add();
        type_identity(&mut form, &hosts, "~/.ssh/id_ed25519");
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.open_key_picker(two_keys());
        assert_eq!(key_picker(&form).selected, 1, "the key it has is selected");
        form.handle_key(press(KeyCode::Home), &hosts);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert_eq!(form.input(FormField::IdentityFile).unwrap().value(), "");
        type_into_name(&mut form, &hosts);
        assert_eq!(form.build(&hosts).unwrap().identity_file, None);
    }

    #[test]
    fn choosing_another_file_leaves_the_box_as_it_was_for_typing() {
        let hosts = sample();
        let mut form = Form::add();
        type_identity(&mut form, &hosts, "/elsewhere/key");
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.open_key_picker(two_keys());
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert_eq!(form.mode(), &FormMode::Editing);
        assert_eq!(
            form.input(FormField::IdentityFile).unwrap().value(),
            "/elsewhere/key"
        );
        // And typing goes on where it was.
        form.handle_key(ch('2'), &hosts);
        assert_eq!(
            form.input(FormField::IdentityFile).unwrap().value(),
            "/elsewhere/key2"
        );
    }

    #[test]
    fn esc_closes_the_list_and_changes_nothing() {
        let hosts = sample();
        let mut form = Form::add();
        type_identity(&mut form, &hosts, "~/.ssh/mine");
        let dirty = form.is_dirty();
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.open_key_picker(two_keys());
        form.handle_key(press(KeyCode::Down), &hosts);
        form.handle_key(press(KeyCode::Esc), &hosts);
        assert_eq!(form.mode(), &FormMode::Editing);
        assert_eq!(
            form.input(FormField::IdentityFile).unwrap().value(),
            "~/.ssh/mine"
        );
        assert_eq!(form.is_dirty(), dirty);
    }

    #[test]
    fn choosing_clears_a_complaint_about_the_field() {
        let hosts = sample();
        let mut form = Form::add();
        type_identity(&mut form, &hosts, "/x/key.pub");
        form.handle_key(press(KeyCode::Tab), &hosts);
        assert!(form.error(FormField::IdentityFile).is_some());
        focus_on(&mut form, &hosts, FormField::IdentityFile);
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.open_key_picker(two_keys());
        form.handle_key(press(KeyCode::Home), &hosts);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert!(form.error(FormField::IdentityFile).is_none());
    }

    #[test]
    fn a_key_whose_path_the_form_would_refuse_is_not_offered() {
        let list = KeyList {
            choices: vec![
                key("fine", Some("ed25519")),
                KeyChoice {
                    name: "odd.pub".to_string(),
                    value: "~/.ssh/odd.pub".to_string(),
                    full_path: "/home/dev/.ssh/odd.pub".to_string(),
                    kind: None,
                },
                KeyChoice {
                    name: "ctl".to_string(),
                    value: "~/.ssh/ctl\u{7}".to_string(),
                    full_path: String::new(),
                    kind: None,
                },
            ],
            note: None,
        };
        let (form, _) = with_key_list(list);
        let names: Vec<&str> = key_picker(&form)
            .options
            .iter()
            .filter_map(|option| match option {
                KeyPick::Key(choice) => Some(choice.name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(names, ["fine"]);
    }

    #[test]
    fn with_no_keys_the_list_still_has_none_and_another_file_and_carries_the_note() {
        let (form, _) = with_key_list(KeyList {
            choices: Vec::new(),
            note: Some("There are no key pairs in /home/dev/.ssh.".to_string()),
        });
        let picker = key_picker(&form);
        assert_eq!(picker.options, [KeyPick::None, KeyPick::Typed]);
        assert_eq!(
            picker.note.as_deref(),
            Some("There are no key pairs in /home/dev/.ssh.")
        );
    }

    #[test]
    fn the_list_moves_stays_inside_and_ignores_typing_and_modifiers() {
        let (mut form, hosts) = with_key_list(two_keys());
        let at = |form: &Form| key_picker(form).selected;
        form.handle_key(press(KeyCode::Up), &hosts);
        assert_eq!(at(&form), 0);
        for _ in 0..10 {
            form.handle_key(ch('j'), &hosts);
        }
        assert_eq!(at(&form), 3);
        form.handle_key(ch('k'), &hosts);
        assert_eq!(at(&form), 2);
        form.handle_key(press(KeyCode::Home), &hosts);
        assert_eq!(at(&form), 0);
        form.handle_key(press(KeyCode::End), &hosts);
        assert_eq!(at(&form), 3);
        // Letters do not go into the box behind the list, and Ctrl/Alt do nothing.
        for key in [
            ch('x'),
            ch(' '),
            press(KeyCode::Tab),
            with(KeyCode::Char('s'), KeyModifiers::CONTROL),
            with(KeyCode::Enter, KeyModifiers::ALT),
            with(KeyCode::Char('j'), KeyModifiers::CONTROL),
        ] {
            assert_eq!(form.handle_key(key, &hosts), Outcome::Stay, "{key:?}");
            assert!(matches!(form.mode(), FormMode::PickKey(_)), "{key:?}");
            assert_eq!(form.input(FormField::IdentityFile).unwrap().value(), "");
        }
        assert_eq!(at(&form), 3, "none of those moved it");
    }

    #[test]
    fn keys_that_arrive_after_the_user_moved_on_are_kept_and_not_shown() {
        let hosts = sample();
        let mut form = Form::add();
        focus_on(&mut form, &hosts, FormField::IdentityFile);
        assert_eq!(
            form.handle_key(press(KeyCode::Enter), &hosts),
            Outcome::NeedKeys
        );
        // The user went on before the answer came.
        form.handle_key(press(KeyCode::Tab), &hosts);
        form.open_key_picker(two_keys());
        assert_eq!(form.mode(), &FormMode::Editing);
        // They are there for next time.
        focus_on(&mut form, &hosts, FormField::IdentityFile);
        assert_eq!(
            form.handle_key(press(KeyCode::Enter), &hosts),
            Outcome::Stay
        );
        assert!(matches!(form.mode(), FormMode::PickKey(_)));
    }

    #[test]
    fn a_question_about_discarding_is_not_covered_by_a_list_that_arrives_late() {
        let hosts = sample();
        let mut form = Form::add();
        type_identity(&mut form, &hosts, "x");
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.handle_key(press(KeyCode::Esc), &hosts);
        assert_eq!(form.mode(), &FormMode::ConfirmDiscard);
        form.open_key_picker(two_keys());
        assert_eq!(form.mode(), &FormMode::ConfirmDiscard);
    }

    #[test]
    fn ctrl_c_with_the_list_open_still_asks_before_throwing_changes_away() {
        let (mut form, hosts) = with_key_list(two_keys());
        form.handle_key(press(KeyCode::Down), &hosts);
        form.handle_key(press(KeyCode::Enter), &hosts);
        form.handle_key(press(KeyCode::Enter), &hosts);
        assert!(matches!(form.mode(), FormMode::PickKey(_)));
        assert!(form.is_dirty());
        assert!(!form.ctrl_c(), "unsaved changes: it asks first");
        assert_eq!(form.mode(), &FormMode::ConfirmDiscard);
    }

    #[test]
    fn the_other_fields_do_not_open_the_list_of_keys() {
        let hosts = sample();
        for field in [FormField::Name, FormField::Tags, FormField::Notes] {
            let mut form = Form::add();
            focus_on(&mut form, &hosts, field);
            assert_ne!(
                form.handle_key(press(KeyCode::Enter), &hosts),
                Outcome::NeedKeys
            );
            assert!(!matches!(form.mode(), FormMode::PickKey(_)));
        }
    }
}
