//! A single-line text editor: the state behind the search box, the form's text
//! fields and the delete confirmation.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Text with a cursor. The cursor counts characters, not bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextInput {
    text: String,
    cursor: usize,
}

impl TextInput {
    /// An input holding `text`, with the cursor at the end.
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let cursor = text.chars().count();
        TextInput { text, cursor }
    }

    pub fn value(&self) -> &str {
        &self.text
    }

    /// The cursor position, in characters from the start.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    fn byte_index(&self, chars: usize) -> usize {
        self.text
            .char_indices()
            .nth(chars)
            .map_or(self.text.len(), |(index, _)| index)
    }

    /// Inserts a character at the cursor. Control characters are refused.
    pub fn insert(&mut self, c: char) -> bool {
        if c.is_control() {
            return false;
        }
        let at = self.byte_index(self.cursor);
        self.text.insert(at, c);
        self.cursor += 1;
        true
    }

    pub fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        self.cursor -= 1;
        let at = self.byte_index(self.cursor);
        self.text.remove(at);
        true
    }

    pub fn delete(&mut self) -> bool {
        if self.cursor >= self.text.chars().count() {
            return false;
        }
        let at = self.byte_index(self.cursor);
        self.text.remove(at);
        true
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.text.chars().count());
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.text.chars().count();
    }

    /// Applies an editing key. Returns whether the *text* changed; moving the
    /// cursor, or a key that is not an editing key, returns `false`.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return false;
        }
        match key.code {
            KeyCode::Char(c) => self.insert(c),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => {
                self.left();
                false
            }
            KeyCode::Right => {
                self.right();
                false
            }
            KeyCode::Home => {
                self.home();
                false
            }
            KeyCode::End => {
                self.end();
                false
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn typed(input: &mut TextInput, text: &str) {
        for c in text.chars() {
            input.handle_key(key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn typing_appends_and_moves_the_cursor() {
        let mut input = TextInput::default();
        typed(&mut input, "web");
        assert_eq!(input.value(), "web");
        assert_eq!(input.cursor(), 3);
    }

    #[test]
    fn new_puts_the_cursor_at_the_end() {
        let input = TextInput::new("héllo");
        assert_eq!(input.cursor(), 5);
    }

    #[test]
    fn insertion_happens_at_the_cursor() {
        let mut input = TextInput::new("wb");
        input.left();
        input.insert('e');
        assert_eq!(input.value(), "web");
        assert_eq!(input.cursor(), 2);
    }

    #[test]
    fn backspace_removes_before_the_cursor_and_delete_after_it() {
        let mut input = TextInput::new("webx");
        assert!(input.backspace());
        assert_eq!(input.value(), "web");
        input.home();
        assert!(!input.backspace(), "nothing before the start");
        assert!(input.delete());
        assert_eq!(input.value(), "eb");
        input.end();
        assert!(!input.delete(), "nothing after the end");
    }

    #[test]
    fn the_cursor_stays_within_the_text() {
        let mut input = TextInput::new("ab");
        input.right();
        assert_eq!(input.cursor(), 2);
        input.home();
        input.left();
        assert_eq!(input.cursor(), 0);
        input.end();
        assert_eq!(input.cursor(), 2);
    }

    #[test]
    fn multibyte_characters_are_edited_whole() {
        let mut input = TextInput::new("añb");
        input.left();
        assert!(input.backspace());
        assert_eq!(input.value(), "ab");
        input.home();
        input.insert('é');
        assert_eq!(input.value(), "éab");
        assert!(input.delete());
        assert_eq!(input.value(), "éb");
    }

    #[test]
    fn handle_key_reports_whether_the_text_changed() {
        let mut input = TextInput::new("ab");
        assert!(input.handle_key(key(KeyCode::Char('c'))));
        assert!(input.handle_key(key(KeyCode::Backspace)));
        assert!(!input.handle_key(key(KeyCode::Left)));
        assert!(!input.handle_key(key(KeyCode::Home)));
        assert!(!input.handle_key(key(KeyCode::Enter)));
        assert!(!input.handle_key(key(KeyCode::Tab)));
        assert_eq!(input.value(), "ab");
    }

    #[test]
    fn control_and_alt_combinations_are_not_typed() {
        let mut input = TextInput::default();
        for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            assert!(!input.handle_key(KeyEvent::new(KeyCode::Char('x'), modifiers)));
        }
        assert!(input.is_empty());
    }

    #[test]
    fn shift_is_part_of_typing() {
        let mut input = TextInput::default();
        assert!(input.handle_key(KeyEvent::new(KeyCode::Char('W'), KeyModifiers::SHIFT)));
        assert_eq!(input.value(), "W");
    }

    #[test]
    fn control_characters_are_refused() {
        let mut input = TextInput::default();
        assert!(!input.insert('\n'));
        assert!(!input.insert('\x1b'));
        assert!(!input.insert('\t'));
        assert!(input.is_empty());
    }

    #[test]
    fn clear_empties_the_text() {
        let mut input = TextInput::new("web");
        input.clear();
        assert!(input.is_empty());
        assert_eq!(input.cursor(), 0);
    }
}
