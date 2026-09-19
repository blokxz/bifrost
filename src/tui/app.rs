//! Application state and key handling.
//!
//! [`App`] holds everything that decides what is on screen and never touches the
//! terminal: key events go in, state changes come out. Rendering (see
//! [`super::ui`]) only reads it, so all of this is unit-testable.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::startup::Startup;

/// The screens of the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    Help,
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

/// Every key Bifrost understands, for the help screen.
pub const HELP_ROWS: &[HelpRow] = &[
    HelpRow {
        keys: "Up/Down j/k",
        description: "Scroll the text up or down when it does not fit",
    },
    HelpRow {
        keys: "?",
        description: "Open this help, or close it",
    },
    HelpRow {
        keys: "Esc",
        description: "Close this help, or quit from the home screen",
    },
    HelpRow {
        keys: "q",
        description: "Quit",
    },
    HelpRow {
        keys: "Ctrl+C",
        description: "Quit from any screen",
    },
];

const HOME_HINTS: &[KeyHint] = &[
    KeyHint {
        keys: "Up/Down j/k",
        label: "scroll",
    },
    KeyHint {
        keys: "?",
        label: "help",
    },
    KeyHint {
        keys: "q/Esc",
        label: "quit",
    },
];

const HELP_HINTS: &[KeyHint] = &[
    KeyHint {
        keys: "Up/Down j/k",
        label: "scroll",
    },
    KeyHint {
        keys: "?/Esc",
        label: "close help",
    },
    KeyHint {
        keys: "q",
        label: "quit",
    },
];

/// The state of the TUI.
#[derive(Debug)]
pub struct App {
    screen: Screen,
    startup: Startup,
    home_scroll: usize,
    help_scroll: usize,
    /// How far the current screen can scroll, as last reported by rendering.
    max_scroll: usize,
    quit: bool,
}

impl App {
    pub fn new(startup: Startup) -> Self {
        App {
            screen: Screen::Home,
            startup,
            home_scroll: 0,
            help_scroll: 0,
            max_scroll: 0,
            quit: false,
        }
    }

    pub fn screen(&self) -> Screen {
        self.screen
    }

    pub fn startup(&self) -> &Startup {
        &self.startup
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// How many lines the current screen is scrolled down.
    pub fn scroll(&self) -> usize {
        match self.screen {
            Screen::Home => self.home_scroll,
            Screen::Help => self.help_scroll,
        }
    }

    /// The keys to list in the footer of the current screen.
    pub fn footer_hints(&self) -> &'static [KeyHint] {
        match self.screen {
            Screen::Home => HOME_HINTS,
            Screen::Help => HELP_HINTS,
        }
    }

    /// Tells the state how far the current screen can scroll.
    ///
    /// Rendering knows how much text fits, so it reports the limit after each
    /// draw; scrolling never goes past it, and a shrinking limit (for example
    /// after a resize) pulls the position back.
    pub fn set_max_scroll(&mut self, max: usize) {
        self.max_scroll = max;
        let scroll = self.scroll_mut();
        *scroll = (*scroll).min(max);
    }

    /// Applies a key press. Callers must pass only key presses, not releases.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        // Other Ctrl or Alt combinations belong to the terminal or the system.
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return;
        }
        match (self.screen, key.code) {
            (_, KeyCode::Char('q')) | (Screen::Home, KeyCode::Esc) => self.quit = true,
            (Screen::Home, KeyCode::Char('?')) => self.open(Screen::Help),
            (Screen::Help, KeyCode::Char('?') | KeyCode::Esc) => self.open(Screen::Home),
            (_, KeyCode::Up | KeyCode::Char('k')) => self.scroll_up(),
            (_, KeyCode::Down | KeyCode::Char('j')) => self.scroll_down(),
            _ => {}
        }
    }

    fn open(&mut self, screen: Screen) {
        self.screen = screen;
        if screen == Screen::Help {
            self.help_scroll = 0;
        }
        // The limit belongs to the screen that was drawn; until the new one is
        // drawn, stay put rather than scroll by a stale amount.
        self.max_scroll = 0;
    }

    fn scroll_mut(&mut self) -> &mut usize {
        match self.screen {
            Screen::Home => &mut self.home_scroll,
            Screen::Help => &mut self.help_scroll,
        }
    }

    fn scroll_up(&mut self) {
        let scroll = self.scroll_mut();
        *scroll = scroll.saturating_sub(1);
    }

    fn scroll_down(&mut self) {
        let max = self.max_scroll;
        let scroll = self.scroll_mut();
        *scroll = (*scroll + 1).min(max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyEventKind;

    fn app() -> App {
        App::new(Startup {
            host_count: Some(0),
            notices: Vec::new(),
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

    #[test]
    fn starts_on_the_home_screen() {
        let app = app();
        assert_eq!(app.screen(), Screen::Home);
        assert!(!app.should_quit());
        assert_eq!(app.scroll(), 0);
    }

    #[test]
    fn q_and_esc_quit_from_home() {
        for key in [ch('q'), press(KeyCode::Esc)] {
            let mut app = app();
            app.handle_key(key);
            assert!(app.should_quit(), "{key:?}");
        }
    }

    #[test]
    fn ctrl_c_quits_from_every_screen() {
        for open_help in [false, true] {
            let mut app = app();
            if open_help {
                app.handle_key(ch('?'));
            }
            app.handle_key(with(KeyCode::Char('c'), KeyModifiers::CONTROL));
            assert!(app.should_quit(), "help open: {open_help}");
        }
    }

    #[test]
    fn a_plain_c_does_nothing() {
        let mut app = app();
        app.handle_key(ch('c'));
        assert!(!app.should_quit());
        assert_eq!(app.screen(), Screen::Home);
    }

    #[test]
    fn question_mark_opens_and_closes_help() {
        let mut app = app();
        app.handle_key(ch('?'));
        assert_eq!(app.screen(), Screen::Help);
        app.handle_key(ch('?'));
        assert_eq!(app.screen(), Screen::Home);
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
    fn esc_closes_help_without_quitting() {
        let mut app = app();
        app.handle_key(ch('?'));
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), Screen::Home);
        assert!(!app.should_quit());
    }

    #[test]
    fn q_quits_from_help() {
        let mut app = app();
        app.handle_key(ch('?'));
        app.handle_key(ch('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn other_ctrl_and_alt_combinations_are_ignored() {
        for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            for code in [KeyCode::Char('q'), KeyCode::Char('?'), KeyCode::Esc] {
                let mut app = app();
                app.handle_key(with(code, modifiers));
                assert!(!app.should_quit(), "{code:?} with {modifiers:?}");
                assert_eq!(app.screen(), Screen::Home, "{code:?} with {modifiers:?}");
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
        assert_eq!(app.screen(), Screen::Home);
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

    #[test]
    fn scrolling_follows_arrows_and_j_k_within_the_limit() {
        let mut app = app();
        app.set_max_scroll(3);
        for key in [ch('j'), press(KeyCode::Down), ch('j')] {
            app.handle_key(key);
        }
        assert_eq!(app.scroll(), 3);
        app.handle_key(ch('j'));
        assert_eq!(app.scroll(), 3, "stops at the limit");
        app.handle_key(ch('k'));
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.scroll(), 1);
        app.handle_key(ch('k'));
        app.handle_key(ch('k'));
        assert_eq!(app.scroll(), 0, "stops at the top");
    }

    #[test]
    fn nothing_scrolls_until_rendering_reports_a_limit() {
        let mut app = app();
        app.handle_key(ch('j'));
        assert_eq!(app.scroll(), 0);
    }

    #[test]
    fn a_smaller_limit_pulls_the_position_back() {
        let mut app = app();
        app.set_max_scroll(10);
        for _ in 0..8 {
            app.handle_key(ch('j'));
        }
        assert_eq!(app.scroll(), 8);
        app.set_max_scroll(5);
        assert_eq!(app.scroll(), 5);
    }

    #[test]
    fn help_opens_at_the_top_and_home_keeps_its_position() {
        let mut app = app();
        app.set_max_scroll(10);
        app.handle_key(ch('j'));
        app.handle_key(ch('j'));
        app.handle_key(ch('?'));
        assert_eq!(app.scroll(), 0);

        app.set_max_scroll(4);
        app.handle_key(ch('j'));
        assert_eq!(app.scroll(), 1);

        app.handle_key(ch('?'));
        assert_eq!(app.screen(), Screen::Home);
        assert_eq!(app.scroll(), 2);

        app.handle_key(ch('?'));
        assert_eq!(app.scroll(), 0, "help starts from the top each time");
    }

    #[test]
    fn footer_shows_the_keys_of_the_current_screen() {
        let mut app = app();
        let home: Vec<_> = app.footer_hints().iter().map(|h| h.label).collect();
        assert_eq!(home, ["scroll", "help", "quit"]);
        app.handle_key(ch('?'));
        let help: Vec<_> = app.footer_hints().iter().map(|h| h.label).collect();
        assert_eq!(help, ["scroll", "close help", "quit"]);
    }

    #[test]
    fn every_footer_key_is_listed_in_the_help() {
        let documented: Vec<&str> = HELP_ROWS
            .iter()
            .flat_map(|row| row.keys.split([' ', '/']))
            .collect();
        for hints in [HOME_HINTS, HELP_HINTS] {
            for hint in hints {
                for key in hint.keys.split([' ', '/']) {
                    assert!(documented.contains(&key), "{key:?} is not in the help");
                }
            }
        }
    }

    #[test]
    fn the_help_documents_every_key_the_state_handles() {
        let keys: String = HELP_ROWS
            .iter()
            .map(|row| row.keys)
            .collect::<Vec<_>>()
            .join(" ");
        for expected in ["Up", "Down", "j", "k", "?", "Esc", "q", "Ctrl+C"] {
            assert!(keys.contains(expected), "{expected:?} missing from help");
        }
    }
}
