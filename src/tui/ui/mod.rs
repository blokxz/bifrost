//! Rendering: turns an [`App`] into what is drawn on screen.
//!
//! Rendering only reads the state. Text is wrapped and cut here, in advance, so
//! the exact number of lines is known and the scroll limits can be reported back
//! (see [`Metrics`]). Every piece of external text goes through
//! [`crate::sanitize`] on the way in; when something was hidden, the footer says
//! so.
//!
//! - [`list`]: the host list.
//! - [`form`]: the add/edit form.
//! - [`modal`]: boxes drawn over a screen.
//! - [`page`]: text pages: help, warnings, and the explanation shown when the
//!   hosts could not be loaded.

use std::borrow::Cow;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Padding, Paragraph, Wrap};

use super::app::{App, KeyHint, Metrics, Screen, Status, StatusKind};
use super::theme::Theme;
use super::wrap::{display_width, wrap};
use crate::sanitize::{has_unsafe_chars, sanitize};

mod form;
mod list;
mod modal;
mod page;

/// The smallest terminal the screens are laid out for.
///
/// Sized so that the host list, its header and the footer fit.
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 15;

/// Shown in the footer when [`crate::sanitize`] replaced something.
const HIDDEN_NOTE: &str = "Note: non-printable characters were hidden (shown as ?).";

/// The most lines a status message may take before it is cut.
const MAX_STATUS_LINES: usize = 6;

/// Draws the current screen and reports what it learned about the layout.
pub fn render(app: &App, theme: &Theme, frame: &mut Frame) -> Metrics {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(theme, frame, area);
        return Metrics::default();
    }
    match app.screen() {
        Screen::List if app.hosts().is_some() => list::render(app, theme, frame, area),
        Screen::List => page::render_unavailable(app, theme, frame, area),
        Screen::Help => page::render_help(app, theme, frame, area),
        Screen::Notices => page::render_notices(app, theme, frame, area),
        Screen::Form => form::render(app, theme, frame, area),
    }
}

fn render_too_small(theme: &Theme, frame: &mut Frame, area: Rect) {
    let message = format!(
        "Terminal too small ({}x{}). Bifrost needs at least {MIN_WIDTH}x{MIN_HEIGHT}. \
         Enlarge the window to continue, or press q to quit.",
        area.width, area.height
    );
    frame.render_widget(
        Paragraph::new(message)
            .style(theme.warning)
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// Tracks whether sanitization changed anything while a screen was built.
#[derive(Default)]
struct Cleaner {
    hidden: bool,
}

impl Cleaner {
    fn clean<'a>(&mut self, text: &'a str) -> Cow<'a, str> {
        if has_unsafe_chars(text) {
            self.hidden = true;
        }
        sanitize(text)
    }
}

/// The frame every screen is drawn in: a border with side padding.
fn page_block() -> Block<'static> {
    Block::bordered().padding(Padding::horizontal(1))
}

/// The screen's regions: the framed body, a status message and the footer.
struct Chrome {
    main: Rect,
    status: Rect,
    footer: Rect,
}

fn split_chrome(area: Rect, status_lines: usize, footer_lines: usize) -> Chrome {
    let height = |lines: usize| u16::try_from(lines).unwrap_or(u16::MAX);
    let [main, status, footer] = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(height(status_lines)),
        Constraint::Length(height(footer_lines)),
    ])
    .areas(area);
    Chrome {
        main,
        status,
        footer,
    }
}

fn render_chrome(
    frame: &mut Frame,
    chrome: &Chrome,
    status: Vec<Line<'static>>,
    footer: Vec<Line<'static>>,
) {
    frame.render_widget(Paragraph::new(status), chrome.status);
    frame.render_widget(Paragraph::new(footer), chrome.footer);
}

/// The footer: the keys of the current screen, wrapped onto as many lines as
/// the width needs, preceded by a note when text was hidden.
fn footer_lines(
    hints: &[KeyHint],
    hidden: bool,
    theme: &Theme,
    width: usize,
) -> Vec<Line<'static>> {
    const SEPARATOR: &str = "  ";
    let mut lines = Vec::new();
    if hidden {
        lines.push(Line::raw(HIDDEN_NOTE));
    }
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut used = 0;
    for hint in hints {
        let piece = display_width(hint.keys) + 1 + display_width(hint.label);
        if !spans.is_empty() && used + SEPARATOR.len() + piece > width {
            lines.push(Line::from(std::mem::take(&mut spans)));
            used = 0;
        }
        if !spans.is_empty() {
            spans.push(Span::raw(SEPARATOR));
            used += SEPARATOR.len();
        }
        spans.push(Span::styled(hint.keys, theme.key));
        spans.push(Span::raw(format!(" {}", hint.label)));
        used += piece;
    }
    lines.push(Line::from(spans));
    lines
}

/// `text` wrapped to `width`, with `label` in front of the first line and the
/// other lines indented under it. Line breaks in `text` are kept.
fn labeled_lines(
    label: &'static str,
    style: Style,
    text: &str,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let indent = if label.is_empty() { 0 } else { label.len() + 1 };
    let text_width = width.saturating_sub(indent).max(1);

    let mut logical: Vec<&str> = text.lines().collect();
    if logical.is_empty() {
        logical.push("");
    }

    let mut lines: Vec<Line<'static>> = Vec::new();
    for line in logical {
        for piece in wrap(&cleaner.clean(line), text_width) {
            if !lines.is_empty() {
                lines.push(Line::raw(format!("{:indent$}{piece}", "")));
            } else if label.is_empty() {
                lines.push(Line::raw(piece));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(label, style),
                    Span::raw(format!(" {piece}")),
                ]));
            }
        }
    }
    lines
}

/// A status message as lines: errors and warnings start with a text label, so
/// what they mean never depends on color.
fn status_lines(
    status: Option<&Status>,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let Some(status) = status else {
        return Vec::new();
    };
    let (label, style) = match status.kind {
        StatusKind::Info => ("", Style::new()),
        StatusKind::Warning => ("Warning:", theme.warning),
        StatusKind::Error => ("Error:", theme.error),
    };
    let mut lines = labeled_lines(label, style, &status.text, width, cleaner);
    lines.truncate(MAX_STATUS_LINES);
    lines
}

/// The part of `text` to show in a box `width` cells wide, so that the cursor
/// (`cursor` characters from the start) is always inside it. Returns that part
/// and the cursor's column within it.
fn input_window(text: &str, cursor: usize, width: usize) -> (String, usize) {
    let chars: Vec<char> = text.chars().collect();
    let cell = |c: &char| display_width(c.encode_utf8(&mut [0; 4]));
    let cursor = cursor.min(chars.len());

    // Scroll right until the cursor has a cell of its own.
    let mut start = 0;
    while start < cursor && chars[start..cursor].iter().map(cell).sum::<usize>() >= width {
        start += 1;
    }
    let column = chars[start..cursor].iter().map(cell).sum();

    let mut shown = String::new();
    let mut used = 0;
    for c in &chars[start..] {
        if used + cell(c) > width {
            break;
        }
        shown.push(*c);
        used += cell(c);
    }
    (shown, column)
}

#[cfg(test)]
pub(crate) mod testing {
    //! Helpers shared by the rendering tests.

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::domain::{Host, Hosts};
    use crate::tui::app::{App, Metrics};
    use crate::tui::persist::testing::FakeStore;
    use crate::tui::startup::{Notice, Startup};
    use crate::tui::theme::Theme;

    pub fn host(name: &str, hostname: &str) -> Host {
        Host::new(name, hostname)
    }

    pub fn app_with(hosts: Vec<Host>, notices: Vec<Notice>) -> App {
        let hosts = Hosts::from_vec(hosts).unwrap();
        App::new(Startup::loaded(hosts, FakeStore::default(), notices))
    }

    pub fn unavailable(notices: Vec<Notice>) -> App {
        App::new(Startup {
            library: None,
            notices,
        })
    }

    /// Draws `app` on a fresh test terminal; returns it with what rendering
    /// reported, and feeds that report back to the app as the event loop does.
    pub fn draw_with(
        app: &mut App,
        theme: &Theme,
        width: u16,
        height: u16,
    ) -> (Terminal<TestBackend>, Metrics) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut metrics = Metrics::default();
        terminal
            .draw(|frame| metrics = super::render(app, theme, frame))
            .unwrap();
        app.apply_metrics(metrics);
        (terminal, metrics)
    }

    pub fn draw(app: &mut App, width: u16, height: u16) -> Terminal<TestBackend> {
        draw_with(app, &Theme::ansi16(), width, height).0
    }

    pub fn screen_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let width = usize::from(buffer.area.width);
        buffer
            .content()
            .chunks(width.max(1))
            .map(|row| {
                let line: String = row.iter().map(|cell| cell.symbol()).collect();
                line.trim_end().to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn text_of(app: &mut App, width: u16, height: u16) -> String {
        screen_text(&draw(app, width, height))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::tui::startup::Notice;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::style::Color;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn one_host() -> Vec<crate::domain::Host> {
        vec![host("web", "192.0.2.1")]
    }

    // ---- terminal size ---------------------------------------------------

    #[test]
    fn a_terminal_that_is_too_narrow_or_too_short_shows_a_message() {
        for (width, height) in [(MIN_WIDTH - 1, MIN_HEIGHT), (MIN_WIDTH, MIN_HEIGHT - 1)] {
            let mut app = app_with(one_host(), Vec::new());
            let text = text_of(&mut app, width, height);
            assert!(
                text.contains("Terminal too small"),
                "{width}x{height}:\n{text}"
            );
            assert!(text.contains(&format!("{width}x{height}")), "{text}");
            assert!(text.contains("60x15"), "{text}");
            assert!(!text.contains("web"), "{text}");
        }
    }

    #[test]
    fn the_minimum_size_is_enough_for_the_normal_layout() {
        let mut app = app_with(one_host(), Vec::new());
        let text = text_of(&mut app, MIN_WIDTH, MIN_HEIGHT);
        assert!(!text.contains("Terminal too small"), "{text}");
        assert!(text.contains("web"), "{text}");
        assert!(text.contains("q/Esc quit"), "{text}");
    }

    #[test]
    fn tiny_terminals_do_not_panic_on_any_screen() {
        for (width, height) in [(0, 0), (1, 1), (10, 2), (60, 1), (1, 40)] {
            let mut app = app_with(one_host(), vec![Notice::warning("careful")]);
            draw(&mut app, width, height);
            for opener in ['?', '?', 'w', 'w'] {
                app.handle_key(key(opener));
                draw(&mut app, width, height);
            }
            let mut broken = unavailable(vec![Notice::error("broken")]);
            draw(&mut broken, width, height);
        }
    }

    // ---- footer ----------------------------------------------------------

    #[test]
    fn the_footer_wraps_instead_of_cutting_keys_off() {
        let mut app = app_with(one_host(), vec![Notice::warning("careful")]);
        let text = text_of(&mut app, MIN_WIDTH, MIN_HEIGHT);
        for expected in [
            "Up/Down j/k move",
            "/ search",
            "f favorite",
            "w warnings",
            "? help",
            "q/Esc quit",
        ] {
            assert!(text.contains(expected), "{expected:?} missing:\n{text}");
        }
        for line in text.lines() {
            assert!(line.chars().count() <= usize::from(MIN_WIDTH), "{line:?}");
        }
    }

    #[test]
    fn wide_terminals_keep_the_footer_on_one_line() {
        let hints = [
            KeyHint {
                keys: "a",
                label: "one",
            },
            KeyHint {
                keys: "b",
                label: "two",
            },
        ];
        let lines = footer_lines(&hints, false, &Theme::plain(), 80);
        assert_eq!(lines.len(), 1);
        let narrow = footer_lines(&hints, false, &Theme::plain(), 8);
        assert_eq!(narrow.len(), 2);
    }

    // ---- color -----------------------------------------------------------

    fn colored_cells(terminal: &Terminal<TestBackend>) -> usize {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .filter(|cell| cell.fg != Color::Reset || cell.bg != Color::Reset)
            .count()
    }

    #[test]
    fn default_theme_uses_ansi_colors() {
        let mut app = unavailable(vec![Notice::error("Broken."), Notice::warning("Careful.")]);
        assert!(colored_cells(&draw(&mut app, 80, 24)) > 0);
    }

    #[test]
    fn no_color_draws_without_any_color_on_every_screen_and_keeps_the_meaning() {
        let theme = Theme::plain();
        let mut broken = unavailable(vec![Notice::error("Broken."), Notice::warning("Careful.")]);
        let (terminal, _) = draw_with(&mut broken, &theme, 80, 24);
        assert_eq!(colored_cells(&terminal), 0);
        let text = screen_text(&terminal);
        assert!(text.contains("Error: Broken."), "{text}");
        assert!(text.contains("Warning: Careful."), "{text}");

        let hosts = vec![host("web", "192.0.2.1"), host("db", "192.0.2.2")];
        let mut app = app_with(hosts, vec![Notice::warning("Careful.")]);
        app.handle_key(key('f'));
        for screen in ["", "w", "w", "?", "?"] {
            for c in screen.chars() {
                app.handle_key(key(c));
            }
            assert_eq!(colored_cells(&draw_with(&mut app, &theme, 80, 24).0), 0);
        }
        app.handle_key(key('/'));
        app.handle_key(key('w'));
        assert_eq!(colored_cells(&draw_with(&mut app, &theme, 80, 24).0), 0);
        assert_eq!(colored_cells(&draw_with(&mut app, &theme, 20, 5).0), 0);
    }

    // ---- sanitization ----------------------------------------------------

    #[test]
    fn external_text_is_sanitized_and_the_footer_says_so() {
        let mut app = unavailable(vec![Notice::warning(
            "Host \x1b[31mred\x1b[0m and evil\u{202e}gpj.exe\nsecond\tline",
        )]);
        let terminal = draw(&mut app, 80, 24);
        let text = screen_text(&terminal);

        assert!(
            text.contains("Host ?[31mred?[0m and evil?gpj.exe"),
            "{text}"
        );
        assert!(text.contains("second?line"), "{text}");
        assert!(
            text.contains("non-printable characters were hidden"),
            "{text}"
        );
        for cell in terminal.backend().buffer().content() {
            assert!(
                !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                "unsafe character reached the buffer: {:?}",
                cell.symbol()
            );
        }
    }

    #[test]
    fn clean_text_gets_no_hidden_characters_note() {
        let mut app = unavailable(vec![Notice::warning("Nothing odd here.")]);
        assert!(!text_of(&mut app, 80, 24).contains("non-printable"));
        let mut list = app_with(one_host(), Vec::new());
        assert!(!text_of(&mut list, 80, 24).contains("non-printable"));
    }

    // ---- helpers ---------------------------------------------------------

    #[test]
    fn labeled_lines_indent_under_the_label() {
        let mut cleaner = Cleaner::default();
        let lines = labeled_lines(
            "Error:",
            Style::new(),
            "one two three four five six seven",
            17,
            &mut cleaner,
        );
        let text: Vec<String> = lines
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert_eq!(text[0], "Error: one two");
        assert!(text[1].starts_with("       "), "{text:?}");
        assert!(!cleaner.hidden);
    }

    #[test]
    fn input_window_keeps_the_cursor_inside_the_box() {
        assert_eq!(input_window("web", 3, 10), ("web".to_string(), 3));
        assert_eq!(input_window("web", 0, 10), ("web".to_string(), 0));

        let (shown, column) = input_window("abcdefghij", 10, 6);
        assert_eq!(shown, "fghij");
        assert_eq!(
            column, 5,
            "the cursor sits after the last visible character"
        );

        let (shown, column) = input_window("abcdefghij", 3, 6);
        assert_eq!(shown, "abcdef");
        assert_eq!(column, 3);
    }

    #[test]
    fn input_window_never_shows_more_than_the_width() {
        for cursor in 0..=20 {
            let (shown, column) = input_window(&"x".repeat(20), cursor, 8);
            assert!(display_width(&shown) <= 8);
            assert!(column < 8, "cursor {cursor} -> column {column}");
        }
    }
}
