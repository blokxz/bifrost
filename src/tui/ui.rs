//! Rendering: turns an [`App`] into what is drawn on screen.
//!
//! Rendering only reads the state. All text is wrapped here, in advance, so the
//! exact number of lines is known and the scroll limit can be reported back.
//! Every piece of external text goes through [`crate::sanitize`] on the way in;
//! when something was hidden, the footer says so.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Padding, Paragraph, Wrap};

use super::app::{App, HELP_ROWS, KeyHint, Screen};
use super::startup::{Notice, Severity};
use super::theme::Theme;
use super::wrap::wrap;
use crate::sanitize::{has_unsafe_chars, sanitize};

/// The smallest terminal the screens are laid out for.
///
/// Sized so that the host list, header and footer planned for later blocks fit.
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 15;

/// Width of the key column on the help screen.
const HELP_KEY_COLUMN: usize = 14;

/// Shown in the footer when [`crate::sanitize`] replaced something.
const HIDDEN_NOTE: &str = "Note: non-printable characters were hidden (shown as ?).";

/// Draws the current screen and returns how far it can scroll.
pub fn render(app: &App, theme: &Theme, frame: &mut Frame) -> usize {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(theme, frame, area);
        return 0;
    }
    let width = usize::from(page_block().inner(area).width);
    let page = match app.screen() {
        Screen::Home => home_page(app, theme, width),
        Screen::Help => help_page(theme, width),
    };
    draw_page(&page, app, theme, frame, area)
}

/// The content of a screen, ready to draw.
struct Page {
    title: String,
    /// Fixed lines above the scrolling text.
    header: Vec<Line<'static>>,
    /// The scrolling text, already wrapped to the page width.
    body: Vec<Line<'static>>,
    /// Whether any external text was altered by sanitization.
    hidden: bool,
}

fn page_block() -> Block<'static> {
    Block::bordered().padding(Padding::horizontal(1))
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

fn draw_page(page: &Page, app: &App, theme: &Theme, frame: &mut Frame, area: Rect) -> usize {
    let footer_height = if page.hidden { 2 } else { 1 };
    let [main, footer] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(footer_height)]).areas(area);

    let inner = page_block().inner(main);
    let [header_area, body_area] = Layout::vertical([
        Constraint::Length(u16::try_from(page.header.len()).unwrap_or(u16::MAX)),
        Constraint::Min(0),
    ])
    .areas(inner);

    let visible = usize::from(body_area.height);
    let max_scroll = page.body.len().saturating_sub(visible);
    let scroll = app.scroll().min(max_scroll);
    let end = (scroll + visible).min(page.body.len());

    let mut block = page_block().title(Span::styled(format!(" {} ", page.title), theme.title));
    if max_scroll > 0 {
        let position = format!(" lines {}-{} of {} ", scroll + 1, end, page.body.len());
        block = block.title_bottom(Line::from(Span::styled(position, theme.muted)).right_aligned());
    }
    frame.render_widget(block, main);
    frame.render_widget(Paragraph::new(page.header.clone()), header_area);
    frame.render_widget(Paragraph::new(page.body[scroll..end].to_vec()), body_area);
    frame.render_widget(
        Paragraph::new(footer_lines(app.footer_hints(), page.hidden, theme)),
        footer,
    );

    max_scroll
}

fn footer_lines(hints: &[KeyHint], hidden: bool, theme: &Theme) -> Vec<Line<'static>> {
    let mut spans = Vec::new();
    for (index, hint) in hints.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(hint.keys, theme.key));
        spans.push(Span::raw(format!(" {}", hint.label)));
    }
    let mut lines = Vec::new();
    if hidden {
        lines.push(Line::raw(HIDDEN_NOTE));
    }
    lines.push(Line::from(spans));
    lines
}

/// Tracks whether sanitization changed anything while a page was built.
#[derive(Default)]
struct Cleaner {
    hidden: bool,
}

impl Cleaner {
    fn clean(&mut self, text: &str) -> String {
        if has_unsafe_chars(text) {
            self.hidden = true;
        }
        sanitize(text).into_owned()
    }
}

fn home_page(app: &App, theme: &Theme, width: usize) -> Page {
    let startup = app.startup();
    let count = match startup.host_count {
        Some(count) => format!("Saved hosts: {count}"),
        None => "Saved hosts: unknown (see the error below)".to_string(),
    };

    let mut cleaner = Cleaner::default();
    let mut body = Vec::new();
    for (index, notice) in startup.notices.iter().enumerate() {
        if index > 0 {
            body.push(Line::raw(""));
        }
        body.extend(notice_lines(notice, theme, width, &mut cleaner));
    }
    if startup.notices.is_empty() {
        body.push(Line::raw("Your saved hosts loaded without problems."));
    }

    Page {
        title: format!("Bifrost {}", env!("CARGO_PKG_VERSION")),
        header: vec![Line::raw(count), Line::raw("")],
        body,
        hidden: cleaner.hidden,
    }
}

/// A notice as wrapped lines: a text label (never color alone) followed by the
/// message, with continuation lines indented under it.
fn notice_lines(
    notice: &Notice,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let (label, style) = match notice.severity {
        Severity::Error => ("Error:", theme.error),
        Severity::Warning => ("Warning:", theme.warning),
    };
    let indent = " ".repeat(label.len() + 1);
    let text_width = width.saturating_sub(indent.len()).max(1);

    let mut logical: Vec<&str> = notice.text.lines().collect();
    if logical.is_empty() {
        logical.push("");
    }

    let mut lines = Vec::new();
    for line in logical {
        for piece in wrap(&cleaner.clean(line), text_width) {
            if lines.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled(label, style),
                    Span::raw(format!(" {piece}")),
                ]));
            } else {
                lines.push(Line::raw(format!("{indent}{piece}")));
            }
        }
    }
    lines
}

fn help_page(theme: &Theme, width: usize) -> Page {
    let description_width = width.saturating_sub(HELP_KEY_COLUMN).max(1);
    let mut body = Vec::new();
    for row in HELP_ROWS {
        for (index, piece) in wrap(row.description, description_width)
            .into_iter()
            .enumerate()
        {
            let keys = if index == 0 { row.keys } else { "" };
            body.push(Line::from(vec![
                Span::styled(format!("{keys:<HELP_KEY_COLUMN$}"), theme.key),
                Span::raw(piece),
            ]));
        }
    }
    Page {
        title: "Help".to_string(),
        header: vec![Line::raw("These keys work in Bifrost:"), Line::raw("")],
        body,
        hidden: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{HOSTS_FILE, Store};
    use crate::sysenv::testing::fake_env;
    use crate::tui::startup::Startup;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::style::Color;
    use std::ffi::OsString;

    fn healthy(count: usize) -> App {
        App::new(Startup {
            host_count: Some(count),
            notices: Vec::new(),
        })
    }

    fn with_notices(notices: Vec<Notice>) -> App {
        App::new(Startup {
            host_count: Some(0),
            notices,
        })
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    /// Draws `app` on a fresh test terminal; returns it with the scroll limit.
    fn draw(app: &App, theme: &Theme, width: u16, height: u16) -> (Terminal<TestBackend>, usize) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut max_scroll = 0;
        terminal
            .draw(|frame| max_scroll = render(app, theme, frame))
            .unwrap();
        (terminal, max_scroll)
    }

    fn screen_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let width = usize::from(buffer.area.width);
        buffer
            .content()
            .chunks(width)
            .map(|row| {
                let line: String = row.iter().map(|cell| cell.symbol()).collect();
                line.trim_end().to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn text_of(app: &App, width: u16, height: u16) -> String {
        screen_text(&draw(app, &Theme::ansi16(), width, height).0)
    }

    #[test]
    fn home_shows_the_title_the_host_count_and_the_footer() {
        let text = text_of(&healthy(3), 80, 24);
        assert!(text.contains("Bifrost"), "{text}");
        assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
        assert!(text.contains("Saved hosts: 3"), "{text}");
        assert!(text.contains("loaded without problems"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("Up/Down j/k scroll"), "{footer}");
        assert!(footer.contains("? help"), "{footer}");
        assert!(footer.contains("q/Esc quit"), "{footer}");
    }

    #[test]
    fn home_with_a_load_error_explains_it_in_plain_english() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(HOSTS_FILE),
            "version = 1\n\n[[hosts]]\nname = \"bad name\"\nhostname = \"192.0.2.1\"\n",
        )
        .unwrap();
        let store = Store::at(dir.path()).with_home(None);
        let app = App::new(Startup::from_load(store.load()));

        let text = text_of(&app, 80, 24);

        assert!(text.contains("Saved hosts: unknown"), "{text}");
        assert!(
            text.contains("Error: Bifrost could not read your saved hosts."),
            "{text}"
        );
        assert!(text.contains("invalid host (line 3)"), "{text}");
        assert!(text.contains("restore the previous version"), "{text}");
        assert!(text.contains("hosts.toml.bak"), "{text}");
        assert!(text.contains("has not changed"), "{text}");
    }

    #[test]
    fn home_with_warnings_labels_each_one() {
        let app = with_notices(vec![
            Notice::warning("hosts.toml is readable by other users."),
            Notice::warning("The key /home/x/id is missing."),
        ]);
        let text = text_of(&app, 80, 24);
        assert!(
            text.contains("Warning: hosts.toml is readable by other users."),
            "{text}"
        );
        assert!(
            text.contains("Warning: The key /home/x/id is missing."),
            "{text}"
        );
        assert!(!text.contains("loaded without problems"), "{text}");
    }

    #[test]
    fn long_notice_text_is_wrapped_and_indented_not_cut_off() {
        let long = "word ".repeat(40) + "END";
        let app = with_notices(vec![Notice::error(format!("Summary\n{long}"))]);
        let text = text_of(&app, 60, 24);
        assert!(
            text.contains("END"),
            "the end of the message is visible:\n{text}"
        );
        for line in text.lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
        let continuation = text.lines().find(|l| l.contains("word")).unwrap();
        // Border and padding, then the width of "Error: " (7 cells).
        assert!(
            continuation.starts_with("│        word"),
            "indented: {continuation:?}"
        );
    }

    #[test]
    fn help_lists_every_key_and_shows_its_own_footer() {
        let mut app = healthy(0);
        app.handle_key(key('?'));
        let text = text_of(&app, 80, 24);
        assert!(text.contains("Help"), "{text}");
        for row in HELP_ROWS {
            assert!(text.contains(row.keys), "{:?} missing:\n{text}", row.keys);
            assert!(
                text.contains(row.description),
                "{:?} missing:\n{text}",
                row.description
            );
        }
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("?/Esc close help"), "{footer}");
        assert!(footer.contains("q quit"), "{footer}");
    }

    #[test]
    fn help_fits_the_minimum_terminal() {
        let mut app = healthy(0);
        app.handle_key(key('?'));
        let (terminal, max_scroll) = draw(&app, &Theme::ansi16(), MIN_WIDTH, MIN_HEIGHT);
        assert_eq!(
            max_scroll, 0,
            "the help needs no scrolling at the minimum size"
        );
        let text = screen_text(&terminal);
        for row in HELP_ROWS {
            assert!(text.contains(row.keys), "{:?} missing:\n{text}", row.keys);
        }
    }

    #[test]
    fn a_terminal_that_is_too_narrow_or_too_short_shows_a_message() {
        for (width, height) in [(MIN_WIDTH - 1, MIN_HEIGHT), (MIN_WIDTH, MIN_HEIGHT - 1)] {
            let (terminal, max_scroll) = draw(&healthy(3), &Theme::ansi16(), width, height);
            let text = screen_text(&terminal);
            assert!(
                text.contains("Terminal too small"),
                "{width}x{height}:\n{text}"
            );
            assert!(text.contains(&format!("{width}x{height}")), "{text}");
            assert!(text.contains("60x15"), "{text}");
            assert!(!text.contains("Saved hosts"), "{text}");
            assert_eq!(max_scroll, 0);
        }
    }

    #[test]
    fn the_minimum_size_is_enough_for_the_normal_layout() {
        let text = text_of(&healthy(3), MIN_WIDTH, MIN_HEIGHT);
        assert!(!text.contains("Terminal too small"), "{text}");
        assert!(text.contains("Saved hosts: 3"), "{text}");
        assert!(
            text.lines().last().unwrap().contains("q/Esc quit"),
            "{text}"
        );
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        for (width, height) in [(0, 0), (1, 1), (10, 2), (60, 1), (1, 40)] {
            let mut app = healthy(1);
            draw(&app, &Theme::ansi16(), width, height);
            app.handle_key(key('?'));
            draw(&app, &Theme::ansi16(), width, height);
        }
    }

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
        let app = with_notices(vec![Notice::error("Broken."), Notice::warning("Careful.")]);
        let (terminal, _) = draw(&app, &Theme::ansi16(), 80, 24);
        assert!(colored_cells(&terminal) > 0);
    }

    #[test]
    fn no_color_draws_without_any_color_and_keeps_the_meaning() {
        let env = fake_env(&[("NO_COLOR", OsString::from("1"))]);
        let theme = Theme::from_env(&env);
        let app = with_notices(vec![Notice::error("Broken."), Notice::warning("Careful.")]);

        let (terminal, _) = draw(&app, &theme, 80, 24);
        assert_eq!(colored_cells(&terminal), 0);
        let text = screen_text(&terminal);
        assert!(text.contains("Error: Broken."), "{text}");
        assert!(text.contains("Warning: Careful."), "{text}");

        let mut help = healthy(0);
        help.handle_key(key('?'));
        assert_eq!(colored_cells(&draw(&help, &theme, 80, 24).0), 0);
        assert_eq!(colored_cells(&draw(&healthy(1), &theme, 20, 5).0), 0);
    }

    #[test]
    fn external_text_is_sanitized_and_the_footer_says_so() {
        let app = with_notices(vec![Notice::warning(
            "Host \x1b[31mred\x1b[0m and evil\u{202e}gpj.exe\nsecond\tline",
        )]);
        let (terminal, _) = draw(&app, &Theme::ansi16(), 80, 24);
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
        let app = with_notices(vec![Notice::warning("Nothing odd here.")]);
        assert!(!text_of(&app, 80, 24).contains("non-printable"));
        assert!(!text_of(&healthy(2), 80, 24).contains("non-printable"));
    }

    fn many_warnings(count: usize) -> App {
        with_notices(
            (1..=count)
                .map(|n| Notice::warning(format!("problem number {n}")))
                .collect(),
        )
    }

    #[test]
    fn scrolling_reveals_text_that_does_not_fit() {
        let mut app = many_warnings(20);
        let (terminal, max_scroll) = draw(&app, &Theme::ansi16(), 60, 15);
        let text = screen_text(&terminal);
        assert!(max_scroll > 0);
        assert!(text.contains("problem number 1"), "{text}");
        assert!(!text.contains("problem number 20"), "{text}");
        assert!(text.contains("lines 1-"), "position is shown: {text}");
        assert!(text.contains("of 39"), "{text}");

        app.set_max_scroll(max_scroll);
        for _ in 0..max_scroll {
            app.handle_key(key('j'));
        }
        let text = screen_text(&draw(&app, &Theme::ansi16(), 60, 15).0);
        assert!(text.contains("problem number 20"), "{text}");
        assert!(text.contains("-39 of 39"), "{text}");
    }

    #[test]
    fn nothing_says_scrollable_when_everything_fits() {
        let text = text_of(&many_warnings(2), 80, 24);
        assert!(!text.contains("lines 1-"), "{text}");
    }

    #[test]
    fn an_out_of_range_scroll_still_shows_the_end() {
        let mut app = many_warnings(20);
        app.set_max_scroll(1000);
        for _ in 0..500 {
            app.handle_key(key('j'));
        }
        // A later, smaller terminal limit than the stored position.
        let text = text_of(&app, 60, 15);
        assert!(text.contains("problem number 20"), "{text}");
    }
}
