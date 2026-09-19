//! Text pages: the help, the warnings, and the explanation shown when the hosts
//! could not be loaded. They share one layout: a fixed header, a scrolling body
//! and a position indicator when the body does not fit.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{
    Cleaner, footer_lines, labeled_lines, page_block, render_chrome, split_chrome, status_lines,
};
use crate::tui::app::{App, HELP, Metrics};
use crate::tui::startup::{Notice, Severity};
use crate::tui::theme::Theme;
use crate::tui::wrap::wrap;

/// Width of the key column on the help page.
const HELP_KEY_COLUMN: usize = 14;

/// The content of a page, ready to draw.
struct Page {
    title: String,
    /// Fixed lines above the scrolling text.
    header: Vec<Line<'static>>,
    /// The scrolling text, already wrapped to the page width.
    body: Vec<Line<'static>>,
}

fn draw(
    page: Page,
    mut cleaner: Cleaner,
    app: &App,
    theme: &Theme,
    frame: &mut Frame,
    area: Rect,
) -> Metrics {
    let status = status_lines(app.status(), theme, usize::from(area.width), &mut cleaner);
    let footer = footer_lines(
        &app.footer_hints(),
        cleaner.hidden,
        theme,
        usize::from(area.width),
    );
    let chrome = split_chrome(area, status.len(), footer.len());

    let inner = page_block().inner(chrome.main);
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
    frame.render_widget(block, chrome.main);
    frame.render_widget(Paragraph::new(page.header), header_area);
    frame.render_widget(Paragraph::new(page.body[scroll..end].to_vec()), body_area);
    render_chrome(frame, &chrome, status, footer);

    Metrics {
        max_scroll,
        ..Metrics::default()
    }
}

/// Notices as wrapped lines, each starting with a text label (never color
/// alone), with a blank line between them.
fn notice_lines(
    notices: &[Notice],
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, notice) in notices.iter().enumerate() {
        if index > 0 {
            lines.push(Line::raw(""));
        }
        let (label, style) = match notice.severity {
            Severity::Error => ("Error:", theme.error),
            Severity::Warning => ("Warning:", theme.warning),
        };
        lines.extend(labeled_lines(label, style, &notice.text, width, cleaner));
    }
    lines
}

fn title() -> String {
    format!("Bifrost {}", env!("CARGO_PKG_VERSION"))
}

/// The list screen when the hosts could not be loaded: it explains why.
pub(super) fn render_unavailable(
    app: &App,
    theme: &Theme,
    frame: &mut Frame,
    area: Rect,
) -> Metrics {
    let width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();
    let page = Page {
        title: title(),
        header: vec![
            Line::raw("Saved hosts: unknown (see the error below)"),
            Line::raw(""),
        ],
        body: notice_lines(app.notices(), theme, width, &mut cleaner),
    };
    draw(page, cleaner, app, theme, frame, area)
}

/// The warnings found when the hosts were loaded.
pub(super) fn render_notices(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) -> Metrics {
    let width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();
    let page = Page {
        title: "Warnings".to_string(),
        header: vec![
            Line::raw("These problems were found when your hosts were loaded:"),
            Line::raw(""),
        ],
        body: notice_lines(app.notices(), theme, width, &mut cleaner),
    };
    draw(page, cleaner, app, theme, frame, area)
}

/// Every key, in sections.
pub(super) fn render_help(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) -> Metrics {
    let width = usize::from(page_block().inner(area).width);
    let description_width = width.saturating_sub(HELP_KEY_COLUMN).max(1);

    let mut body = Vec::new();
    for (index, section) in HELP.iter().enumerate() {
        if index > 0 {
            body.push(Line::raw(""));
        }
        body.push(Line::styled(section.title, theme.title));
        for row in section.rows {
            for (line, piece) in wrap(row.description, description_width)
                .into_iter()
                .enumerate()
            {
                let keys = if line == 0 { row.keys } else { "" };
                body.push(Line::from(vec![
                    Span::styled(format!("{keys:<HELP_KEY_COLUMN$}"), theme.key),
                    Span::raw(piece),
                ]));
            }
        }
    }
    let page = Page {
        title: "Help".to_string(),
        header: vec![Line::raw("These keys work in Bifrost:"), Line::raw("")],
        body,
    };
    draw(page, Cleaner::default(), app, theme, frame, area)
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use crate::tui::startup::Notice;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn one_host() -> Vec<crate::domain::Host> {
        vec![host("web", "192.0.2.1")]
    }

    // ---- help --------------------------------------------------------------

    #[test]
    fn help_lists_every_key_and_shows_its_own_footer() {
        let mut app = app_with(one_host(), Vec::new());
        app.handle_key(key('?'));
        // Tall enough for the whole page, so nothing needs scrolling.
        let text = text_of(&mut app, 100, 80);
        assert!(text.contains("Help"), "{text}");
        // Long descriptions wrap, so compare with the layout squeezed out.
        let flat = text
            .split_whitespace()
            .filter(|word| *word != "│")
            .collect::<Vec<_>>()
            .join(" ");
        for section in HELP {
            assert!(
                text.contains(section.title),
                "{:?} missing:\n{text}",
                section.title
            );
            for row in section.rows {
                assert!(text.contains(row.keys), "{:?} missing:\n{text}", row.keys);
                assert!(
                    flat.contains(row.description),
                    "{:?} missing:\n{text}",
                    row.description
                );
            }
        }
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("?/Esc close help"), "{footer}");
        assert!(footer.contains("q quit"), "{footer}");
    }

    #[test]
    fn help_can_be_scrolled_to_its_last_line_on_the_smallest_terminal() {
        let mut app = app_with(one_host(), Vec::new());
        app.handle_key(key('?'));
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        assert!(metrics.max_scroll > 0, "the help does not fit in 60x15");

        let first = text_of(&mut app, 60, 15);
        assert!(first.contains("Host list"), "{first}");
        assert!(first.contains("lines 1-"), "{first}");
        assert!(!first.contains("Quit from any screen"), "{first}");

        for _ in 0..metrics.max_scroll {
            app.handle_key(key('j'));
        }
        let last = text_of(&mut app, 60, 15);
        assert!(
            last.contains("Ctrl+C"),
            "the last row is reachable:\n{last}"
        );
        assert!(!last.contains("lines 1-"), "the indicator moved: {last}");
    }

    #[test]
    fn help_descriptions_wrap_under_the_description_column() {
        let mut app = app_with(one_host(), Vec::new());
        app.handle_key(key('?'));
        let text = text_of(&mut app, 60, 60);
        let dbp = text.lines().find(|l| l.contains("Filter by name")).unwrap();
        assert!(dbp.starts_with("│ Type"), "{dbp}");
        let next = text
            .lines()
            .skip_while(|l| !l.contains("Filter by name"))
            .nth(1)
            .unwrap();
        assert!(
            next.starts_with("│               "),
            "continuation is indented: {next:?}"
        );
    }

    // ---- warnings ----------------------------------------------------------

    #[test]
    fn the_warnings_page_lists_each_warning_with_a_label() {
        let notices = vec![
            Notice::warning("hosts.toml is readable by other users."),
            Notice::warning("The key /home/x/id is missing."),
        ];
        let mut app = app_with(one_host(), notices);
        app.handle_key(key('w'));
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("Warnings"), "{text}");
        assert!(
            text.contains("Warning: hosts.toml is readable by other users."),
            "{text}"
        );
        assert!(
            text.contains("Warning: The key /home/x/id is missing."),
            "{text}"
        );
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("w/Esc close"), "{footer}");
    }

    #[test]
    fn a_long_warning_wraps_and_indents_instead_of_being_cut_off() {
        let long = "word ".repeat(40) + "END";
        let mut app = app_with(one_host(), vec![Notice::warning(long)]);
        app.handle_key(key('w'));
        let text = text_of(&mut app, 60, 30);
        assert!(
            text.contains("END"),
            "the end of the message is visible:\n{text}"
        );
        for line in text.lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
        let continuation = text.lines().filter(|l| l.contains("word")).nth(1).unwrap();
        // Border and padding, then the width of "Warning: " (9 cells).
        assert!(
            continuation.starts_with("│          word"),
            "indented: {continuation:?}"
        );
    }

    // ---- hosts that could not be loaded ------------------------------------

    fn load_error() -> Notice {
        Notice::error(
            "Bifrost could not read your saved hosts.\n\
             /tmp/x/hosts.toml contains an invalid host (line 3): Host 'bad name': \
             Name may only contain letters, digits, '.', '_' and '-'.\n\
             Fix the reported line in the file, or restore the previous version from \
             /tmp/x/hosts.toml.bak. Bifrost has not changed the file.",
        )
    }

    #[test]
    fn a_load_error_is_explained_in_plain_english() {
        let mut app = unavailable(vec![load_error()]);
        let text = text_of(&mut app, 80, 24);

        assert!(text.contains("Saved hosts: unknown"), "{text}");
        assert!(
            text.contains("Error: Bifrost could not read your saved hosts."),
            "{text}"
        );
        assert!(text.contains("invalid host (line 3)"), "{text}");
        assert!(text.contains("restore the previous version"), "{text}");
        assert!(text.contains("hosts.toml.bak"), "{text}");
        assert!(text.contains("has not changed"), "{text}");
        assert!(!text.contains("Name  "), "no list, no columns: {text}");
    }

    #[test]
    fn editing_keys_on_a_load_error_explain_themselves_in_the_status_line() {
        let mut app = unavailable(vec![load_error()]);
        app.handle_key(key('f'));
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("until the problem above is fixed"), "{text}");
    }

    #[test]
    fn a_long_load_error_scrolls_to_its_end() {
        let long = Notice::error("word ".repeat(300) + "THE END");
        let mut app = unavailable(vec![long]);
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        assert!(metrics.max_scroll > 0);
        assert!(!text_of(&mut app, 60, 15).contains("THE END"));
        for _ in 0..metrics.max_scroll {
            app.handle_key(key('j'));
        }
        assert!(text_of(&mut app, 60, 15).contains("THE END"));
    }
}
