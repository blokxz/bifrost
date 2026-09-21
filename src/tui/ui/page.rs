//! Text pages: the help, the warnings, the explanation shown when the hosts
//! could not be loaded, why a connection failed, and what ssh printed. They
//! share one layout: a fixed header, a scrolling body
//! and a position indicator when the body does not fit.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::modal::{place_cursor, render_popup};
use super::{
    Cleaner, footer_lines, input_window, labeled_lines, page_block, render_chrome, split_chrome,
    status_lines,
};
use crate::ssh::connect::RETAINED;
use crate::ssh::diagnose::{FailureKind, excerpt, raw_lines};
use crate::tui::app::{App, HELP, KeyChangeView, Metrics};
use crate::tui::input::TextInput;
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

/// How many lines of ssh's own output are quoted on the error screen of a
/// failure that is not recognized.
const QUOTED_LINES: usize = 8;

/// `text` as a bullet: `- ` in front of the first line, aligned under it after.
fn bullet_lines(text: &str, width: usize) -> Vec<Line<'static>> {
    wrap(text, width.saturating_sub(2).max(1))
        .into_iter()
        .enumerate()
        .map(|(index, piece)| Line::raw(format!("{}{piece}", if index == 0 { "- " } else { "  " })))
        .collect()
}

/// Why the last connection failed, in plain English, with what to try next.
pub(super) fn render_connect_error(
    app: &App,
    theme: &Theme,
    frame: &mut Frame,
    area: Rect,
) -> Metrics {
    let width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();

    let (kind, name, stderr) = match app.report() {
        Some(report) => (
            report.failure.unwrap_or(FailureKind::Unrecognized),
            report.name.as_str(),
            report.stderr.as_slice(),
        ),
        None => (FailureKind::Unrecognized, "", [].as_slice()),
    };

    // Everything here is fixed text plus the saved host's name; only the quoted
    // lines of an unrecognized failure come from ssh, and they are cleaned.
    let mut body = labeled_lines(
        "Error:",
        theme.error,
        &kind.explanation(name),
        width,
        &mut cleaner,
    );
    body.push(Line::raw(""));
    body.push(Line::styled("What you can try:", theme.title));
    for step in kind.next_steps() {
        body.extend(bullet_lines(step, width));
    }
    if kind == FailureKind::Unrecognized {
        let quoted = excerpt(stderr, QUOTED_LINES);
        if !quoted.is_empty() {
            body.push(Line::raw(""));
            body.push(Line::styled("ssh said:", theme.title));
            for line in quoted {
                for piece in wrap(&cleaner.clean(&line), width.saturating_sub(2).max(1)) {
                    body.push(Line::raw(format!("  {piece}")));
                }
            }
        }
    }
    let page = Page {
        title: kind.title().to_string(),
        header: Vec::new(),
        body,
    };
    draw(page, cleaner, app, theme, frame, area)
}

/// Where a server's own copy of its public host key is kept, for the tip on how
/// to check a fingerprint. Only for key types Bifrost knows; anything else gets
/// a generic tip, since the type comes from ssh's output.
fn server_key_file(key_type: Option<&str>) -> &'static str {
    match key_type {
        Some("ED25519") => "/etc/ssh/ssh_host_ed25519_key.pub",
        Some("ECDSA") => "/etc/ssh/ssh_host_ecdsa_key.pub",
        Some("RSA") => "/etc/ssh/ssh_host_rsa_key.pub",
        Some("DSA") => "/etc/ssh/ssh_host_dsa_key.pub",
        _ => "/etc/ssh/ssh_host_*_key.pub",
    }
}

/// The lines of the blocking host key screen.
fn key_change_lines(
    view: &KeyChangeView,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    // The key that changed can be a jump host's: say whose it is when it is known.
    let owner = view
        .removal
        .as_ref()
        .map_or(view.name.as_str(), |target| target.saved_name.as_str());
    let kind = FailureKind::HostKeyChanged;
    let mut body = labeled_lines(
        "Stop:",
        theme.error,
        &kind.explanation(owner),
        width,
        cleaner,
    );
    body.push(Line::raw(""));
    for step in kind.next_steps() {
        body.extend(labeled_lines("", Style::new(), step, width, cleaner));
    }
    body.push(Line::raw(""));

    // What ssh reported, each part only if it looked like what it should.
    let key = match (&view.fingerprint, &view.key_type) {
        (Some(hash), Some(kind)) => Some(format!("{hash}  ({kind})")),
        (Some(hash), None) => Some(hash.clone()),
        _ => None,
    };
    let saved = view.file.as_ref().map(|file| match view.line {
        Some(line) => format!("{file}, line {line}"),
        None => file.clone(),
    });
    let label_width = 13;
    for (label, value) in [("Received key", key), ("Old key in", saved)] {
        let Some(value) = value else { continue };
        let indent = " ".repeat(label_width);
        let pieces = wrap(
            &cleaner.clean(&value),
            width.saturating_sub(label_width).max(1),
        );
        for (index, piece) in pieces.into_iter().enumerate() {
            body.push(if index == 0 {
                Line::from(vec![
                    Span::styled(format!("{label:<label_width$}"), theme.muted),
                    Span::raw(piece),
                ])
            } else {
                Line::raw(format!("{indent}{piece}"))
            });
        }
    }
    if view.fingerprint.is_none() {
        body.extend(labeled_lines(
            "",
            theme.muted,
            "ssh's output has the fingerprint of the key it received (press d).",
            width,
            cleaner,
        ));
    }
    body.push(Line::raw(""));
    body.extend(labeled_lines(
        "",
        Style::new(),
        "Tip: ask the server's administrator for its fingerprint, or run this on the \
         server:",
        width,
        cleaner,
    ));
    body.push(Line::raw(format!(
        "  ssh-keygen -lf {}",
        server_key_file(view.key_type.as_deref())
    )));
    body.push(Line::raw(""));

    let paragraph = if view.removal.is_some() {
        "Enter aborts, and is the safe choice. To connect anyway, the old key has to go: \
         press r, then type the host name. Bifrost does not edit known_hosts itself: it \
         runs ssh-keygen -R, which keeps the previous file as known_hosts.old. Then \
         connect again, and ssh will show the new key for you to accept."
    } else {
        "Bifrost will not remove a key here: it cannot tell which entry of your \
         known_hosts is affected, or the entry is in a file Bifrost does not edit. Enter \
         aborts. Press d to read what ssh said."
    };
    body.extend(labeled_lines("", Style::new(), paragraph, width, cleaner));
    body
}

/// The blocking screen for a server whose key is not the one saved.
pub(super) fn render_host_key_changed(
    app: &App,
    theme: &Theme,
    frame: &mut Frame,
    area: Rect,
) -> Metrics {
    let width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();
    let Some(view) = app.key_change() else {
        // Not reachable: the screen is only opened with a view.
        return Metrics::default();
    };
    let page = Page {
        title: "Stop: the server's identity changed".to_string(),
        header: Vec::new(),
        body: key_change_lines(view, theme, width, &mut cleaner),
    };
    let metrics = draw(page, cleaner, app, theme, frame, area);
    if let (Some(confirm), Some(target)) = (app.key_confirm(), view.removal.as_ref()) {
        render_removal_prompt(
            frame,
            area,
            theme,
            &target.saved_name,
            confirm.mismatch,
            &confirm.input,
        );
    }
    metrics
}

const REMOVAL_MISMATCH: &str =
    "That is not the host's name. Type it exactly, or press Esc to cancel.";

/// The box that asks for the host's name before an old key is removed.
fn render_removal_prompt(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    saved_name: &str,
    mismatch: bool,
    input: &TextInput,
) {
    let mut cleaner = Cleaner::default();
    // A popup is at most 60 wide, less its border and padding.
    let width = usize::from(area.width.saturating_sub(2))
        .min(60)
        .saturating_sub(4)
        .max(1);
    let mut lines = labeled_lines(
        "",
        Style::new(),
        &format!("Remove the old key of '{saved_name}'?"),
        width,
        &mut cleaner,
    );
    lines.extend(labeled_lines(
        "",
        Style::new(),
        "It is removed from your known_hosts by ssh-keygen. Your ssh will then treat the \
         server as new.",
        width,
        &mut cleaner,
    ));
    lines.push(Line::raw(""));
    lines.push(Line::raw("Type the host name to confirm:"));
    let typed = cleaner.clean(input.value()).into_owned();
    let (visible, column) = input_window(&typed, input.cursor(), width.saturating_sub(2));
    let cursor_row = lines.len();
    lines.push(Line::from(vec![
        Span::styled("> ", theme.key),
        Span::raw(visible),
    ]));
    if mismatch {
        lines.push(Line::raw(""));
        lines.extend(labeled_lines(
            "Error:",
            theme.error,
            REMOVAL_MISMATCH,
            width,
            &mut cleaner,
        ));
    }
    let inner = render_popup(frame, area, "Remove old key", lines, theme);
    place_cursor(frame, inner, 2 + column, cursor_row);
}

/// Everything ssh printed during the last connection, cleaned.
pub(super) fn render_ssh_output(
    app: &App,
    theme: &Theme,
    frame: &mut Frame,
    area: Rect,
) -> Metrics {
    let width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();

    let (name, stderr) = match app.report() {
        Some(report) => (report.name.as_str(), report.stderr.as_slice()),
        None => ("", [].as_slice()),
    };

    let mut header = labeled_lines(
        "",
        Style::new(),
        &format!("What ssh printed during the last connection to '{name}':"),
        width,
        &mut cleaner,
    );
    if stderr.len() >= RETAINED {
        header.push(Line::styled(
            format!("(Only the last {} KiB are kept.)", RETAINED / 1024),
            theme.muted,
        ));
    }
    header.push(Line::raw(""));

    let mut body = Vec::new();
    for line in raw_lines(stderr) {
        for piece in wrap(&cleaner.clean(&line), width) {
            body.push(Line::raw(piece));
        }
    }
    if body.is_empty() {
        body.push(Line::styled("ssh printed nothing.", theme.muted));
    }

    let page = Page {
        title: "ssh output".to_string(),
        header,
        body,
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
    use crate::tui::effects::testing::take_connect_request;
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
        let text = text_of(&mut app, 100, 120);
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

    // ---- a failed connection ---------------------------------------------

    use crate::ssh::connect::{Exit, Outcome};
    use crate::tui::app::HandoverResult;

    fn fail(app: &mut App, stderr: &str) {
        app.connection_ended(
            "web",
            HandoverResult::Ran(Outcome {
                exit: Exit::Code(255),
                stderr: stderr.as_bytes().to_vec(),
                interrupted: false,
            }),
        );
    }

    fn failed_app(stderr: &str) -> App {
        let mut app = app_with(one_host(), Vec::new());
        fail(&mut app, stderr);
        app
    }

    /// Every message ssh is known by, with the title its screen must carry.
    const FAILURES: &[(&str, &str)] = &[
        (
            "deploy@192.0.2.1: Permission denied (publickey).\r\n",
            "The server refused the login",
        ),
        (
            "Host key verification failed.\r\n",
            "The server's identity was not accepted",
        ),
        (
            "ssh: connect to host 192.0.2.1 port 22: Connection refused\r\n",
            "Connection refused",
        ),
        (
            "ssh: connect to host 192.0.2.1 port 22: Connection timed out\r\n",
            "The server did not answer",
        ),
        (
            "ssh: Could not resolve hostname x: Name or service not known\r\n",
            "The host name was not found",
        ),
        (
            "ssh: connect to host 192.0.2.1 port 22: Network is unreachable\r\n",
            "The network is unreachable",
        ),
        (
            "Connection to 192.0.2.1 closed by remote host.\r\n",
            "The server closed the connection",
        ),
        (
            "client_loop: send disconnect: Broken pipe\r\n",
            "The connection was interrupted",
        ),
        ("something new\r\n", "The connection failed"),
    ];

    #[test]
    fn every_known_failure_has_a_screen_that_explains_it_and_says_what_to_try() {
        for (stderr, title) in FAILURES {
            let mut app = failed_app(stderr);
            let text = text_of(&mut app, 100, 40);
            assert!(text.contains(title), "{title}:\n{text}");
            assert!(text.contains("Error: "), "{title}:\n{text}");
            assert!(text.contains("'web'"), "names the host:\n{text}");
            assert!(text.contains("What you can try:"), "{title}:\n{text}");
            assert!(text.contains("- "), "{title}: at least one step\n{text}");
            let footer = text.lines().last().unwrap();
            assert!(footer.contains("o ssh output"), "{footer}");
            assert!(footer.contains("Enter/Esc back"), "{footer}");
        }
    }

    #[test]
    fn a_failure_that_is_not_recognized_quotes_the_end_of_ssh_s_output() {
        let noise: String = (1..=12).map(|n| format!("line {n}\r\n")).collect();
        let mut app = failed_app(&noise);
        let text = text_of(&mut app, 100, 40);
        assert!(text.contains("The connection failed"), "{text}");
        assert!(text.contains("ssh said:"), "{text}");
        assert!(
            text.contains("  line 12"),
            "the last line is quoted:\n{text}"
        );
        assert!(text.contains("  line 5"), "eight lines are quoted:\n{text}");
        assert!(!text.contains("line 4"), "but no more than that:\n{text}");
    }

    #[test]
    fn a_recognized_failure_shows_none_of_ssh_s_own_text() {
        let mut app = failed_app(
            "Welcome, BANNER-MARKER. Permission denied (publickey).\r\n\
             ssh: connect to host 192.0.2.1 port 22: Connection refused\r\n",
        );
        let text = text_of(&mut app, 100, 40);
        assert!(text.contains("Connection refused"), "{text}");
        assert!(
            !text.contains("BANNER-MARKER") && !text.contains("192.0.2.1"),
            "the explanation is fixed text:\n{text}"
        );
    }

    #[test]
    fn hostile_output_never_reaches_the_screen_on_either_page() {
        let hostile = "ok\r\n\x1b[2J\x1b]0;pwned\x07evil\u{202e}gpj.exe\r\nlast\x1b[31m red\r\n";
        let mut app = failed_app(hostile);
        for page in ["error", "output"] {
            if page == "output" {
                app.handle_key(key('o'));
            }
            let terminal = super::super::testing::draw(&mut app, 80, 30);
            let text = screen_text(&terminal);
            assert!(
                text.contains("non-printable characters were hidden"),
                "{page}:\n{text}"
            );
            for cell in terminal.backend().buffer().content() {
                assert!(
                    !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                    "{page}: unsafe character reached the buffer: {:?}",
                    cell.symbol()
                );
            }
        }
        // On the output page the cleaned text is what is shown.
        let text = text_of(&mut app, 80, 30);
        assert!(text.contains("?[2J?]0;pwned?evil?gpj.exe"), "{text}");
    }

    #[test]
    fn a_failure_with_no_output_says_there_is_nothing_to_read() {
        let mut app = failed_app("");
        let text = text_of(&mut app, 100, 40);
        assert!(text.contains("The connection failed"), "{text}");
        assert!(!text.contains("ssh said:"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(!footer.contains("ssh output"), "{footer}");
    }

    #[test]
    fn the_longest_explanation_still_fits_the_smallest_terminal() {
        // 60x15 is the smallest terminal Bifrost draws for. The most common
        // failure, with its three steps, must not need scrolling there.
        let mut app = failed_app("Permission denied (publickey).\r\n");
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        assert_eq!(metrics.max_scroll, 0);
        assert!(text_of(&mut app, 60, 15).contains("retype it"));
    }

    #[test]
    fn a_long_error_screen_scrolls_to_its_last_line_on_the_smallest_terminal() {
        let noise: String = (1..=12).map(|n| format!("line {n}\r\n")).collect();
        let mut app = failed_app(&noise);
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        assert!(metrics.max_scroll > 0);
        for _ in 0..metrics.max_scroll {
            app.handle_key(key('j'));
        }
        let text = text_of(&mut app, 60, 15);
        assert!(
            text.contains("  line 12"),
            "the last line is reachable:\n{text}"
        );
    }

    // ---- what ssh printed ------------------------------------------------

    #[test]
    fn the_output_page_shows_everything_including_blank_lines() {
        let mut app = failed_app("first\r\n\r\nthird\r\n");
        app.handle_key(key('o'));
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("ssh output"), "{text}");
        assert!(
            text.contains("What ssh printed during the last connection to 'web':"),
            "{text}"
        );
        let body: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.contains("first"))
            .take(3)
            .collect();
        assert!(body[0].contains("first"), "{text}");
        assert!(
            body[1].trim_matches(|c| c == '│' || c == ' ').is_empty(),
            "blank line kept:\n{text}"
        );
        assert!(body[2].contains("third"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("o/Esc/Enter back"), "{footer}");
    }

    #[test]
    fn the_output_page_wraps_long_lines_and_scrolls_to_the_end() {
        let long = "word ".repeat(60) + "THE-END";
        let many: String = (0..80).map(|n| format!("row {n}\r\n")).collect();
        let mut app = failed_app(&format!("{long}\r\n{many}LAST-ROW\r\n"));
        app.handle_key(key('o'));
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        assert!(metrics.max_scroll > 0);
        for _ in 0..metrics.max_scroll {
            app.handle_key(key('j'));
        }
        let text = text_of(&mut app, 60, 15);
        assert!(text.contains("LAST-ROW"), "{text}");
        assert!(!text.contains("lines 1-"), "the indicator moved:\n{text}");
    }

    #[test]
    fn a_word_wider_than_the_terminal_does_not_overflow_it() {
        let mut app = failed_app(&format!("{}\r\n", "x".repeat(300)));
        app.handle_key(key('o'));
        let text = text_of(&mut app, 60, 15);
        for line in text.lines() {
            assert!(crate::tui::wrap::display_width(line) <= 60, "{line}");
        }
    }

    #[test]
    fn the_output_page_says_when_only_the_end_was_kept() {
        let full = "a".repeat(crate::ssh::connect::RETAINED);
        let mut app = failed_app(&full);
        app.handle_key(key('o'));
        assert!(text_of(&mut app, 80, 24).contains("Only the last 64 KiB are kept."));

        let mut short = failed_app("a\r\n");
        short.handle_key(key('o'));
        assert!(!text_of(&mut short, 80, 24).contains("Only the last"));
    }

    #[test]
    fn output_of_a_session_that_was_not_a_failure_can_be_read_from_the_list() {
        let mut app = app_with(one_host(), Vec::new());
        app.connection_ended(
            "web",
            HandoverResult::Ran(Outcome {
                exit: Exit::Code(0),
                stderr: b"Warning: Permanently added 'x'.\r\n".to_vec(),
                interrupted: false,
            }),
        );
        app.handle_key(key('o'));
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("Warning: Permanently added 'x'."), "{text}");
    }

    #[test]
    fn the_new_pages_use_no_color_under_no_color() {
        let mut app = failed_app("something new\r\n");
        let theme = Theme::plain();
        assert_eq!(
            super::super::testing::colored_cells_of(&draw_with(&mut app, &theme, 80, 24).0),
            0
        );
        app.handle_key(key('o'));
        assert_eq!(
            super::super::testing::colored_cells_of(&draw_with(&mut app, &theme, 80, 24).0),
            0
        );
    }

    // ---- a changed host key ------------------------------------------------

    const KNOWN_HOSTS: &str = "/home/dev/.ssh/known_hosts";
    const FINGERPRINT: &str = "SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA";

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

    /// An app whose connection to `web` (192.0.2.1) failed with a changed key.
    fn key_changed_app(host: &str, file: &str) -> App {
        let mut app = app_with(one_host(), Vec::new());
        app.set_known_hosts_file(Some(std::path::PathBuf::from(KNOWN_HOSTS)));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let request = take_connect_request(&mut app).unwrap();
        fail(&mut app, &changed_key_output(host, file));
        assert_eq!(request.name, "web");
        app
    }

    fn flat(text: &str) -> String {
        text.split_whitespace()
            .filter(|word| *word != "│")
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn the_blocking_screen_says_stop_why_and_what_ssh_reported() {
        let mut app = key_changed_app("192.0.2.1", KNOWN_HOSTS);
        let text = text_of(&mut app, 100, 40);
        let words = flat(&text);
        assert!(
            text.contains("Stop: the server's identity changed"),
            "{text}"
        );
        assert!(
            words.contains("Stop: The key that 'web' presented is not the one saved"),
            "{text}"
        );
        assert!(
            words.contains("someone is intercepting the connection"),
            "{text}"
        );
        assert!(
            words.contains("Do not continue unless you know why"),
            "{text}"
        );
        assert!(
            words.contains(&format!("Received key {FINGERPRINT} (ED25519)")),
            "{text}"
        );
        assert!(
            words.contains(&format!("Old key in {KNOWN_HOSTS}, line 12")),
            "{text}"
        );
        assert!(
            words.contains("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"),
            "{text}"
        );
        assert!(
            words.contains("Enter aborts, and is the safe choice"),
            "{text}"
        );
        assert!(words.contains("it runs ssh-keygen -R"), "{text}");
        assert!(words.contains("known_hosts.old"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("Enter/Esc abort (safe)"), "{footer}");
        assert!(footer.contains("r remove old key..."), "{footer}");
        assert!(footer.contains("d ssh output"), "{footer}");
    }

    #[test]
    fn when_no_removal_is_offered_the_screen_says_so_and_does_not_advertise_it() {
        let mut app = key_changed_app("other.example.com", KNOWN_HOSTS);
        let text = text_of(&mut app, 100, 40);
        let words = flat(&text);
        assert!(
            words.contains("Bifrost will not remove a key here"),
            "{text}"
        );
        assert!(!words.contains("press r"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(!footer.contains("remove"), "{footer}");
        assert!(footer.contains("Enter/Esc abort (safe)"), "{footer}");
        // What ssh named is not shown: it is not to be trusted, and it is not
        // needed.
        assert!(!text.contains("other.example.com"), "{text}");
    }

    #[test]
    fn a_jump_host_s_key_names_the_jump_host() {
        let mut client = host("client", "10.0.0.9");
        client.proxy_jump = Some("bastion".to_string());
        let mut app = app_with(vec![host("bastion", "192.0.2.7"), client], Vec::new());
        app.set_known_hosts_file(Some(std::path::PathBuf::from(KNOWN_HOSTS)));
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        take_connect_request(&mut app).unwrap();
        fail(&mut app, &changed_key_output("192.0.2.7", KNOWN_HOSTS));
        let words = flat(&text_of(&mut app, 100, 40));
        assert!(
            words.contains("The key that 'bastion' presented"),
            "{words}"
        );
    }

    #[test]
    fn details_that_do_not_look_right_are_left_out() {
        let mut app = app_with(one_host(), Vec::new());
        app.set_known_hosts_file(Some(std::path::PathBuf::from(KNOWN_HOSTS)));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        take_connect_request(&mut app).unwrap();
        fail(
            &mut app,
            "REMOTE HOST IDENTIFICATION HAS CHANGED!\r\n\
             The fingerprint for the ED25519 key sent by the remote host is\r\n\
             SHA256:not-a-fingerprint.\r\n\
             Host key verification failed.\r\n",
        );
        let text = text_of(&mut app, 100, 40);
        assert!(!text.contains("Received key"), "{text}");
        assert!(!text.contains("not-a-fingerprint"), "{text}");
        assert!(text.contains("press d"), "{text}");
        // The key type was fine, so the tip can name the file.
        assert!(text.contains("ssh_host_ed25519_key.pub"), "{text}");
    }

    #[test]
    fn with_no_key_type_the_tip_is_generic() {
        let mut app = app_with(one_host(), Vec::new());
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        take_connect_request(&mut app).unwrap();
        fail(
            &mut app,
            "REMOTE HOST IDENTIFICATION HAS CHANGED!\r\nHost key verification failed.\r\n",
        );
        let text = text_of(&mut app, 100, 40);
        assert!(
            text.contains("ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub"),
            "{text}"
        );
    }

    #[test]
    fn the_tip_names_the_server_file_for_the_key_type_only_when_the_type_is_known() {
        assert_eq!(
            server_key_file(Some("ED25519")),
            "/etc/ssh/ssh_host_ed25519_key.pub"
        );
        assert_eq!(
            server_key_file(Some("ECDSA")),
            "/etc/ssh/ssh_host_ecdsa_key.pub"
        );
        assert_eq!(
            server_key_file(Some("RSA")),
            "/etc/ssh/ssh_host_rsa_key.pub"
        );
        for odd in [Some("ED25519-SK"), Some("X; rm -rf /"), Some(""), None] {
            assert_eq!(
                server_key_file(odd),
                "/etc/ssh/ssh_host_*_key.pub",
                "{odd:?}"
            );
        }
    }

    #[test]
    fn the_confirmation_box_shows_the_name_the_typed_text_and_a_cursor() {
        let mut app = key_changed_app("192.0.2.1", KNOWN_HOSTS);
        app.handle_key(key('r'));
        for c in "we".chars() {
            app.handle_key(key(c));
        }
        let terminal = super::super::testing::draw(&mut app, 100, 40);
        let text = screen_text(&terminal);
        assert!(text.contains("Remove the old key of 'web'?"), "{text}");
        assert!(text.contains("Type the host name to confirm:"), "{text}");
        assert!(text.contains("> we"), "{text}");
        assert!(!text.contains("Error:"), "no complaint yet:\n{text}");
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("Enter remove") && footer.contains("Esc cancel"),
            "{footer}"
        );
        // The text cursor is in the box, after what was typed.
        let cursor = terminal.backend().cursor_position();
        let row = text.lines().nth(usize::from(cursor.y)).unwrap();
        assert!(
            row.contains("> we"),
            "the cursor is on the input row: {row}"
        );
    }

    #[test]
    fn a_wrong_name_is_refused_in_words() {
        let mut app = key_changed_app("192.0.2.1", KNOWN_HOSTS);
        app.handle_key(key('r'));
        app.handle_key(key('x'));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let text = text_of(&mut app, 100, 40);
        assert!(
            text.contains("Error: That is not the host's name."),
            "{text}"
        );
    }

    #[test]
    fn the_blocking_screen_fits_and_scrolls_on_the_smallest_terminal() {
        let mut app = key_changed_app("192.0.2.1", KNOWN_HOSTS);
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        assert!(metrics.max_scroll > 0);
        let first = text_of(&mut app, 60, 15);
        assert!(
            first.contains("Stop:"),
            "the warning is what is seen first:\n{first}"
        );
        for _ in 0..metrics.max_scroll {
            app.handle_key(key('j'));
        }
        let last = text_of(&mut app, 60, 15);
        assert!(last.contains("to accept."), "the end is reachable:\n{last}");
        // The footer wraps at this width; abort is on its first line.
        let footer: Vec<&str> = last.lines().rev().take(3).collect();
        assert!(
            footer.iter().any(|line| line.contains("Enter/Esc abort")),
            "{footer:?}"
        );
    }

    #[test]
    fn the_confirmation_fits_the_smallest_terminal() {
        let mut app = key_changed_app("192.0.2.1", KNOWN_HOSTS);
        app.handle_key(key('r'));
        let terminal = super::super::testing::draw(&mut app, 60, 15);
        let text = screen_text(&terminal);
        assert!(text.contains("Type the host name to confirm:"), "{text}");
        assert!(text.contains("> "), "{text}");
    }

    #[test]
    fn the_blocking_screen_never_shows_text_from_ssh_that_it_did_not_check() {
        let mut app = app_with(one_host(), Vec::new());
        app.set_known_hosts_file(Some(std::path::PathBuf::from(KNOWN_HOSTS)));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        take_connect_request(&mut app).unwrap();
        fail(
            &mut app,
            "REMOTE HOST IDENTIFICATION HAS CHANGED!\r\n\
             Offending ED25519 key in /home/dev/.ssh/known_hosts\x1b]0;pwned\x07:12\r\n\
             \u{202e}Host key for web has changed and you have requested strict checking.\r\n\
             Host key verification failed.\r\n",
        );
        let terminal = super::super::testing::draw(&mut app, 100, 40);
        let text = screen_text(&terminal);
        assert!(text.contains("Stop:"), "{text}");
        assert!(!text.contains("pwned"), "{text}");
        for cell in terminal.backend().buffer().content() {
            assert!(
                !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                "{:?}",
                cell.symbol()
            );
        }
    }

    #[test]
    fn the_blocking_screen_uses_no_color_under_no_color() {
        let mut app = key_changed_app("192.0.2.1", KNOWN_HOSTS);
        let theme = Theme::plain();
        let colored = |app: &mut App| {
            super::super::testing::colored_cells_of(&draw_with(app, &theme, 100, 40).0)
        };
        assert_eq!(colored(&mut app), 0);
        app.handle_key(key('r'));
        assert_eq!(colored(&mut app), 0);
        // And the meaning does not depend on it: the label is text.
        assert!(text_of(&mut app, 100, 40).contains("Stop:"));
    }
}
