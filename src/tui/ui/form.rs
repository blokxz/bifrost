//! The add/edit form screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::modal::{place_cursor, render_popup};
use super::{
    Cleaner, footer_lines, input_window, labeled_lines, page_block, render_chrome, split_chrome,
};
use crate::tui::app::{App, Metrics};
use crate::tui::form::{AGENT_WARNING, Form, FormField, FormMode, KeyPick, KeyPicker, Picker};
use crate::tui::list::window_start;
use crate::tui::theme::Theme;
use crate::tui::wrap::{display_width, pad, truncate, wrap};

/// Marker, space, then the label padded to this many cells.
const LABEL_WIDTH: usize = 14;
/// Where a value starts: marker + space + label + space.
const VALUE_COLUMN: usize = 2 + LABEL_WIDTH + 1;
/// Fixed height of the help under the fields: up to three lines of explanation
/// and one of example.
const HELP_LINES: usize = 4;
const MAX_BANNER_LINES: usize = 3;

/// One row of the form, as the lines it takes.
struct FieldLines {
    field: FormField,
    lines: Vec<Line<'static>>,
}

fn placeholder(field: FormField) -> &'static str {
    match field {
        FormField::Name | FormField::Hostname => "(required)",
        _ => "(optional)",
    }
}

/// The value of a row, as spans, and the cursor column within the value area
/// when it is the row being edited.
fn value_spans(
    form: &Form,
    field: FormField,
    focused: bool,
    width: usize,
    theme: &Theme,
    cleaner: &mut Cleaner,
) -> (Vec<Span<'static>>, Option<usize>) {
    match field {
        FormField::Advanced => {
            let text = if form.advanced_open() {
                "[-] shown"
            } else {
                "[+] hidden"
            };
            (vec![Span::raw(text)], None)
        }
        FormField::ForwardAgent => {
            let text = if form.forward_agent() {
                "[x] on"
            } else {
                "[ ] off"
            };
            (vec![Span::raw(text)], None)
        }
        FormField::ProxyJump => {
            let shown = match form.jump() {
                Some(name) => truncate(&cleaner.clean(name), width).0,
                None => "(none)".to_string(),
            };
            (vec![Span::raw(shown)], None)
        }
        _ => {
            let Some(input) = form.input(field) else {
                return (Vec::new(), None);
            };
            let text = cleaner.clean(input.value()).into_owned();
            if text.is_empty() && !focused {
                return (vec![Span::styled(placeholder(field), theme.muted)], None);
            }
            if focused {
                let (visible, column) = input_window(&text, input.cursor(), width);
                (vec![Span::raw(visible)], Some(column))
            } else {
                (vec![Span::raw(truncate(&text, width).0)], None)
            }
        }
    }
}

fn field_lines(
    form: &Form,
    field: FormField,
    inner_width: usize,
    theme: &Theme,
    cleaner: &mut Cleaner,
) -> (FieldLines, Option<usize>) {
    let focused = form.focus() == field;
    let value_width = inner_width.saturating_sub(VALUE_COLUMN).max(1);
    let (value, cursor) = value_spans(form, field, focused, value_width, theme, cleaner);

    let marker = if focused { "> " } else { "  " };
    let label = format!("{:<LABEL_WIDTH$} ", field.label());
    let label_style = if focused {
        theme.key
    } else {
        Default::default()
    };
    let mut spans = vec![Span::raw(marker), Span::styled(label, label_style)];
    spans.extend(value);
    let mut lines = vec![Line::from(spans)];

    let indent = " ".repeat(VALUE_COLUMN);
    if let Some(message) = form.error(field) {
        for line in labeled_lines("Error:", theme.error, message, value_width, cleaner) {
            lines.push(indented(&indent, line));
        }
    }
    if field == FormField::ForwardAgent && form.forward_agent() {
        for line in labeled_lines(
            "Warning:",
            theme.warning,
            AGENT_WARNING,
            value_width,
            cleaner,
        ) {
            lines.push(indented(&indent, line));
        }
    }
    (
        FieldLines { field, lines },
        cursor.map(|c| VALUE_COLUMN + c),
    )
}

fn indented(indent: &str, line: Line<'static>) -> Line<'static> {
    let mut spans = vec![Span::raw(indent.to_string())];
    spans.extend(line.spans);
    Line::from(spans)
}

/// The help for the focused field: what it is for and an example.
fn help_lines(field: FormField, width: usize, theme: &Theme) -> Vec<Line<'static>> {
    let help = field.help();
    let mut lines: Vec<Line<'static>> = wrap(help.explanation, width.max(1))
        .into_iter()
        .map(Line::raw)
        .collect();
    if lines.len() > HELP_LINES - 1 {
        lines.truncate(HELP_LINES - 1);
        if let Some(last) = lines.last_mut() {
            let text: String = last.spans.iter().map(|s| s.content.as_ref()).collect();
            *last = Line::raw(truncate(&format!("{text}..."), width).0);
        }
    }
    while lines.len() < HELP_LINES - 1 {
        lines.push(Line::raw(""));
    }
    lines.push(Line::from(vec![
        Span::styled("Example: ", theme.muted),
        Span::raw(truncate(help.example, width.saturating_sub(9)).0),
    ]));
    lines
}

/// Where the visible window of the form starts so that the focused row is in
/// view (its first line at least), moving as little as possible.
fn window_for(offset: usize, first: usize, last: usize, visible: usize, total: usize) -> usize {
    let start = window_start(offset, Some(first), visible, total);
    if last > start + visible {
        // A row taller than the window shows its beginning.
        (last - visible).min(first)
    } else {
        start
    }
}

fn picker_lines(
    picker: &Picker,
    theme: &Theme,
    cleaner: &mut Cleaner,
    visible: usize,
) -> Vec<Line<'static>> {
    let start = window_start(0, Some(picker.selected), visible, picker.options.len());
    picker
        .options
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(index, option)| {
            let name = match option {
                Some(name) => cleaner.clean(name).into_owned(),
                None => "(none)".to_string(),
            };
            let selected = index == picker.selected;
            let line = Line::raw(format!("{}{name}", if selected { "> " } else { "  " }));
            if selected {
                line.style(theme.selected)
            } else {
                line
            }
        })
        .collect()
}

/// The widest a key's name is allowed to be in the list of keys.
const KEY_NAME_WIDTH: usize = 24;

/// The list of key files: each key with its type, "none" and "another file", and
/// under it what is worth saying about the list. `height` is how many lines the
/// popup has room for.
fn key_picker_lines(
    picker: &KeyPicker,
    theme: &Theme,
    cleaner: &mut Cleaner,
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let note: Vec<Line<'static>> = picker
        .note
        .as_deref()
        .map(|note| {
            let mut lines = vec![Line::raw("")];
            lines.extend(
                wrap(&cleaner.clean(note), width.max(1))
                    .into_iter()
                    .map(|piece| Line::styled(piece, theme.muted)),
            );
            lines
        })
        .unwrap_or_default();
    // The note is what explains an empty list, so it keeps its room and the list
    // is what gives way.
    let rows = height.saturating_sub(note.len()).max(3);
    let rows = rows.min(picker.options.len());

    let names: Vec<String> = picker
        .options
        .iter()
        .map(|option| match option {
            KeyPick::None => "(none)".to_string(),
            KeyPick::Key(choice) => cleaner.clean(&choice.name).into_owned(),
            KeyPick::Typed => "Another file".to_string(),
        })
        .collect();
    let name_width = names
        .iter()
        .map(|name| display_width(name))
        .max()
        .unwrap_or(0)
        .min(KEY_NAME_WIDTH);
    let start = window_start(0, Some(picker.selected), rows, picker.options.len());

    let mut lines: Vec<Line<'static>> = picker
        .options
        .iter()
        .enumerate()
        .skip(start)
        .take(rows)
        .map(|(index, option)| {
            let detail = match option {
                KeyPick::None => "ssh uses its default keys".to_string(),
                KeyPick::Key(choice) => choice
                    .kind
                    .clone()
                    .unwrap_or_else(|| "type unknown".to_string()),
                KeyPick::Typed => match &picker.typed {
                    Some(path) => format!("keeps {}", cleaner.clean(path)),
                    None => "type a path yourself".to_string(),
                },
            };
            let name = truncate(&names[index], name_width).0;
            let selected = index == picker.selected;
            let text = format!(
                "{}{}  {}",
                if selected { "> " } else { "  " },
                pad(&name, name_width),
                truncate(&detail, width.saturating_sub(name_width + 4)).0
            );
            if selected {
                Line::styled(pad(&text, width), theme.selected)
            } else {
                Line::raw(text)
            }
        })
        .collect();
    lines.extend(note);
    lines
}

pub(super) fn render(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) -> Metrics {
    let Some(form) = app.form() else {
        return Metrics::default();
    };
    let inner_width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();

    let mut rows = Vec::new();
    let mut cursor_column = None;
    for field in form.fields() {
        let (row, cursor) = field_lines(form, field, inner_width, theme, &mut cleaner);
        if field == form.focus() {
            cursor_column = cursor;
        }
        rows.push(row);
    }
    let banner: Vec<Line<'static>> = form
        .notice()
        .map(|text| {
            let mut lines = labeled_lines("Error:", theme.error, text, inner_width, &mut cleaner);
            lines.truncate(MAX_BANNER_LINES);
            lines
        })
        .unwrap_or_default();
    let help = help_lines(form.focus(), inner_width, theme);
    let title = cleaner.clean(&form.title()).into_owned();

    // Built before the footer: what it cleans is counted in what the footer says.
    let key_popup = match form.mode() {
        FormMode::PickKey(picker) => {
            // A popup is at most this wide, less its border and padding.
            let width = usize::from(area.width.saturating_sub(2))
                .min(64)
                .saturating_sub(4)
                .max(1);
            let height = usize::from(area.height).saturating_sub(4).max(1);
            Some(key_picker_lines(picker, theme, &mut cleaner, width, height))
        }
        _ => None,
    };

    let footer = footer_lines(
        &app.footer_hints(),
        cleaner.hidden,
        theme,
        usize::from(area.width),
    );
    let chrome = split_chrome(area, 0, footer.len());
    let inner = page_block().inner(chrome.main);
    let [banner_area, body_area, help_area] = Layout::vertical([
        Constraint::Length(u16::try_from(banner.len()).unwrap_or(u16::MAX)),
        Constraint::Min(0),
        Constraint::Length(u16::try_from(HELP_LINES).unwrap_or(4)),
    ])
    .areas(inner);

    // Which lines the focused row takes, and which part of the form is shown.
    let total: usize = rows.iter().map(|row| row.lines.len()).sum();
    let mut first = 0;
    let mut last = 0;
    let mut line_count = 0;
    for row in &rows {
        if row.field == form.focus() {
            first = line_count;
            last = line_count + row.lines.len();
        }
        line_count += row.lines.len();
    }
    let visible = usize::from(body_area.height);
    let start = window_for(form.scroll, first, last, visible, total);

    let all: Vec<Line<'static>> = rows.into_iter().flat_map(|row| row.lines).collect();
    let end = (start + visible).min(all.len());

    let mut block = page_block().title(Span::styled(format!(" {title} "), theme.title));
    if total > visible {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" lines {}-{} of {} ", start + 1, end, total),
                theme.muted,
            ))
            .right_aligned(),
        );
    }
    frame.render_widget(block, chrome.main);
    frame.render_widget(Paragraph::new(banner), banner_area);
    frame.render_widget(Paragraph::new(all[start..end].to_vec()), body_area);
    frame.render_widget(Paragraph::new(help), help_area);

    match form.mode() {
        FormMode::Editing => {
            if let Some(column) = cursor_column {
                place_cursor(frame, body_area, column, first.saturating_sub(start));
            }
        }
        FormMode::PickJump(picker) => {
            let room = usize::from(area.height).saturating_sub(6).max(1);
            let lines = picker_lines(picker, theme, &mut cleaner, room.min(picker.options.len()));
            render_popup(frame, area, "Jump host", lines, theme);
        }
        FormMode::PickKey(_) => {
            render_popup(
                frame,
                area,
                "Key file",
                key_popup.unwrap_or_default(),
                theme,
            );
        }
        FormMode::ConfirmDiscard => {
            let lines = vec![
                Line::raw("You have unsaved changes."),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("y", theme.key),
                    Span::raw(" discard them    "),
                    Span::styled("n", theme.key),
                    Span::raw(" keep editing"),
                ]),
            ];
            render_popup(frame, area, "Discard changes?", lines, theme);
        }
    }

    render_chrome(frame, &chrome, Vec::new(), footer);
    Metrics {
        form_scroll: start,
        ..Metrics::default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::MIN_WIDTH;
    use super::super::testing::*;
    use super::*;
    use crate::domain::Host;
    use crate::tui::wrap::display_width;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_key(key(c));
        }
    }

    fn tab(app: &mut App, times: usize) {
        for _ in 0..times {
            app.handle_key(press(KeyCode::Tab));
        }
    }

    fn app_with_hosts() -> App {
        let mut web = host("web", "web.example.com");
        web.user = Some("deploy".to_string());
        app_with(
            vec![web, host("db", "10.0.0.2"), host("bastion", "10.0.0.9")],
            Vec::new(),
        )
    }

    fn add_form(app: &mut App) {
        app.handle_key(key('a'));
    }

    #[test]
    fn the_form_lists_every_basic_field_and_the_collapsed_advanced_row() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        let text = text_of(&mut app, 80, 30);
        assert!(text.contains("Add host"), "{text}");
        for label in [
            "Name",
            "Hostname",
            "User",
            "Port",
            "Identity file",
            "Tags",
            "Notes",
            "Advanced",
        ] {
            assert!(text.contains(label), "{label} missing:\n{text}");
        }
        assert!(text.contains("[+] hidden"), "{text}");
        assert!(
            !text.contains("Jump host"),
            "the advanced fields are collapsed:\n{text}"
        );
        assert!(!text.contains("Forward agent"), "{text}");
    }

    #[test]
    fn required_and_optional_fields_say_so_when_empty() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        tab(&mut app, 2);
        let text = text_of(&mut app, 80, 30);
        assert!(line_with(&text, "Name").contains("(required)"), "{text}");
        assert!(
            line_with(&text, "Hostname").contains("(required)"),
            "{text}"
        );
        assert!(line_with(&text, "Port").contains("(optional)"), "{text}");
    }

    fn line_with<'a>(text: &'a str, needle: &str) -> &'a str {
        text.lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no line with {needle:?} in:\n{text}"))
    }

    #[test]
    fn the_focused_field_is_marked_and_shows_its_help_and_an_example() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        let text = text_of(&mut app, 80, 30);
        assert!(line_with(&text, "Name").contains("> Name"), "{text}");
        assert!(!line_with(&text, "Hostname").contains(">"), "{text}");
        assert!(
            text.contains("A short label for this connection."),
            "{text}"
        );
        assert!(text.contains("Example: prod-web-1"), "{text}");

        tab(&mut app, 1);
        let text = text_of(&mut app, 80, 30);
        assert!(
            line_with(&text, "Hostname").contains("> Hostname"),
            "{text}"
        );
        assert!(
            text.contains("The server's DNS name or IP address."),
            "{text}"
        );
        assert!(text.contains("Example: web.example.com"), "{text}");
    }

    #[test]
    fn every_field_shows_help_that_fits_its_area_on_the_smallest_terminal() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        app.handle_key(press(KeyCode::BackTab));
        app.handle_key(press(KeyCode::Enter));
        for _ in 0..12 {
            let focus = app.form().unwrap().focus();
            let help = focus.help();
            let text = text_of(&mut app, 60, 15);
            assert!(text.contains("Example:"), "{focus:?}:\n{text}");
            let words: Vec<&str> = help.explanation.split(' ').take(3).collect();
            assert!(
                text.contains(&words.join(" ")),
                "{focus:?} help starts with {words:?}:\n{text}"
            );
            // Explanations are cut, never allowed to push the fields away.
            let lines = wrap(help.explanation, 54);
            assert!(lines.len() <= 4, "{focus:?} needs {} lines", lines.len());
            app.handle_key(press(KeyCode::Tab));
        }
    }

    #[test]
    fn the_notes_help_explains_how_to_insert_a_line_break() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        tab(&mut app, 6);
        assert_eq!(app.form().unwrap().focus(), FormField::Notes);
        let text = text_of(&mut app, 100, 30);
        assert!(
            text.contains("Type \\n (backslash, n) to insert a line break."),
            "{text}"
        );
        assert!(
            text.contains("Example: Nightly backup runs here.\\nOwner: ops team"),
            "{text}"
        );
    }

    #[test]
    fn typed_text_appears_in_the_field_and_the_cursor_follows_it() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        type_text(&mut app, "app");
        let mut terminal = draw(&mut app, 80, 30);
        let text = screen_text(&terminal);
        assert!(
            line_with(&text, "Name").contains("> Name           app"),
            "{text}"
        );
        let cursor = terminal.get_cursor_position().unwrap();
        // Border, padding, marker and label, then "app".
        assert_eq!(cursor.x, 2 + VALUE_COLUMN as u16 + 3);
        assert_eq!(cursor.y, 1);
    }

    #[test]
    fn a_field_with_an_error_shows_it_next_to_the_field_in_words() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        type_text(&mut app, "bad name");
        tab(&mut app, 1);
        let text = text_of(&mut app, 80, 30);
        let lines: Vec<&str> = text.lines().collect();
        let at = lines.iter().position(|l| l.contains("Name")).unwrap();
        assert!(lines[at].contains("bad name"), "{text}");
        assert!(lines[at + 1].contains("Error:"), "{text}");
        assert!(
            lines[at + 1].contains("Name may only contain letters"),
            "{text}"
        );
        assert!(!lines[at + 2].contains("Error:"), "only that field: {text}");
    }

    #[test]
    fn a_blocked_save_marks_every_problem_and_says_why_at_the_top() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        let text = text_of(&mut app, 80, 30);
        assert!(
            text.contains("Error: Fix the fields marked with an error before saving."),
            "{text}"
        );
        assert!(text.contains("Name cannot be empty."), "{text}");
        assert!(text.contains("Hostname cannot be empty."), "{text}");
        assert_eq!(app.screen(), Screen::Form);
    }

    use crate::tui::app::Screen;

    #[test]
    fn the_advanced_section_shows_its_fields_when_opened() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        app.handle_key(press(KeyCode::BackTab));
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 80, 40);
        assert!(text.contains("[-] shown"), "{text}");
        for label in [
            "Jump host",
            "Local forwards",
            "Remote fwds",
            "Forward agent",
        ] {
            assert!(text.contains(label), "{label} missing:\n{text}");
        }
        assert!(line_with(&text, "Jump host").contains("(none)"), "{text}");
        assert!(
            line_with(&text, "Forward agent").contains("[ ] off"),
            "{text}"
        );
    }

    fn open_advanced(app: &mut App) {
        add_form(app);
        app.handle_key(press(KeyCode::BackTab));
        app.handle_key(press(KeyCode::Enter));
    }

    #[test]
    fn turning_on_agent_forwarding_shows_the_security_warning_in_words() {
        let mut app = app_with_hosts();
        open_advanced(&mut app);
        tab(&mut app, 4);
        assert_eq!(app.form().unwrap().focus(), FormField::ForwardAgent);
        assert!(!text_of(&mut app, 80, 40).contains("Warning:"));

        app.handle_key(key(' '));
        let text = text_of(&mut app, 80, 40);
        assert!(
            line_with(&text, "Forward agent").contains("[x] on"),
            "{text}"
        );
        let flat = text
            .split_whitespace()
            .filter(|word| *word != "│")
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            text.contains("Warning: Anyone who controls this server"),
            "{text}"
        );
        assert!(
            flat.contains("can use your ssh keys while you are connected."),
            "{text}"
        );
        assert!(flat.contains("fully trust"), "{text}");

        app.handle_key(key(' '));
        assert!(
            !text_of(&mut app, 80, 40).contains("Warning:"),
            "off again: no warning"
        );
    }

    #[test]
    fn the_jump_host_list_appears_over_the_form_and_shows_the_choices() {
        let mut app = app_with_hosts();
        open_advanced(&mut app);
        tab(&mut app, 1);
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 80, 30);
        assert!(text.contains("Jump host"), "{text}");
        assert!(text.contains("> (none)"), "{text}");
        for name in ["bastion", "db", "web"] {
            assert!(text.contains(name), "{name} missing:\n{text}");
        }
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("Enter choose"), "{footer}");

        app.handle_key(press(KeyCode::Down));
        let text = text_of(&mut app, 80, 30);
        assert!(text.contains("> bastion"), "{text}");
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 80, 30);
        assert!(line_with(&text, "Jump host").contains("bastion"), "{text}");
    }

    #[test]
    fn asking_to_discard_shows_the_question_with_both_answers() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        type_text(&mut app, "app");
        app.handle_key(press(KeyCode::Esc));
        let text = text_of(&mut app, 80, 30);
        assert!(text.contains("Discard changes?"), "{text}");
        assert!(text.contains("You have unsaved changes."), "{text}");
        assert!(text.contains("y discard them"), "{text}");
        assert!(text.contains("n keep editing"), "{text}");
        assert!(text.contains("app"), "the input is still behind it: {text}");
    }

    #[test]
    fn editing_shows_the_host_being_edited_in_the_title_and_the_fields() {
        let mut app = app_with_hosts();
        app.handle_key(key('j'));
        app.handle_key(key('j'));
        app.handle_key(key('e'));
        let text = text_of(&mut app, 80, 30);
        assert!(text.contains("Edit host 'web'"), "{text}");
        assert!(
            line_with(&text, "Hostname").contains("web.example.com"),
            "{text}"
        );
        assert!(line_with(&text, "User").contains("deploy"), "{text}");
    }

    #[test]
    fn a_long_value_scrolls_inside_its_field_and_the_cursor_stays_visible() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        tab(&mut app, 4);
        type_text(&mut app, &"k".repeat(120));
        let mut terminal = draw(&mut app, 60, 20);
        let cursor = terminal.get_cursor_position().unwrap();
        assert!(usize::from(cursor.x) < 60 - 2, "{cursor:?}");
        for line in screen_text(&terminal).lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
    }

    #[test]
    fn a_tall_form_scrolls_to_keep_the_focused_field_in_view() {
        let mut app = app_with_hosts();
        open_advanced(&mut app);
        // 60x15 leaves room for only a few fields.
        for step in 0..12 {
            let text = text_of(&mut app, 60, 15);
            let focus = app.form().unwrap().focus();
            assert!(
                text.contains(&format!("> {}", focus.label())),
                "step {step}: {focus:?} should be visible and marked:\n{text}"
            );
            tab(&mut app, 1);
        }
        // Going back up brings the top back.
        for _ in 0..12 {
            app.handle_key(press(KeyCode::BackTab));
            let focus = app.form().unwrap().focus();
            let text = text_of(&mut app, 60, 15);
            assert!(
                text.contains(&format!("> {}", focus.label())),
                "{focus:?}:\n{text}"
            );
        }
        while app.form().unwrap().focus() != FormField::Name {
            app.handle_key(press(KeyCode::BackTab));
        }
        let text = text_of(&mut app, 60, 15);
        assert!(text.contains("> Name"), "back at the top:\n{text}");
    }

    #[test]
    fn a_form_that_does_not_fit_shows_a_position_indicator() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        assert!(
            !text_of(&mut app, 60, 15).contains("lines 1-"),
            "the seven basic fields and the Advanced row fit the smallest terminal"
        );
        app.handle_key(press(KeyCode::BackTab));
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 60, 15);
        assert!(
            text.contains("lines 2-9 of 13"),
            "scrolled so the focused row is visible: {text}"
        );
        assert!(!text_of(&mut app, 100, 50).contains("lines "));
    }

    #[test]
    fn the_form_footer_lists_its_keys_and_changes_with_the_focused_row() {
        let mut app = app_with_hosts();
        add_form(&mut app);
        let text = text_of(&mut app, 80, 30);
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("Tab/Shift+Tab move"), "{footer}");
        assert!(footer.contains("Ctrl+S save"), "{footer}");
        assert!(footer.contains("Esc cancel"), "{footer}");

        app.handle_key(press(KeyCode::BackTab));
        assert!(
            text_of(&mut app, 80, 30)
                .lines()
                .last()
                .unwrap()
                .contains("Enter show/hide")
        );
    }

    #[test]
    fn host_derived_text_in_the_form_is_sanitized() {
        // The form's values come from typing or from a stored host; both are
        // validated, but a `Host` is a plain struct, so the screen defends itself.
        let mut odd = Host::new("we\x1bb", "10.0.0.1");
        odd.user = Some("de\u{202e}p".to_string());
        let hosts = crate::domain::Hosts::from_vec(vec![host("ok", "10.0.0.2")]).unwrap();
        let mut app = crate::tui::app::App::new(crate::tui::startup::Startup::loaded(
            hosts,
            crate::tui::persist::testing::FakeStore::default(),
            Vec::new(),
        ));
        // Opening a form for a host with unsafe characters is only possible
        // through the type, so exercise the renderer with the form directly.
        let form = Form::edit(&odd);
        let mut cleaner = Cleaner::default();
        let (row, _) = field_lines(&form, FormField::Name, 60, &Theme::plain(), &mut cleaner);
        let shown: String = row.lines[0]
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(shown.contains("we?b"), "{shown:?}");
        assert!(cleaner.hidden);
        let (row, _) = field_lines(&form, FormField::User, 60, &Theme::plain(), &mut cleaner);
        let shown: String = row.lines[0]
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(shown.contains("de?p"), "{shown:?}");
        let _ = &mut app;
    }

    #[test]
    fn the_form_stays_within_the_window_at_the_smallest_size() {
        let mut app = app_with_hosts();
        open_advanced(&mut app);
        for _ in 0..12 {
            let text = text_of(&mut app, usize::from(MIN_WIDTH) as u16, 15);
            for line in text.lines() {
                assert!(display_width(line) <= usize::from(MIN_WIDTH), "{line:?}");
            }
            tab(&mut app, 1);
        }
    }

    // ---- the list of key files ---------------------------------------------------

    fn flat_words(text: &str) -> String {
        text.split_whitespace()
            .filter(|word| !word.chars().all(|c| "│┌┐└┘─".contains(c)))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// An add form on the identity file, with these keys' names and types listed
    /// (`None` for a key whose type could not be read).
    fn key_list_app(keys: Vec<(&str, Option<&str>)>, snapshot_note: bool) -> App {
        use crate::ssh::keys::Permissions;
        use crate::tui::effects::{Request, Response};
        use crate::tui::keys::testing::{entry, snapshot};
        let mut app = app_with(vec![Host::new("web", "192.0.2.1")], Vec::new());
        app.handle_key(key('a'));
        tab(&mut app, 4);
        app.handle_key(press(KeyCode::Enter));
        let request = app.take_request().unwrap();
        assert_eq!(request, Request::ListKeys);
        let entries = keys
            .into_iter()
            .map(|(name, kind)| {
                let mut key = entry(name, Permissions::Fine, false);
                match kind {
                    Some(kind) => {
                        if let Ok(found) = &mut key.fingerprint {
                            let (name, bits) = kind.split_once(' ').unwrap_or((kind, "256"));
                            found.key_type = name.to_uppercase();
                            found.bits = bits.parse().unwrap_or(256);
                        }
                    }
                    None => key.fingerprint = Err("ssh-keygen could not read it".to_string()),
                }
                key
            })
            .collect();
        let mut snap = snapshot(entries);
        snap.missing_dir = snapshot_note;
        app.handle_response(&request, Response::KeyList(snap));
        app
    }

    #[test]
    fn the_list_shows_none_each_key_with_its_type_and_another_file() {
        let mut app = key_list_app(
            vec![
                ("id_ed25519", Some("ed25519")),
                ("id_rsa_old", Some("rsa 3072")),
                ("odd", None),
            ],
            false,
        );
        let text = text_of(&mut app, 100, 30);
        assert!(text.contains("Key file"), "{text}");
        let words = flat_words(&text);
        for expected in [
            "> (none) ssh uses its default keys",
            "id_ed25519 ed25519",
            "id_rsa_old rsa 3072",
            "odd type unknown",
            "Another file type a path yourself",
        ] {
            assert!(words.contains(expected), "{expected}:\n{text}");
        }
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("Up/Down j/k move")
                && footer.contains("Enter choose")
                && footer.contains("Esc close"),
            "{footer}"
        );
    }

    #[test]
    fn the_selection_marker_follows_the_choice_and_a_typed_path_is_kept_in_view() {
        let mut app = key_list_app(vec![("id_ed25519", Some("ed25519"))], false);
        app.handle_key(key('j'));
        assert!(flat_words(&text_of(&mut app, 100, 30)).contains("> id_ed25519 ed25519"));
        app.handle_key(press(KeyCode::Esc));
        type_text(&mut app, "/elsewhere/key");
        app.handle_key(press(KeyCode::Enter));
        let words = flat_words(&text_of(&mut app, 100, 30));
        assert!(
            words.contains("> Another file keeps /elsewhere/key"),
            "{words}"
        );
    }

    #[test]
    fn with_no_keys_the_list_says_what_to_do_about_it() {
        let mut app = key_list_app(Vec::new(), false);
        let words = flat_words(&text_of(&mut app, 100, 30));
        assert!(
            words.contains("(none)") && words.contains("Another file"),
            "{words}"
        );
        assert!(
            words.contains("There are no key pairs in /home/dev/.ssh. Make one from the keys screen (K, then g)"),
            "{words}"
        );
        let mut missing = key_list_app(Vec::new(), true);
        assert!(flat_words(&text_of(&mut missing, 100, 30)).contains("does not exist yet"));
    }

    #[test]
    fn on_the_smallest_terminal_the_list_keeps_every_choice_and_its_note() {
        let mut app = key_list_app(Vec::new(), false);
        let text = text_of(&mut app, 60, 15);
        let words = flat_words(&text);
        for expected in [
            "(none)",
            "Another file",
            "There are no key pairs",
            "Another file and type a path.",
        ] {
            assert!(words.contains(expected), "{expected}:\n{text}");
        }
        for line in text.lines() {
            assert!(display_width(line) <= 60, "{line}");
        }
    }

    #[test]
    fn many_keys_scroll_with_the_choice_and_the_last_ones_are_reachable() {
        let names: Vec<String> = (0..30).map(|n| format!("key{n:02}")).collect();
        let mut app = key_list_app(
            names
                .iter()
                .map(|n| (n.as_str(), Some("ed25519")))
                .collect(),
            false,
        );
        draw(&mut app, 60, 15);
        for _ in 0..40 {
            app.handle_key(key('j'));
            draw(&mut app, 60, 15);
        }
        let words = flat_words(&text_of(&mut app, 60, 15));
        assert!(
            words.contains("> Another file"),
            "the last choice is selected and shown: {words}"
        );
        assert!(
            !words.contains("key00"),
            "the first ones scrolled away: {words}"
        );
    }

    #[test]
    fn key_names_from_outside_are_cleaned_and_the_footer_says_so() {
        // A name with control characters never gets this far (the form refuses
        // the path it would give), but a bidirectional override is not a control
        // character, so it can, and must not be drawn.
        let mut app = key_list_app(vec![("evil\u{202e}key", Some("ed25519"))], false);
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(
                !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                "{:?}",
                cell.symbol()
            );
        }
        let text = screen_text(&terminal);
        assert!(text.contains("evil"), "still shown, cleaned:\n{text}");
        assert!(
            flat_words(&text).contains("non-printable characters were hidden"),
            "and the footer says so:\n{text}"
        );
    }

    #[test]
    fn a_key_whose_name_has_control_characters_is_not_offered_at_all() {
        let mut app = key_list_app(
            vec![
                ("fine", Some("ed25519")),
                ("evil\x1b]0;pwned\x07key", Some("ed25519")),
            ],
            false,
        );
        let text = text_of(&mut app, 100, 30);
        assert!(flat_words(&text).contains("fine ed25519"), "{text}");
        assert!(!text.contains("evil"), "{text}");
        assert!(!text.contains("pwned"), "{text}");
    }

    #[test]
    fn the_identity_file_row_shows_what_was_chosen() {
        let mut app = key_list_app(vec![("id_ed25519", Some("ed25519"))], false);
        app.handle_key(key('j'));
        app.handle_key(press(KeyCode::Enter));
        let words = flat_words(&text_of(&mut app, 100, 30));
        assert!(words.contains("Identity file ~/.ssh/id_ed25519"), "{words}");
        assert!(!words.contains("Key file"), "the list is closed: {words}");
    }
}
