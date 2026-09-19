//! The host list screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::modal::{place_cursor, render_panel, render_popup};

use super::{
    Cleaner, footer_lines, input_window, labeled_lines, page_block, render_chrome, split_chrome,
    status_lines,
};
use crate::domain::Host;
use crate::tui::app::{App, ListMode, Metrics};
use crate::tui::list::{HostMatch, is_blank, window_start};
use crate::tui::theme::Theme;
use crate::tui::wrap::{display_width, pad, truncate, wrap};

/// The columns before the name: selection marker, space, favorite marker, space.
const PREFIX_WIDTH: usize = 4;
const COLUMN_GAP: &str = "  ";
const MAX_NAME_WIDTH: usize = 24;
const MAX_TAGS_WIDTH: usize = 24;
const SEARCH_LABEL: &str = "Search: ";

/// One host as the text of its columns, sanitized, with the characters a search
/// matched.
struct Cells {
    favorite: bool,
    name: String,
    name_hits: Vec<usize>,
    target: String,
    target_hits: Vec<usize>,
    tags: String,
    tag_hits: Vec<usize>,
}

fn cells_for(host: &Host, matched: Option<&HostMatch>, cleaner: &mut Cleaner) -> Cells {
    let mut clean = |text: &str| cleaner.clean(text).into_owned();

    let name = clean(&host.name);
    let hostname = clean(&host.hostname);
    let user = host.user.as_deref().map(&mut clean);

    let mut target = String::new();
    if let Some(user) = &user {
        target.push_str(user);
        target.push('@');
    }
    let hostname_at = target.chars().count();
    target.push_str(&hostname);
    // The port is only shown when set.
    if let Some(port) = host.port {
        target.push_str(&format!(":{port}"));
    }

    let mut tags = String::new();
    let mut tag_hits = Vec::new();
    for (index, tag) in host.tags.iter().enumerate() {
        if index > 0 {
            tags.push(' ');
        }
        tags.push('#');
        let start = tags.chars().count();
        tags.push_str(&clean(tag));
        if let Some(positions) = matched.and_then(|m| m.tags.get(index)) {
            tag_hits.extend(positions.iter().map(|p| start + p));
        }
    }

    Cells {
        favorite: host.favorite,
        name,
        name_hits: matched.map(|m| m.name.clone()).unwrap_or_default(),
        target,
        target_hits: matched
            .map(|m| m.hostname.iter().map(|p| hostname_at + p).collect())
            .unwrap_or_default(),
        tags,
        tag_hits,
    }
}

/// The widths of the three columns for a list `width` cells wide.
struct Columns {
    name: usize,
    target: usize,
    tags: usize,
}

fn columns(cells: &[Cells], width: usize) -> Columns {
    let widest = |text: fn(&Cells) -> &str| {
        cells
            .iter()
            .map(|cell| display_width(text(cell)))
            .max()
            .unwrap_or(0)
    };
    let available = width.saturating_sub(PREFIX_WIDTH);
    let gap = COLUMN_GAP.len();

    let name = widest(|c| &c.name)
        .min(MAX_NAME_WIDTH)
        .min(available * 2 / 5)
        .max(4.min(available));
    let rest = available.saturating_sub(name + gap);

    let max_target = widest(|c| &c.target);
    let max_tags = widest(|c| &c.tags).min(MAX_TAGS_WIDTH);
    // Tags get a third of what is left at most; the target column takes the
    // rest, and hands back what it does not need.
    let tags_share = if max_tags == 0 {
        0
    } else {
        (rest / 3).min(max_tags)
    };
    let target_room = rest.saturating_sub(if tags_share > 0 { tags_share + gap } else { 0 });
    let target = target_room.min(max_target);
    let tags = if max_tags == 0 {
        0
    } else {
        rest.saturating_sub(target + gap).min(max_tags)
    };
    Columns {
        name,
        target,
        tags: if tags >= 4 { tags } else { 0 },
    }
}

/// A cell's text as spans, cut and padded to `width`, with `hits` highlighted.
fn cell_spans(text: &str, hits: &[usize], width: usize, theme: &Theme) -> Vec<Span<'static>> {
    let (shown, kept) = truncate(text, width);
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut run = String::new();
    let mut run_hit = false;
    for (index, ch) in shown.chars().enumerate() {
        let hit = index < kept && hits.contains(&index);
        if hit != run_hit && !run.is_empty() {
            spans.push(styled_run(std::mem::take(&mut run), run_hit, theme));
        }
        run_hit = hit;
        run.push(ch);
    }
    if !run.is_empty() {
        spans.push(styled_run(run, run_hit, theme));
    }
    let padding = width.saturating_sub(display_width(&shown));
    if padding > 0 {
        spans.push(Span::raw(" ".repeat(padding)));
    }
    spans
}

fn styled_run(text: String, hit: bool, theme: &Theme) -> Span<'static> {
    if hit {
        Span::styled(text, theme.highlight)
    } else {
        Span::raw(text)
    }
}

fn row_line(
    cells: &Cells,
    columns: &Columns,
    selected: bool,
    width: usize,
    theme: &Theme,
) -> Line<'static> {
    let mut spans = vec![
        Span::raw(if selected { "> " } else { "  " }),
        if cells.favorite {
            Span::styled("* ", theme.favorite)
        } else {
            Span::raw("  ")
        },
    ];
    spans.extend(cell_spans(
        &cells.name,
        &cells.name_hits,
        columns.name,
        theme,
    ));
    spans.push(Span::raw(COLUMN_GAP));
    spans.extend(cell_spans(
        &cells.target,
        &cells.target_hits,
        columns.target,
        theme,
    ));
    if columns.tags > 0 {
        spans.push(Span::raw(COLUMN_GAP));
        spans.extend(cell_spans(
            &cells.tags,
            &cells.tag_hits,
            columns.tags,
            theme,
        ));
    }
    let used: usize = spans.iter().map(|span| span.width()).sum();
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
    let line = Line::from(spans);
    if selected {
        line.style(theme.selected)
    } else {
        line
    }
}

fn column_header(columns: &Columns, width: usize, theme: &Theme) -> Line<'static> {
    let mut text = " ".repeat(PREFIX_WIDTH);
    text.push_str(&pad(&truncate("Name", columns.name).0, columns.name));
    text.push_str(COLUMN_GAP);
    text.push_str(&pad(&truncate("Target", columns.target).0, columns.target));
    if columns.tags > 0 {
        text.push_str(COLUMN_GAP);
        text.push_str(&truncate("Tags", columns.tags).0);
    }
    Line::styled(pad(&text, width), theme.muted)
}

/// What to say instead of a list.
fn empty_message(
    searching: bool,
    query: &str,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut paragraph = |text: &str| {
        for piece in wrap(text, width.max(1)) {
            lines.push(Line::raw(piece));
        }
    };
    if searching {
        let shown = cleaner.clean(query);
        paragraph(&format!("No hosts match \"{shown}\"."));
        paragraph("");
        paragraph("Check the spelling, or press Esc to clear the search and see all your hosts.");
    } else {
        paragraph("You have no saved hosts yet.");
        paragraph("");
        paragraph(
            "Press a to add your first host. You only need a name (any label you like) \
             and the hostname or IP address of the server.",
        );
        paragraph("");
        paragraph("Press ? to see all the keys.");
    }
    lines
}

/// Something drawn over the list: the delete confirmation or the ssh command.
enum Overlay {
    /// A centered box. `cursor` is the row and column of the text cursor
    /// inside it, when something is being typed.
    Popup {
        title: &'static str,
        lines: Vec<Line<'static>>,
        cursor: Option<(usize, usize)>,
    },
    /// Text across the whole width, meant to be selected and copied.
    Panel {
        title: String,
        lines: Vec<Line<'static>>,
    },
}

const DELETE_MISMATCH: &str =
    "That is not the host's name. Type it exactly, or press Esc to cancel.";
const COPY_REQUESTED: &str = "Copy requested: your terminal was asked to put this command on its \
     clipboard. Terminals that do not support this ignore the request, so if nothing was copied, \
     select the text above with the mouse.";
const JOIN_HINT: &str = "The command is split over several lines to fit; when you copy it by hand, \
     join the lines with spaces.";

/// The overlay for the current mode, built before the footer so that any text
/// hidden by sanitizing is counted.
fn overlay_for(app: &App, theme: &Theme, area: Rect, cleaner: &mut Cleaner) -> Option<Overlay> {
    match app.mode() {
        ListMode::ConfirmDelete => {
            let confirm = app.delete()?;
            // A popup is at most 60 wide, less its border and padding.
            let width = usize::from(area.width.saturating_sub(2))
                .min(60)
                .saturating_sub(4)
                .max(1);
            let mut lines = labeled_lines(
                "",
                Default::default(),
                &format!("Delete host '{}'?", confirm.name),
                width,
                cleaner,
            );
            lines.extend(labeled_lines(
                "",
                Default::default(),
                "This removes its saved settings and notes. It cannot be undone.",
                width,
                cleaner,
            ));
            lines.push(Line::raw(""));
            lines.push(Line::raw("Type the host name to confirm:"));

            let typed = cleaner.clean(confirm.input.value()).into_owned();
            let (visible, column) =
                input_window(&typed, confirm.input.cursor(), width.saturating_sub(2));
            let cursor = (lines.len(), 2 + column);
            lines.push(Line::from(vec![
                Span::styled("> ", theme.key),
                Span::raw(visible),
            ]));
            if confirm.mismatch {
                lines.push(Line::raw(""));
                lines.extend(labeled_lines(
                    "Error:",
                    theme.error,
                    DELETE_MISMATCH,
                    width,
                    cleaner,
                ));
            }
            Some(Overlay::Popup {
                title: "Delete host",
                lines,
                cursor: Some(cursor),
            })
        }
        ListMode::Command => {
            let view = app.command()?;
            let width = usize::from(area.width).max(1);
            let command = cleaner.clean(&view.text).into_owned();
            let mut lines: Vec<Line<'static>> =
                wrap(&command, width).into_iter().map(Line::raw).collect();
            let split = lines.len() > 1;
            lines.push(Line::raw(""));
            if split {
                lines.extend(labeled_lines(
                    "",
                    Default::default(),
                    JOIN_HINT,
                    width,
                    cleaner,
                ));
            }
            lines.extend(labeled_lines(
                "",
                Default::default(),
                COPY_REQUESTED,
                width,
                cleaner,
            ));
            let title = format!("ssh command for '{}'", cleaner.clean(&view.host));
            Some(Overlay::Panel { title, lines })
        }
        ListMode::Browse | ListMode::Search => None,
    }
}

fn notices_summary(count: usize) -> String {
    match count {
        1 => "1 problem found. Press w to read it.".to_string(),
        n => format!("{n} problems found. Press w to read them."),
    }
}

pub(super) fn render(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) -> Metrics {
    let Some(hosts) = app.hosts() else {
        return Metrics::default();
    };
    let rows = app.rows();
    let list = app.list();
    let query = list.query.value();
    let filtering = !is_blank(query);
    let searching = app.mode() == ListMode::Search;
    let inner_width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();

    let cells: Vec<Cells> = rows
        .iter()
        .map(|row| {
            cells_for(
                &hosts.as_slice()[row.index],
                row.matched.as_ref(),
                &mut cleaner,
            )
        })
        .collect();

    // The header: the search box or the count, and a summary of the warnings.
    let mut header: Vec<Line<'static>> = Vec::new();
    let mut cursor_column = None;
    if searching {
        let clean_query = cleaner.clean(query).into_owned();
        let room = inner_width.saturating_sub(SEARCH_LABEL.len());
        let (visible, column) = input_window(&clean_query, list.query.cursor(), room);
        header.push(Line::from(vec![
            Span::styled(SEARCH_LABEL, theme.key),
            Span::raw(visible),
        ]));
        cursor_column = Some(SEARCH_LABEL.len() + column);
    } else if filtering {
        let clean_query = cleaner.clean(query).into_owned();
        header.push(Line::from(vec![
            Span::styled("Filter: ", theme.key),
            Span::raw(truncate(&clean_query, inner_width.saturating_sub(8)).0),
        ]));
    } else {
        header.push(Line::raw(format!("Saved hosts: {}", hosts.len())));
    }
    if !app.notices().is_empty() {
        header.extend(labeled_lines(
            "Warning:",
            theme.warning,
            &notices_summary(app.notices().len()),
            inner_width,
            &mut cleaner,
        ));
    }

    let overlay = overlay_for(app, theme, area, &mut cleaner);
    let status = status_lines(app.status(), theme, usize::from(area.width), &mut cleaner);
    let footer = footer_lines(
        &app.footer_hints(),
        cleaner.hidden,
        theme,
        usize::from(area.width),
    );
    let chrome = split_chrome(area, status.len(), footer.len());
    let inner = page_block().inner(chrome.main);

    let show_columns = !rows.is_empty();
    let [header_area, column_area, list_area] = Layout::vertical([
        Constraint::Length(u16::try_from(header.len()).unwrap_or(u16::MAX)),
        Constraint::Length(u16::from(show_columns)),
        Constraint::Min(0),
    ])
    .areas(inner);

    let visible = usize::from(list_area.height);
    let selected = list.position(hosts, &rows);
    let start = window_start(list.offset, selected, visible, rows.len());
    let end = (start + visible).min(rows.len());

    let mut block = page_block().title(Span::styled(
        format!(" Bifrost {} ", env!("CARGO_PKG_VERSION")),
        theme.title,
    ));
    if filtering {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" {} of {} hosts ", rows.len(), hosts.len()),
                theme.muted,
            ))
            .left_aligned(),
        );
    }
    if rows.len() > visible {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" hosts {}-{} of {} ", start + 1, end, rows.len()),
                theme.muted,
            ))
            .right_aligned(),
        );
    }
    frame.render_widget(block, chrome.main);
    frame.render_widget(Paragraph::new(header), header_area);

    if show_columns {
        let cols = columns(&cells, usize::from(list_area.width));
        frame.render_widget(
            Paragraph::new(column_header(&cols, usize::from(list_area.width), theme)),
            column_area,
        );
        let lines: Vec<Line<'static>> = (start..end)
            .map(|position| {
                row_line(
                    &cells[position],
                    &cols,
                    Some(position) == selected,
                    usize::from(list_area.width),
                    theme,
                )
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), list_area);
    } else {
        let message = empty_message(filtering, query, usize::from(list_area.width), &mut cleaner);
        frame.render_widget(Paragraph::new(message), list_area);
    }

    render_chrome(frame, &chrome, status, footer);
    match overlay {
        Some(Overlay::Popup {
            title,
            lines,
            cursor,
        }) => {
            let inner = render_popup(frame, area, title, lines, theme);
            if let Some((row, column)) = cursor {
                place_cursor(frame, inner, column, row);
            }
        }
        Some(Overlay::Panel { title, lines }) => render_panel(frame, area, &title, lines, theme),
        None => {}
    }
    if let Some(column) = cursor_column {
        let x = header_area.x + u16::try_from(column).unwrap_or(0);
        frame.set_cursor_position(Position::new(
            x.min(header_area.right().saturating_sub(1)),
            header_area.y,
        ));
    }

    Metrics {
        list_rows: visible,
        ..Metrics::default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use crate::tui::startup::Notice;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::style::Modifier;

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

    fn tagged(name: &str, hostname: &str, tags: &[&str]) -> Host {
        let mut host = host(name, hostname);
        host.tags = tags.iter().map(|t| (*t).to_string()).collect();
        host
    }

    fn sample() -> Vec<Host> {
        let mut web = tagged("web", "web.example.com", &["prod", "eu"]);
        web.user = Some("deploy".to_string());
        web.port = Some(2222);
        let mut backup = tagged("backup", "10.0.0.3", &[]);
        backup.favorite = true;
        vec![web, tagged("db", "10.0.0.2", &["prod"]), backup]
    }

    fn line_of<'a>(text: &'a str, needle: &str) -> &'a str {
        text.lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no line with {needle:?} in:\n{text}"))
    }

    // ---- the list --------------------------------------------------------

    #[test]
    fn the_list_shows_marker_name_target_and_tags_in_columns() {
        let mut app = app_with(sample(), Vec::new());
        let text = text_of(&mut app, 80, 24);

        assert!(text.contains("Saved hosts: 3"), "{text}");
        let header = line_of(&text, "Name");
        assert!(
            header.contains("Target") && header.contains("Tags"),
            "{header}"
        );

        let web = line_of(&text, "web.example.com");
        assert!(
            web.contains("deploy@web.example.com:2222"),
            "user and port when set: {web}"
        );
        assert!(web.contains("#prod #eu"), "{web}");

        let db = line_of(&text, "10.0.0.2");
        assert!(!db.contains('@'), "no user, no @: {db}");
        assert!(!db.contains("10.0.0.2:"), "the port only when set: {db}");
        assert!(db.contains("#prod"), "{db}");
    }

    #[test]
    fn favorites_come_first_and_are_marked_without_relying_on_color() {
        let mut app = app_with(sample(), Vec::new());
        let text = text_of(&mut app, 80, 24);
        let rows: Vec<&str> = text
            .lines()
            .filter(|l| {
                l.contains("10.0.0.3") || l.contains("10.0.0.2") || l.contains("web.example")
            })
            .collect();
        assert!(rows[0].contains("backup"), "{rows:?}");
        assert!(
            rows[0].contains("* backup"),
            "the favorite marker is a character: {rows:?}"
        );
        assert!(!rows[1].contains('*'), "{rows:?}");
        assert!(
            rows[1].contains("db") && rows[2].contains("web"),
            "then by name: {rows:?}"
        );
    }

    #[test]
    fn the_selected_row_has_a_marker_and_reverse_video() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('j'));
        let (terminal, _) = draw_with(&mut app, &Theme::plain(), 80, 24);
        let text = screen_text(&terminal);
        assert!(line_of(&text, "db").contains("> "), "{text}");
        assert!(!line_of(&text, "backup").contains("> "), "{text}");

        // Reverse video covers the whole selected row and only that row.
        let buffer = terminal.backend().buffer();
        let row_of = |needle: &str| {
            (0..buffer.area.height)
                .find(|&y| {
                    let line: String = (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect();
                    line.contains(needle)
                })
                .unwrap()
        };
        let reversed = |y: u16, x: u16| buffer[(x, y)].modifier.contains(Modifier::REVERSED);
        let db_row = row_of("10.0.0.2");
        assert!((2..78).all(|x| reversed(db_row, x)));
        assert!(!reversed(row_of("10.0.0.3"), 10));
    }

    #[test]
    fn the_target_column_is_cut_with_dots_when_the_window_is_narrow() {
        let mut long = host(
            "production-database",
            "very-long-hostname.internal.example.com",
        );
        long.user = Some("administrator".to_string());
        let mut app = app_with(vec![long], Vec::new());
        let text = text_of(&mut app, 60, 15);
        assert!(text.contains("..."), "{text}");
        for line in text.lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
    }

    #[test]
    fn tags_are_dropped_before_the_target_gets_unreadable() {
        let mut app = app_with(
            vec![tagged(
                "web",
                "web.example.com",
                &["production", "europe-west"],
            )],
            Vec::new(),
        );
        let narrow = text_of(&mut app, 60, 15);
        assert!(narrow.contains("web.example.com"), "{narrow}");
        let wide = text_of(&mut app, 100, 15);
        assert!(wide.contains("#production #europe-west"), "{wide}");
    }

    // ---- empty and no match ----------------------------------------------

    #[test]
    fn an_empty_store_explains_how_to_add_the_first_host() {
        let mut app = app_with(Vec::new(), Vec::new());
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("Saved hosts: 0"), "{text}");
        assert!(text.contains("You have no saved hosts yet."), "{text}");
        assert!(text.contains("Press a to add your first host"), "{text}");
        assert!(text.contains("hostname or IP address"), "{text}");
        assert!(
            !text.contains("Name"),
            "no column header without hosts: {text}"
        );
    }

    #[test]
    fn a_search_without_results_says_so_clearly() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "zzz");
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("No hosts match \"zzz\"."), "{text}");
        assert!(text.contains("press Esc to clear the search"), "{text}");
        assert!(text.contains("0 of 3 hosts"), "{text}");
        assert!(!text.contains("web.example.com"), "{text}");
    }

    // ---- searching -------------------------------------------------------

    #[test]
    fn the_search_box_shows_the_query_and_places_the_cursor_after_it() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "we");
        let mut terminal = draw(&mut app, 80, 24);
        let text = screen_text(&terminal);
        assert!(text.contains("Search: we"), "{text}");
        assert!(text.contains("1 of 3 hosts"), "{text}");
        let cursor = terminal.get_cursor_position().unwrap();
        // Border, padding, then "Search: we".
        assert_eq!((cursor.x, cursor.y), (2 + 8 + 2, 1));
    }

    #[test]
    fn the_cursor_is_hidden_when_not_searching() {
        let mut app = app_with(sample(), Vec::new());
        let mut terminal = draw(&mut app, 80, 24);
        // ratatui hides the cursor when no position was requested.
        let before = terminal.get_cursor_position().unwrap();
        assert_eq!((before.x, before.y), (0, 0));
    }

    #[test]
    fn a_kept_filter_shows_as_a_filter_with_its_count() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "prod");
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("Filter: prod"), "{text}");
        assert!(text.contains("2 of 3 hosts"), "{text}");
        assert!(text.contains("Esc clear search"), "{text}");
        assert!(!text.contains("backup"), "{text}");
    }

    /// The characters of the row containing `needle` that have `modifier`.
    fn styled_chars(
        terminal: &ratatui::Terminal<ratatui::backend::TestBackend>,
        needle: &str,
        modifier: Modifier,
    ) -> String {
        let buffer = terminal.backend().buffer();
        for y in 0..buffer.area.height {
            let line: String = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect();
            if line.contains(needle) {
                return (0..buffer.area.width)
                    .filter(|&x| buffer[(x, y)].modifier.contains(modifier))
                    .map(|x| buffer[(x, y)].symbol())
                    .collect();
            }
        }
        panic!("no row with {needle:?}");
    }

    #[test]
    fn matched_characters_are_highlighted_with_bold_and_underline() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "wb");
        let terminal = draw(&mut app, 80, 24);

        let underlined = styled_chars(&terminal, "web.example.com", Modifier::UNDERLINED);
        // "web" matches in the name and again in the hostname: both are marked,
        // and nothing else in the row is.
        assert_eq!(
            underlined, "wbwb",
            "only the matched letters are underlined"
        );
        let bold = styled_chars(&terminal, "web.example.com", Modifier::BOLD);
        assert!(bold.contains('w') && bold.contains('b'), "{bold:?}");
    }

    #[test]
    fn highlighting_needs_no_color_and_survives_no_color() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "wb");
        let (terminal, _) = draw_with(&mut app, &Theme::plain(), 80, 24);
        assert_eq!(
            styled_chars(&terminal, "web.example.com", Modifier::UNDERLINED),
            "wbwb"
        );
        let (terminal, _) = draw_with(&mut app, &Theme::ansi16(), 80, 24);
        let buffer = terminal.backend().buffer();
        assert!(
            buffer
                .content()
                .iter()
                .filter(|cell| cell.modifier.contains(Modifier::UNDERLINED))
                .all(|cell| cell.fg == ratatui::style::Color::Reset),
            "the highlight itself adds no color"
        );
    }

    #[test]
    fn matches_are_highlighted_in_the_hostname_and_in_tags_too() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "eu");
        let terminal = draw(&mut app, 100, 24);
        // "eu" is in the tag "#eu" of web, and in nothing else's tags.
        assert_eq!(
            styled_chars(&terminal, "#prod #eu", Modifier::UNDERLINED),
            "eu"
        );

        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "exam");
        let terminal = draw(&mut app, 100, 24);
        assert_eq!(
            styled_chars(&terminal, "web.example.com", Modifier::UNDERLINED),
            "exam"
        );
    }

    #[test]
    fn results_are_shown_best_match_first() {
        let hosts = vec![
            host("aaa-mydb", "10.0.0.1"),
            host("db-main", "10.0.0.2"),
            host("prod-db", "10.0.0.3"),
        ];
        let mut app = app_with(hosts, Vec::new());
        app.handle_key(key('/'));
        type_text(&mut app, "db");
        let text = text_of(&mut app, 80, 24);
        let order: Vec<&str> = ["db-main", "prod-db", "aaa-mydb"].to_vec();
        let positions: Vec<usize> = order.iter().map(|n| text.find(n).unwrap()).collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{text}");
    }

    // ---- long lists ------------------------------------------------------

    fn many(count: usize) -> Vec<Host> {
        (0..count)
            .map(|n| host(&format!("host-{n:02}"), &format!("10.0.0.{n}")))
            .collect()
    }

    #[test]
    fn a_long_list_shows_a_position_indicator_and_scrolls_with_the_selection() {
        let mut app = app_with(many(40), Vec::new());
        let (terminal, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        let text = screen_text(&terminal);
        assert!(metrics.list_rows > 0 && metrics.list_rows < 40);
        assert!(text.contains("host-00"), "{text}");
        assert!(!text.contains("host-39"), "{text}");
        assert!(
            text.contains(&format!("hosts 1-{} of 40", metrics.list_rows)),
            "{text}"
        );

        for _ in 0..39 {
            app.handle_key(key('j'));
            draw_with(&mut app, &Theme::ansi16(), 60, 15);
        }
        let text = text_of(&mut app, 60, 15);
        assert!(
            text.contains("host-39"),
            "the last host is reachable:\n{text}"
        );
        assert!(text.contains("-40 of 40"), "{text}");
        assert!(
            line_of(&text, "host-39").contains("> "),
            "and selected:\n{text}"
        );
        assert!(!text.contains("host-00"), "{text}");
    }

    #[test]
    fn the_selection_stays_visible_while_moving_up_and_down() {
        let mut app = app_with(many(40), Vec::new());
        for step in 0..60 {
            let key_code = if step < 30 { 'j' } else { 'k' };
            app.handle_key(key(key_code));
            let text = text_of(&mut app, 60, 15);
            let selected = app.list().selected.clone().unwrap();
            assert!(
                line_of(&text, &selected).contains("> "),
                "step {step}: {selected} should be visible and marked:\n{text}"
            );
        }
    }

    #[test]
    fn page_keys_and_end_work_against_the_real_row_count() {
        let mut app = app_with(many(40), Vec::new());
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 60, 15);
        app.handle_key(press(KeyCode::PageDown));
        assert_eq!(
            app.list().selected.as_deref(),
            Some(format!("host-{:02}", metrics.list_rows).as_str())
        );
        app.handle_key(press(KeyCode::End));
        let text = text_of(&mut app, 60, 15);
        assert!(line_of(&text, "host-39").contains("> "), "{text}");
    }

    #[test]
    fn a_short_list_has_no_position_indicator() {
        let mut app = app_with(sample(), Vec::new());
        assert!(!text_of(&mut app, 80, 24).contains("hosts 1-"));
    }

    // ---- warnings, status and load problems ------------------------------

    #[test]
    fn warnings_stay_visible_as_a_summary_with_the_key_to_read_them() {
        let notices = vec![Notice::warning("one"), Notice::warning("two")];
        let mut app = app_with(sample(), notices);
        let text = text_of(&mut app, 80, 24);
        assert!(
            text.contains("Warning: 2 problems found. Press w to read them."),
            "{text}"
        );
        // One line, even on the smallest terminal: the list keeps its room.
        let mut narrow = app_with(
            sample(),
            vec![Notice::warning("one"), Notice::warning("two")],
        );
        let narrow_text = text_of(&mut narrow, 60, 15);
        assert!(
            narrow_text.contains("Warning: 2 problems found. Press w to read them."),
            "{narrow_text}"
        );
        assert!(
            text.contains("web.example.com"),
            "the list is still there: {text}"
        );

        let mut single = app_with(sample(), vec![Notice::warning("one")]);
        assert!(
            text_of(&mut single, 80, 24).contains("Warning: 1 problem found. Press w to read it.")
        );
    }

    #[test]
    fn a_status_message_shows_above_the_footer_with_a_label_for_errors() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('f'));
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("'backup' is no longer a favorite."), "{text}");

        // A failed save is labeled as an error, in words.
        let store = crate::tui::persist::testing::FakeStore::default();
        store.fail_saves(true);
        let hosts = crate::domain::Hosts::from_vec(sample()).unwrap();
        let mut failing = App::new(crate::tui::startup::Startup::loaded(
            hosts,
            store,
            Vec::new(),
        ));
        failing.handle_key(key('f'));
        let text = text_of(&mut failing, 80, 24);
        assert!(
            text.contains("Error: Could not save your changes"),
            "{text}"
        );
        assert!(
            text.contains("disk is"),
            "wrapping may split the message: {text}"
        );
        assert!(text.contains("* backup"), "the list is unchanged: {text}");
    }

    #[test]
    fn host_text_is_sanitized_before_it_reaches_a_cell() {
        // Validation refuses these characters, so a loaded host never has them;
        // the screen must still defend itself, because a `Host` is a plain struct.
        let mut odd = host("we\x1bb", "10.0.\u{202e}0.1");
        odd.user = Some("de\x07p".to_string());
        odd.tags = vec!["a\u{85}b".to_string()];
        let mut cleaner = Cleaner::default();

        let cells = cells_for(&odd, None, &mut cleaner);

        assert_eq!(cells.name, "we?b");
        assert_eq!(cells.target, "de?p@10.0.?0.1");
        assert_eq!(cells.tags, "#a?b");
        assert!(cleaner.hidden, "and the footer will say so");
        for text in [&cells.name, &cells.target, &cells.tags] {
            assert!(
                !text.chars().any(crate::sanitize::is_unsafe_char),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_clean_host_does_not_trigger_the_hidden_characters_note() {
        let mut cleaner = Cleaner::default();
        cells_for(&host("web", "10.0.0.1"), None, &mut cleaner);
        assert!(!cleaner.hidden);
    }

    #[test]
    fn highlight_positions_stay_valid_after_sanitizing() {
        // Sanitizing replaces one character with one, so positions computed on
        // the original text still point at the same characters.
        let odd = host("we\x1bb", "10.0.0.1");
        let matched = crate::tui::list::match_host("b", &odd).unwrap();
        let mut cleaner = Cleaner::default();
        let cells = cells_for(&odd, Some(&matched), &mut cleaner);
        let shown: Vec<char> = cells.name.chars().collect();
        assert!(cells.name_hits.iter().all(|&p| p < shown.len()));
        assert_eq!(cells.name_hits, [3]);
    }

    #[test]
    fn a_search_query_is_sanitized_too() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('/'));
        // Typing cannot produce a control character; a bidi override can be
        // pasted or typed by an input method.
        for c in "a\u{202e}b".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let terminal = draw(&mut app, 80, 24);
        let text = screen_text(&terminal);
        assert!(text.contains("Search: a?b"), "{text}");
        assert!(
            text.contains("non-printable characters were hidden"),
            "{text}"
        );
    }

    #[test]
    fn the_hosts_table_stays_within_the_window() {
        let mut long = host(&"n".repeat(64), &"h".repeat(60));
        long.user = Some("u".repeat(60));
        long.tags = vec!["t".repeat(30); 5];
        let mut app = app_with(vec![long], Vec::new());
        for (width, height) in [(60, 15), (80, 24), (120, 30)] {
            let text = text_of(&mut app, width, height);
            for line in text.lines() {
                assert!(
                    line.chars().count() <= usize::from(width),
                    "{width}x{height}: {line:?}"
                );
            }
        }
    }

    // ---- deleting and copying --------------------------------------------

    fn with_dependents() -> Vec<Host> {
        let mut a = host("a", "10.0.1.1");
        a.proxy_jump = Some("bastion".to_string());
        vec![host("bastion", "10.0.0.9"), a]
    }

    #[test]
    fn the_delete_confirmation_names_the_host_and_asks_for_it_to_be_typed() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('j'));
        app.handle_key(key('d'));
        let text = text_of(&mut app, 80, 24);

        assert!(text.contains("Delete host"), "{text}");
        assert!(text.contains("Delete host 'db'?"), "{text}");
        let flat = text
            .split_whitespace()
            .filter(|word| *word != "│")
            .collect::<Vec<_>>()
            .join(" ");
        assert!(flat.contains("It cannot be undone."), "{text}");
        assert!(text.contains("Type the host name to confirm:"), "{text}");
        assert!(text.contains("> "), "{text}");
        assert!(
            !text.contains("Error:"),
            "no error before anything was typed: {text}"
        );
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("Enter delete"), "{footer}");
        assert!(footer.contains("Esc cancel"), "{footer}");
        assert!(
            text.contains("web.example.com"),
            "the list is still behind it: {text}"
        );
    }

    #[test]
    fn what_is_typed_shows_in_the_confirmation_with_the_cursor_after_it() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('d'));
        type_text(&mut app, "bac");
        let mut terminal = draw(&mut app, 80, 24);
        let text = screen_text(&terminal);
        let input_row = text.lines().position(|l| l.contains("> bac")).expect(&text);
        let cursor = terminal.get_cursor_position().unwrap();
        assert_eq!(usize::from(cursor.y), input_row, "{text}");
        let line = text.lines().nth(input_row).unwrap();
        let start = line.find("> bac").unwrap();
        // Width of the text before "> " counted in characters, plus "> bac".
        let column = line[..start].chars().count() + "> bac".chars().count();
        assert_eq!(usize::from(cursor.x), column, "{text}");
    }

    #[test]
    fn a_wrong_name_shows_an_error_in_words() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('d'));
        type_text(&mut app, "nope");
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 80, 24);
        assert!(
            text.contains("Error: That is not the host's name."),
            "{text}"
        );
        assert!(text.contains("press Esc to cancel"), "{text}");
    }

    #[test]
    fn the_confirmation_fits_the_smallest_terminal() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('d'));
        type_text(&mut app, "wrong");
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 60, 15);
        assert!(text.contains("Type the host name to confirm:"), "{text}");
        assert!(text.contains("Error:"), "{text}");
        for line in text.lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
    }

    #[test]
    fn the_refusal_to_delete_a_jump_host_is_shown_with_its_dependents() {
        let mut app = app_with(with_dependents(), Vec::new());
        // Alphabetical: a, bastion. Select the jump host.
        app.handle_key(key('j'));
        app.handle_key(key('d'));
        let text = text_of(&mut app, 80, 24);
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            text.contains("Error: Host 'bastion' is the jump host of 'a'."),
            "{text}"
        );
        assert!(
            flat.contains("Change or remove the jump host on those hosts first."),
            "{text}"
        );
        assert!(
            !text.contains("Type the host name"),
            "no confirmation: {text}"
        );
    }

    #[test]
    fn deleting_shows_the_confirmation_of_what_happened() {
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('d'));
        type_text(&mut app, "backup");
        app.handle_key(press(KeyCode::Enter));
        let text = text_of(&mut app, 80, 24);
        assert!(text.contains("Deleted host 'backup'."), "{text}");
        assert!(text.contains("Saved hosts: 2"), "{text}");
        assert!(!text.contains("10.0.0.3"), "{text}");
    }

    fn command_app() -> App {
        let mut web = host("web", "web.example.com");
        web.user = Some("deploy".to_string());
        web.port = Some(2222);
        app_with(vec![web], Vec::new())
    }

    #[test]
    fn the_command_is_shown_on_screen_with_an_honest_message_about_copying() {
        let mut app = command_app();
        app.handle_key(key('c'));
        let text = text_of(&mut app, 100, 24);

        assert!(text.contains("ssh command for 'web'"), "{text}");
        assert!(
            text.contains("ssh -l deploy -p 2222 -- web.example.com"),
            "{text}"
        );
        assert!(text.contains("Copy requested"), "{text}");
        assert!(text.contains("if nothing was copied"), "{text}");
        assert!(
            !text.to_lowercase().contains("copied to"),
            "never claims success: {text}"
        );
        assert!(!text.contains("Copied"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(footer.contains("Any key close"), "{footer}");
    }

    #[test]
    fn the_command_has_no_side_borders_so_selecting_it_copies_only_the_command() {
        let mut app = command_app();
        app.handle_key(key('c'));
        let text = text_of(&mut app, 100, 24);
        let line = text
            .lines()
            .find(|l| l.contains("ssh -l deploy"))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(
            line.starts_with("ssh -l deploy"),
            "flush left, no border: {line:?}"
        );
        assert!(!line.contains('│'), "{line:?}");
    }

    #[test]
    fn a_long_command_wraps_at_spaces_and_says_to_join_the_lines() {
        let mut long = host("prod-database-server-01", "prod-db-01.internal.example.com");
        long.user = Some("administrator".to_string());
        long.port = Some(2222);
        long.identity_file = Some("/home/someone/.ssh/keys/production/id_ed25519".to_string());
        let mut app = app_with(vec![long], Vec::new());
        app.handle_key(key('c'));
        let text = text_of(&mut app, 60, 20);

        assert!(text.contains("join the lines with spaces"), "{text}");
        // Every word of the command is on screen, in order.
        let command = app.command().unwrap().text.clone();
        let squeezed = text
            .lines()
            .take_while(|l| !l.trim().is_empty() || !l.contains("ssh"))
            .collect::<Vec<_>>()
            .join(" ");
        let squeezed = squeezed.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            squeezed.contains(&command),
            "{command:?} not found in:\n{text}"
        );
        for line in text.lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
    }

    #[test]
    fn a_short_command_gets_no_join_hint() {
        let mut app = command_app();
        app.handle_key(key('c'));
        assert!(!text_of(&mut app, 100, 24).contains("join the lines"));
    }

    #[test]
    fn the_command_panel_fits_the_smallest_terminal() {
        let mut app = command_app();
        app.handle_key(key('c'));
        let text = text_of(&mut app, 60, 15);
        assert!(
            text.contains("ssh -l deploy -p 2222 -- web.example.com"),
            "{text}"
        );
        assert!(text.contains("Copy requested"), "{text}");
    }

    #[test]
    fn closing_the_command_brings_the_list_back() {
        let mut app = command_app();
        app.handle_key(key('c'));
        app.handle_key(key('x'));
        let text = text_of(&mut app, 100, 24);
        assert!(!text.contains("ssh command for"), "{text}");
        assert!(text.contains("Saved hosts: 1"), "{text}");
    }

    #[test]
    fn no_color_draws_the_popup_and_the_panel_without_color() {
        use ratatui::style::Color;
        let plain = Theme::plain();
        let mut app = app_with(sample(), Vec::new());
        app.handle_key(key('d'));
        type_text(&mut app, "x");
        app.handle_key(press(KeyCode::Enter));
        for step in 0..2 {
            let (terminal, _) = draw_with(&mut app, &plain, 80, 24);
            assert!(
                terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .all(|c| c.fg == Color::Reset && c.bg == Color::Reset),
                "step {step}"
            );
            app.handle_key(press(KeyCode::Esc));
            app.handle_key(key('c'));
        }
    }
}
