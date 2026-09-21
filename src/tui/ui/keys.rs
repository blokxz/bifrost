//! The keys screen: the key pairs in the ssh directory, whether the agent holds
//! them, whether their permissions are ones ssh accepts, and what is known about
//! the selected one.
//!
//! Everything that came from outside (file names, key comments, paths, what
//! ssh-add or ssh-keygen said) goes through [`Cleaner`] on the way in.

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
use crate::ssh::agent::AgentState;
use crate::ssh::keys::{KeyEntry, KeysSnapshot, Permissions, mode_label};
use crate::tui::app::{App, Metrics};
use crate::tui::keys::{
    CopyDialog, DeleteQuestion, GenerateField, GenerateForm, KeysScreen, UseKeyQuestion,
};
use crate::tui::list::window_start;
use crate::tui::theme::Theme;
use crate::tui::wrap::{display_width, pad, truncate, wrap};

const COLUMN_GAP: &str = "  ";
const TYPE_WIDTH: usize = 11;
const AGENT_WIDTH: usize = 10;
const PERMS_WIDTH: usize = 13;
/// The columns before the name (selection marker) and every fixed column.
const FIXED_WIDTH: usize = 2 + TYPE_WIDTH + AGENT_WIDTH + PERMS_WIDTH + 3 * COLUMN_GAP.len();
const MAX_NAME_WIDTH: usize = 28;
/// The label column of the detail panel.
const LABEL_WIDTH: usize = 12;
/// The most rows the detail panel takes, and the fewest the list keeps.
const MAX_DETAIL_LINES: usize = 10;
const MIN_LIST_ROWS: usize = 3;

/// What is said about the agent, and how much of it.
fn agent_lines(
    agent: &AgentState,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let (style, headline, explanation): (Style, String, Option<String>) = match agent {
        AgentState::Running { hashes } => (
            theme.title,
            match hashes.len() {
                0 => "running, holding no keys.".to_string(),
                1 => "running, holding 1 key.".to_string(),
                n => format!("running, holding {n} keys."),
            },
            None,
        ),
        AgentState::NotStarted => (
            theme.title,
            "not running.".to_string(),
            Some(
                "This terminal has no ssh-agent, so keys cannot be kept loaded here and every \
                 connection asks for a key's passphrase. That is normal. To start one, run: \
                 eval \"$(ssh-agent -s)\" (on Windows, start the ssh-agent service)."
                    .to_string(),
            ),
        ),
        AgentState::Unreachable => (
            theme.title,
            "not running.".to_string(),
            Some(
                "SSH_AUTH_SOCK points to an agent that is not answering: it has probably ended. \
                 Start a new one to keep keys loaded."
                    .to_string(),
            ),
        ),
        AgentState::Unavailable(why) => (
            theme.warning,
            "could not be checked.".to_string(),
            Some(why.clone()),
        ),
        AgentState::Unknown(said) => (
            theme.warning,
            "could not be told.".to_string(),
            Some(format!("ssh-add said: {said}")),
        ),
    };
    let mut lines = labeled_lines("Agent:", style, &headline, width, cleaner);
    if let Some(text) = explanation {
        for piece in wrap(&cleaner.clean(&text), width.saturating_sub(2).max(1)) {
            lines.push(Line::styled(format!("  {piece}"), theme.muted));
        }
    }
    lines
}

/// The width of the labels in the generate form.
const FIELD_LABEL: usize = 10;

/// Said before ssh-keygen takes the terminal, because Bifrost neither asks for
/// the passphrase nor can tell afterwards whether one was set.
const PASSPHRASE_NOTE: &str = "Next, ssh-keygen asks for a passphrase. You type it into \
    ssh-keygen itself: Bifrost never sees it. Without one, anyone who copies the key file can \
    use the key.";

/// The generate form's lines, and where the cursor goes: (column, row) inside
/// the popup.
fn generate_lines(
    form: &GenerateForm,
    theme: &Theme,
    area_width: u16,
    cleaner: &mut Cleaner,
) -> (Vec<Line<'static>>, (usize, usize)) {
    // A popup is at most 60 wide, less its border and padding.
    let width = usize::from(area_width.saturating_sub(2))
        .min(60)
        .saturating_sub(4)
        .max(1);
    let value_width = width.saturating_sub(2 + FIELD_LABEL).max(1);
    let indent = " ".repeat(2 + FIELD_LABEL);

    let mut lines = vec![Line::raw("Make a new ed25519 key."), Line::raw("")];
    let mut cursor = (0, 0);
    let fields = [
        (GenerateField::Name, "File name", form.name()),
        (GenerateField::Comment, "Comment", form.comment()),
    ];
    for (field, label, input) in fields {
        let focused = form.focus() == field;
        let typed = cleaner.clean(input.value()).into_owned();
        let (visible, column) = input_window(&typed, input.cursor(), value_width);
        if focused {
            cursor = (2 + FIELD_LABEL + column, lines.len());
        }
        lines.push(Line::from(vec![
            Span::raw(if focused { "> " } else { "  " }),
            Span::styled(
                format!("{label:<FIELD_LABEL$}"),
                if focused { theme.key } else { Style::new() },
            ),
            Span::raw(visible),
        ]));
        if let Some((_, message)) = form.error().filter(|(with_error, _)| *with_error == field) {
            for line in labeled_lines("Error:", theme.error, message, value_width, cleaner) {
                let mut spans = vec![Span::raw(indent.clone())];
                spans.extend(line.spans);
                lines.push(Line::from(spans));
            }
        }
    }
    let help = match form.focus() {
        GenerateField::Name => "Letters, digits, '.', '_' and '-'.",
        GenerateField::Comment => "Optional: a label kept in the key. Empty means user@computer.",
    };
    lines.push(Line::styled(format!("{indent}{help}"), theme.muted));
    lines.push(Line::raw(""));
    lines.extend(labeled_lines(
        "",
        Style::new(),
        PASSPHRASE_NOTE,
        width,
        cleaner,
    ));
    (lines, cursor)
}

/// The most saved hosts that are named one by one in the question about deleting.
const MAX_HOSTS_NAMED: usize = 8;

/// The question before deleting a key, and where the cursor goes in it.
///
/// What it must say is fixed: which saved hosts use the key, that Bifrost cannot
/// know which servers have it, and that the name has to be typed. On a small
/// terminal the popup cannot hold everything, so what is only helpful goes first,
/// in this order: the spacing, the note about the agent, the note that no host uses
/// the key, the note about a link, and the paths.
fn delete_lines(
    question: &DeleteQuestion,
    theme: &Theme,
    area: Rect,
    cleaner: &mut Cleaner,
) -> (Vec<Line<'static>>, (usize, usize)) {
    // A popup is at most this wide, less its border and padding.
    let width = usize::from(area.width.saturating_sub(2))
        .min(64)
        .saturating_sub(4)
        .max(1);
    let paragraph =
        |text: &str, cleaner: &mut Cleaner| labeled_lines("", Style::new(), text, width, cleaner);

    let heading = paragraph(&format!("Delete the key '{}'?", question.key), cleaner);
    // The hosts that use the key, `shown` of them by name.
    let used_for = |shown: usize, cleaner: &mut Cleaner| {
        if question.used_by.is_empty() {
            return Vec::new();
        }
        let shown = shown.min(question.used_by.len());
        let mut names = question.used_by[..shown].join(", ");
        if question.used_by.len() > shown {
            names.push_str(&format!(" and {} more", question.used_by.len() - shown));
        }
        labeled_lines(
            "Used by:",
            theme.warning,
            &format!("{names}. Their key file is this key, and would be gone."),
            width,
            cleaner,
        )
    };
    let mut shown = MAX_HOSTS_NAMED;
    let mut used = used_for(shown, cleaner);
    let nobody = if question.used_by.is_empty() {
        paragraph("No saved host has this key as its key file.", cleaner)
    } else {
        Vec::new()
    };
    let warning = labeled_lines(
        "Warning:",
        theme.warning,
        "Bifrost cannot know which servers have this key in their authorized_keys. Deleting it \
         means losing access to those servers until another key is installed.",
        width,
        cleaner,
    );
    let removes = paragraph(
        &format!("This removes {} and {}.", question.private, question.public),
        cleaner,
    );
    let link = if question.symlink {
        paragraph(
            "It is a symbolic link: only the link is removed, and the file it points to stays.",
            cleaner,
        )
    } else {
        Vec::new()
    };
    let agent = if question.loaded {
        paragraph(
            "The agent holds this key and keeps holding it until it is restarted or you run \
             ssh-add -d.",
            cleaner,
        )
    } else {
        Vec::new()
    };
    let prompt = Line::raw("Type the key's name to confirm:");
    let typed = cleaner.clean(question.input.value()).into_owned();
    let (visible, column) = input_window(&typed, question.input.cursor(), width.saturating_sub(2));
    let input = Line::from(vec![Span::styled("> ", theme.key), Span::raw(visible)]);
    let mismatch = if question.mismatch {
        labeled_lines(
            "Error:",
            theme.error,
            "That is not the key's name. Type it exactly, or press Esc to cancel.",
            width,
            cleaner,
        )
    } else {
        Vec::new()
    };

    // What is left out, in the order it goes.
    let (mut spaces, mut keep_agent, mut keep_nobody, mut keep_link, mut keep_removes) =
        (2, true, true, true, true);
    let budget = usize::from(area.height).saturating_sub(4);
    loop {
        let height = heading.len()
            + used.len()
            + warning.len()
            + 2
            + mismatch.len()
            + spaces
            + if keep_agent { agent.len() } else { 0 }
            + if keep_nobody { nobody.len() } else { 0 }
            + if keep_link { link.len() } else { 0 }
            + if keep_removes { removes.len() } else { 0 };
        if height <= budget {
            break;
        }
        if spaces > 0 {
            spaces -= 1;
        } else if keep_agent {
            keep_agent = false;
        } else if keep_nobody {
            keep_nobody = false;
        } else if keep_link {
            keep_link = false;
        } else if keep_removes {
            keep_removes = false;
        } else if shown > 1 {
            // Everything that can go has gone: the list of hosts gives way, since
            // the line to type the name on may not.
            shown -= 1;
            used = used_for(shown, cleaner);
        } else {
            break;
        }
    }

    let mut lines = heading;
    if spaces > 0 {
        lines.push(Line::raw(""));
    }
    lines.extend(used);
    if keep_nobody {
        lines.extend(nobody);
    }
    lines.extend(warning);
    if keep_removes {
        lines.extend(removes);
    }
    if keep_link {
        lines.extend(link);
    }
    if keep_agent {
        lines.extend(agent);
    }
    if spaces > 1 {
        lines.push(Line::raw(""));
    }
    lines.push(prompt);
    let cursor = (2 + column, lines.len());
    lines.push(input);
    lines.extend(mismatch);
    (lines, cursor)
}

/// The question asked once a key was sent: use it for that host from now on?
///
/// It says what would change, and, when the host has a key file already, that it
/// is replaced. On a small terminal the spaces go first and then the explanation
/// from its end, and never that replacement or how to answer.
fn use_key_lines(
    question: &UseKeyQuestion,
    area: Rect,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    // A popup is at most this wide, less its border and padding.
    let width = usize::from(area.width.saturating_sub(2))
        .min(64)
        .saturating_sub(4)
        .max(1);
    let host = &question.host;
    let heading = labeled_lines(
        "",
        Style::new(),
        &format!("Use this key for '{host}' from now on?"),
        width,
        cleaner,
    );
    let mut explanation = labeled_lines(
        "",
        Style::new(),
        &format!(
            "'{}' was just sent to '{host}'. To use it, Bifrost sets the host's identity file to \
             {}, so ssh offers only that key when you connect to it.",
            question.key, question.value
        ),
        width,
        cleaner,
    );
    let replaces = question
        .replaces
        .as_deref()
        .map(|old| {
            labeled_lines(
                "",
                Style::new(),
                &format!("This replaces {old}, which the host uses now."),
                width,
                cleaner,
            )
        })
        .unwrap_or_default();
    let answer = Line::raw("Press y to use it, or n to leave the host as it is.");

    let budget = usize::from(area.height).saturating_sub(4);
    let mut spaces = 2;
    let total = |spaces: usize, explanation: &[Line<'static>]| {
        heading.len() + explanation.len() + replaces.len() + 1 + spaces
    };
    while total(spaces, &explanation) > budget && spaces > 0 {
        spaces -= 1;
    }
    while total(spaces, &explanation) > budget && !explanation.is_empty() {
        explanation.pop();
    }

    let mut lines = heading;
    if spaces > 0 {
        lines.push(Line::raw(""));
    }
    lines.extend(explanation);
    lines.extend(replaces);
    if spaces > 1 {
        lines.push(Line::raw(""));
    }
    lines.push(answer);
    lines
}

/// The width of the labels in the confirmation of sending a key.
const CONFIRM_LABEL: usize = 6;

/// The most host rows the dialog shows at once.
const MAX_HOST_ROWS: usize = 12;

/// Adds a `Label  value` line to `lines`, the value wrapped under itself.
fn push_fact(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: &str,
    width: usize,
    theme: &Theme,
    cleaner: &mut Cleaner,
) {
    let room = width.saturating_sub(CONFIRM_LABEL).max(1);
    for (index, piece) in wrap(&cleaner.clean(value), room).into_iter().enumerate() {
        lines.push(if index == 0 {
            Line::from(vec![
                Span::styled(pad(label, CONFIRM_LABEL), theme.muted),
                Span::raw(piece),
            ])
        } else {
            Line::raw(format!("{:CONFIRM_LABEL$}{piece}", ""))
        });
    }
}

/// What the send-a-key dialog draws, and how many host rows it had room for
/// (0 when it is showing the question).
fn copy_lines(
    dialog: &CopyDialog,
    screen: &KeysScreen,
    theme: &Theme,
    area: Rect,
    cleaner: &mut Cleaner,
) -> (Vec<Line<'static>>, usize) {
    // A popup is at most this wide, less its border and padding.
    let width = usize::from(area.width.saturating_sub(2))
        .min(64)
        .saturating_sub(4)
        .max(1);

    if dialog.confirming() {
        let Some(choice) = dialog.selected_choice() else {
            return (Vec::new(), 0);
        };
        let question = labeled_lines(
            "",
            Style::new(),
            &format!(
                "Send the public key of '{}' to '{}'?",
                dialog.key(),
                choice.name
            ),
            width,
            cleaner,
        );

        // What the key is: its type and comment, then the fingerprint on a line
        // of its own, which is as wide as the popup's narrowest content.
        let key = screen
            .snapshot()
            .keys
            .iter()
            .find(|entry| entry.name == dialog.key());
        let (described, fingerprint) = match key.map(|entry| &entry.fingerprint) {
            Some(Ok(found)) => {
                let mut text = found.key_type.to_lowercase();
                if let Some(comment) = &found.comment {
                    text.push_str(&format!(" ({comment})"));
                }
                (text, Some(found.hash.clone()))
            }
            _ => (dialog.key().to_string(), None),
        };
        let mut facts: Vec<Line<'static>> = Vec::new();
        push_fact(&mut facts, "Key", &described, width, theme, cleaner);
        if let Some(hash) = &fingerprint {
            for piece in wrap(&cleaner.clean(hash), width.saturating_sub(2).max(1)) {
                facts.push(Line::raw(format!("  {piece}")));
            }
        }
        push_fact(
            &mut facts,
            "Host",
            &choice.destination,
            width,
            theme,
            cleaner,
        );

        let mut explanation = labeled_lines(
            "",
            Style::new(),
            "It is added to ~/.ssh/authorized_keys there, so whoever has the matching private \
             key can log in. ssh may ask for a password first.",
            width,
            cleaner,
        );

        // On a small terminal the popup cannot hold everything, and what is cut
        // is cut from the bottom. So fit it instead, keeping what matters: the
        // question, the key and host, and the line that says how to answer. The
        // spaces go first, then the explanation from its end.
        let budget = usize::from(area.height).saturating_sub(4);
        let mut spaces = 2;
        let total = |spaces: usize, explanation: &[Line<'static>]| {
            question.len() + facts.len() + explanation.len() + 1 + spaces
        };
        while total(spaces, &explanation) > budget && spaces > 0 {
            spaces -= 1;
        }
        while total(spaces, &explanation) > budget && !explanation.is_empty() {
            explanation.pop();
        }

        let mut lines = question;
        if spaces > 0 {
            lines.push(Line::raw(""));
        }
        lines.extend(facts);
        if spaces > 1 {
            lines.push(Line::raw(""));
        }
        lines.extend(explanation);
        lines.push(Line::raw("Press y to send it, or n to go back."));
        return (lines, 0);
    }

    let mut lines = labeled_lines(
        "",
        Style::new(),
        &format!("Send the public key of '{}' to which host?", dialog.key()),
        width,
        cleaner,
    );
    lines.push(Line::raw(""));
    let total = dialog.choices().len();
    // The popup keeps a border and padding, and this has a header and, when the
    // hosts do not all fit, a line saying where in them the window is.
    let room = usize::from(area.height).saturating_sub(4 + lines.len() + 1);
    let rows = total.min(room.clamp(1, MAX_HOST_ROWS));
    let start = window_start(dialog.offset(), Some(dialog.selected()), rows, total);
    let end = (start + rows).min(total);

    let names: Vec<String> = dialog.choices()[start..end]
        .iter()
        .map(|choice| cleaner.clean(&choice.name).into_owned())
        .collect();
    let name_width = names
        .iter()
        .map(|name| display_width(name))
        .max()
        .unwrap_or(0);
    let name_width = name_width.clamp(4, 20).min(width.saturating_sub(4).max(1));
    for (offset, choice) in dialog.choices()[start..end].iter().enumerate() {
        let selected = start + offset == dialog.selected();
        let name = truncate(&names[offset], name_width).0;
        let used = 2 + name_width + 2;
        let destination = truncate(
            &cleaner.clean(&choice.destination),
            width.saturating_sub(used),
        )
        .0;
        let text = pad(
            &format!(
                "{}{}  {destination}",
                if selected { "> " } else { "  " },
                pad(&name, name_width)
            ),
            width,
        );
        lines.push(if selected {
            Line::styled(text, theme.selected)
        } else {
            Line::raw(text)
        });
    }
    if end - start < total {
        lines.push(Line::styled(
            format!("hosts {}-{} of {}", start + 1, end, total),
            theme.muted,
        ));
    }
    (lines, rows)
}

/// The row's cells, cleaned.
struct Cells {
    name: String,
    kind: String,
    agent: &'static str,
    perms: String,
    too_open: bool,
}

fn cells_for(entry: &KeyEntry, cleaner: &mut Cleaner) -> Cells {
    let perms = match entry.permissions {
        Permissions::Fine => "ok".to_string(),
        Permissions::TooOpen { mode } => format!("{} too open", mode_label(mode)),
        Permissions::Unchecked => "-".to_string(),
    };
    Cells {
        name: cleaner.clean(&entry.name).into_owned(),
        kind: match &entry.fingerprint {
            Ok(key) => key.type_label(),
            Err(_) => "?".to_string(),
        },
        agent: match entry.loaded {
            Some(true) => "loaded",
            Some(false) => "not loaded",
            None => "unknown",
        },
        perms,
        too_open: entry.permissions.is_too_open(),
    }
}

fn header_line(name_width: usize, width: usize, theme: &Theme) -> Line<'static> {
    let mut text = "  ".to_string();
    text.push_str(&pad("Name", name_width));
    for (title, cell) in [
        ("Type", TYPE_WIDTH),
        ("Agent", AGENT_WIDTH),
        ("Permissions", PERMS_WIDTH),
    ] {
        text.push_str(COLUMN_GAP);
        text.push_str(&pad(title, cell));
    }
    Line::styled(pad(&text, width), theme.muted)
}

fn row_line(
    cells: &Cells,
    name_width: usize,
    selected: bool,
    width: usize,
    theme: &Theme,
) -> Line<'static> {
    let cell = |text: &str, cell_width: usize| pad(&truncate(text, cell_width).0, cell_width);
    let perms_style = if cells.too_open {
        theme.warning
    } else {
        Style::new()
    };
    let mut spans = vec![
        Span::raw(if selected { "> " } else { "  " }),
        Span::raw(cell(&cells.name, name_width)),
        Span::raw(COLUMN_GAP),
        Span::raw(cell(&cells.kind, TYPE_WIDTH)),
        Span::raw(COLUMN_GAP),
        Span::raw(cell(cells.agent, AGENT_WIDTH)),
        Span::raw(COLUMN_GAP),
        Span::styled(cell(&cells.perms, PERMS_WIDTH), perms_style),
    ];
    let used: usize = spans.iter().map(Span::width).sum();
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

/// A `Label  value` line, the value wrapped under itself.
fn fact(
    label: &str,
    value: &str,
    width: usize,
    theme: &Theme,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let room = width.saturating_sub(LABEL_WIDTH).max(1);
    wrap(&cleaner.clean(value), room)
        .into_iter()
        .enumerate()
        .map(|(index, piece)| {
            if index == 0 {
                Line::from(vec![
                    Span::styled(pad(label, LABEL_WIDTH), theme.muted),
                    Span::raw(piece),
                ])
            } else {
                Line::raw(format!("{:LABEL_WIDTH$}{piece}", ""))
            }
        })
        .collect()
}

/// What is known about one key: its problems first, since they are what the
/// person came to see, then what it is, then where it is.
fn detail_lines(
    entry: &KeyEntry,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match entry.permissions {
        Permissions::TooOpen { mode } if entry.symlink => lines.extend(labeled_lines(
            "Warning:",
            theme.warning,
            &format!(
                "Other users can read this private key (permissions {}), so ssh will refuse to \
                 use it. It is a symbolic link, so Bifrost will not change it: change the \
                 permissions of the file it points to.",
                mode_label(mode)
            ),
            width,
            cleaner,
        )),
        Permissions::TooOpen { mode } => lines.extend(labeled_lines(
            "Warning:",
            theme.warning,
            &format!(
                "Other users can read this private key (permissions {}), so ssh will refuse to \
                 use it. Press f to set it to 0600.",
                mode_label(mode)
            ),
            width,
            cleaner,
        )),
        Permissions::Fine | Permissions::Unchecked => {}
    }
    match &entry.fingerprint {
        Ok(key) => {
            lines.extend(fact("Fingerprint", &key.hash, width, theme, cleaner));
            lines.extend(fact(
                "Comment",
                key.comment.as_deref().unwrap_or("(none)"),
                width,
                theme,
                cleaner,
            ));
        }
        Err(why) => lines.extend(labeled_lines("Error:", theme.error, why, width, cleaner)),
    }
    lines.extend(fact(
        "Private",
        &entry.private.display().to_string(),
        width,
        theme,
        cleaner,
    ));
    lines.extend(fact(
        "Public",
        &entry.public.display().to_string(),
        width,
        theme,
        cleaner,
    ));
    lines
}

/// What to say instead of a list.
fn empty_lines(
    snapshot: &KeysSnapshot,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let dir = snapshot.dir.display().to_string();
    if let Some(problem) = &snapshot.problem {
        return labeled_lines("Error:", theme.error, problem, width, cleaner);
    }
    let mut lines = Vec::new();
    let mut paragraph = |text: &str, lines: &mut Vec<Line<'static>>| {
        for piece in wrap(&cleaner.clean(text), width.max(1)) {
            lines.push(Line::raw(piece));
        }
    };
    if snapshot.missing_dir {
        paragraph(
            &format!("The folder {dir} does not exist, so there are no keys yet."),
            &mut lines,
        );
    } else {
        paragraph(&format!("No key pairs were found in {dir}."), &mut lines);
        paragraph("", &mut lines);
        paragraph(
            "A key pair is a private key file with a .pub file of the same name next to it.",
            &mut lines,
        );
    }
    paragraph("", &mut lines);
    paragraph(
        "To make one, run this in a terminal: ssh-keygen -t ed25519",
        &mut lines,
    );
    lines
}

pub(super) fn render(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) -> Metrics {
    let Some(screen) = app.keys() else {
        return Metrics::default();
    };
    let snapshot = screen.snapshot();
    let inner_width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();

    // The header: where the keys are, and the agent.
    let mut header: Vec<Line<'static>> = Vec::new();
    if snapshot.dir.as_os_str().is_empty() {
        header.push(Line::raw("Your ssh keys"));
    } else {
        header.push(Line::raw(format!(
            "Keys in {}",
            cleaner.clean(&snapshot.dir.display().to_string())
        )));
    }
    header.extend(agent_lines(
        &snapshot.agent,
        theme,
        inner_width,
        &mut cleaner,
    ));
    if snapshot.truncated {
        header.push(Line::styled(
            format!(
                "Only the first {} key pairs are listed.",
                crate::ssh::keys::MAX_KEYS
            ),
            theme.muted,
        ));
    }
    if !snapshot.keys.is_empty()
        && snapshot
            .keys
            .iter()
            .all(|key| key.permissions == Permissions::Unchecked)
    {
        header.push(Line::styled(
            "Permissions are not checked on this system.",
            theme.muted,
        ));
    }
    header.push(Line::raw(""));

    let cells: Vec<Cells> = snapshot
        .keys
        .iter()
        .map(|entry| cells_for(entry, &mut cleaner))
        .collect();
    let widest_name = cells
        .iter()
        .map(|cell| display_width(&cell.name))
        .max()
        .unwrap_or(0);
    let name_room = inner_width.saturating_sub(FIXED_WIDTH).max(4);
    let name_width = widest_name.clamp(4, MAX_NAME_WIDTH).min(name_room);
    let details = screen
        .selected_entry()
        .map(|entry| detail_lines(entry, theme, inner_width, &mut cleaner))
        .unwrap_or_default();
    let empty = if snapshot.keys.is_empty() {
        empty_lines(snapshot, theme, inner_width, &mut cleaner)
    } else {
        Vec::new()
    };

    let status = status_lines(app.status(), theme, usize::from(area.width), &mut cleaner);
    let confirm = screen.confirming().map(|name| {
        let width = usize::from(area.width.saturating_sub(2))
            .min(60)
            .saturating_sub(4)
            .max(1);
        let mut lines = labeled_lines(
            "",
            Style::new(),
            &format!("Change the permissions of '{name}'?"),
            width,
            &mut cleaner,
        );
        lines.extend(labeled_lines(
            "",
            Style::new(),
            "It will be set to 0600, so only you can read and write it. ssh refuses to use a \
             private key that other users can read.",
            width,
            &mut cleaner,
        ));
        lines.push(Line::raw(""));
        lines.push(Line::raw("Press y to change it, or n to cancel."));
        lines
    });
    let generate = screen
        .generating()
        .map(|form| generate_lines(form, theme, area.width, &mut cleaner));
    let delete = screen
        .deleting()
        .map(|question| delete_lines(question, theme, area, &mut cleaner));
    let use_key = screen
        .using()
        .map(|question| use_key_lines(question, area, &mut cleaner));
    let copy = screen
        .copying()
        .map(|dialog| copy_lines(dialog, screen, theme, area, &mut cleaner));
    let footer = footer_lines(
        &app.footer_hints(),
        cleaner.hidden,
        theme,
        usize::from(area.width),
    );
    let chrome = split_chrome(area, status.len(), footer.len());
    let inner = page_block().inner(chrome.main);

    // The details sit right under the list. The list keeps a few rows before the
    // details are cut, and takes only the rows it has.
    let have_list = !cells.is_empty();
    let below_header = usize::from(inner.height).saturating_sub(header.len());
    let for_list_and_details = below_header.saturating_sub(usize::from(have_list));
    let detail_height = if have_list {
        (details.len() + 1)
            .min(MAX_DETAIL_LINES + 1)
            .min(for_list_and_details.saturating_sub(MIN_LIST_ROWS.min(cells.len())))
    } else {
        0
    };
    let list_height = if have_list {
        cells.len().min(for_list_and_details - detail_height)
    } else {
        for_list_and_details
    };
    let [header_area, column_area, list_area, detail_area, _] = Layout::vertical([
        Constraint::Length(u16::try_from(header.len()).unwrap_or(u16::MAX)),
        Constraint::Length(u16::from(have_list)),
        Constraint::Length(u16::try_from(list_height).unwrap_or(u16::MAX)),
        Constraint::Length(u16::try_from(detail_height).unwrap_or(u16::MAX)),
        Constraint::Min(0),
    ])
    .areas(inner);

    let visible = usize::from(list_area.height);
    let start = window_start(
        screen.offset(),
        Some(screen.selected()),
        visible,
        cells.len(),
    );
    let end = (start + visible).min(cells.len());

    let mut block = page_block().title(Span::styled(" Keys ", theme.title));
    if cells.len() > visible && visible > 0 {
        block = block.title_bottom(
            Line::from(Span::styled(
                format!(" keys {}-{} of {} ", start + 1, end, cells.len()),
                theme.muted,
            ))
            .right_aligned(),
        );
    }
    frame.render_widget(block, chrome.main);
    frame.render_widget(Paragraph::new(header), header_area);
    if have_list {
        frame.render_widget(
            Paragraph::new(vec![header_line(name_width, inner_width, theme)]),
            column_area,
        );
        let rows: Vec<Line<'static>> = (start..end)
            .map(|index| {
                row_line(
                    &cells[index],
                    name_width,
                    index == screen.selected(),
                    inner_width,
                    theme,
                )
            })
            .collect();
        frame.render_widget(Paragraph::new(rows), list_area);
        if detail_height > 1 {
            let mut shown = vec![Line::raw("")];
            shown.extend(details.into_iter().take(detail_height - 1));
            frame.render_widget(Paragraph::new(shown), detail_area);
        }
    } else {
        frame.render_widget(Paragraph::new(empty), list_area);
    }
    render_chrome(frame, &chrome, status, footer);
    if let Some(lines) = confirm {
        render_popup(frame, area, "Fix permissions", lines, theme);
    }
    if let Some((lines, (column, row))) = generate {
        let inner = render_popup(frame, area, "New key", lines, theme);
        place_cursor(frame, inner, column, row);
    }
    if let Some(lines) = use_key {
        render_popup(frame, area, "Use this key?", lines, theme);
    }
    if let Some((lines, (column, row))) = delete {
        let inner = render_popup(frame, area, "Delete key", lines, theme);
        place_cursor(frame, inner, column, row);
    }
    let mut copy_rows = 0;
    if let Some((lines, rows)) = copy {
        copy_rows = rows;
        render_popup(frame, area, "Send public key", lines, theme);
    }
    Metrics {
        keys_rows: visible,
        copy_rows,
        ..Metrics::default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use crate::ssh::keys::Fingerprint;
    use crate::tui::effects::{Request, Response};
    use crate::tui::keys::testing::{entry, snapshot};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::path::PathBuf;

    const HASH_A: &str = "SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw";
    const HASH_B: &str = "SHA256:Crv2UD7RjSr55ym7z5Nso5T9YwtVbduZ6xUVvnj9VtE";

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    /// An app on the keys screen showing `snapshot`.
    fn on_keys(snapshot: KeysSnapshot) -> App {
        let mut app = app_with(vec![host("web", "192.0.2.1")], Vec::new());
        app.handle_key(key('K'));
        let request = app.take_request().unwrap();
        assert_eq!(request, Request::LoadKeys);
        app.handle_response(&request, Response::Keys(snapshot));
        app
    }

    fn rsa(name: &str, permissions: Permissions) -> KeyEntry {
        let mut key = entry(name, permissions, false);
        key.fingerprint = Ok(Fingerprint {
            bits: 2048,
            hash: HASH_B.to_string(),
            comment: None,
            key_type: "RSA".to_string(),
        });
        key
    }

    fn typical() -> KeysSnapshot {
        let mut homelab = entry("id_ed25519_homelab", Permissions::Fine, false);
        homelab.loaded = Some(true);
        let mut snap = snapshot(vec![
            homelab,
            rsa("id_rsa_old", Permissions::TooOpen { mode: 0o644 }),
            entry("deploy", Permissions::Fine, false),
        ]);
        snap.agent = AgentState::Running {
            hashes: vec![HASH_A.to_string()],
        };
        snap
    }

    fn flat(text: &str) -> String {
        text.split_whitespace()
            .filter(|word| *word != "│")
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn the_list_shows_each_key_with_its_type_agent_and_permissions() {
        let mut app = on_keys(typical());
        let text = text_of(&mut app, 100, 30);
        for expected in [
            "Keys in /home/dev/.ssh",
            "Agent: running, holding 1 key.",
            "Name",
            "Type",
            "Agent",
            "Permissions",
            "id_ed25519_homelab",
            "ed25519",
            "loaded",
            "id_rsa_old",
            "rsa 2048",
            "0644 too open",
            "deploy",
        ] {
            assert!(text.contains(expected), "{expected}:\n{text}");
        }
        // Sorted as the snapshot is, the first is selected, and the footer lists
        // what works here.
        assert!(text.contains("> id_ed25519_homelab"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("Up/Down j/k move") && footer.contains("r refresh"),
            "{footer}"
        );
        assert!(
            footer.contains("Esc back") && footer.contains("q quit"),
            "{footer}"
        );
    }

    #[test]
    fn the_selected_key_is_described_below_the_list() {
        let mut app = on_keys(typical());
        let words = flat(&text_of(&mut app, 100, 30));
        assert!(words.contains(&format!("Fingerprint {HASH_A}")), "{words}");
        assert!(words.contains("Comment dev laptop"), "{words}");
        assert!(
            words.contains("Private /home/dev/.ssh/id_ed25519_homelab"),
            "{words}"
        );
        assert!(
            words.contains("Public /home/dev/.ssh/id_ed25519_homelab.pub"),
            "{words}"
        );

        app.handle_key(key('j'));
        let words = flat(&text_of(&mut app, 100, 30));
        assert!(words.contains(&format!("Fingerprint {HASH_B}")), "{words}");
        assert!(
            words.contains("Comment (none)"),
            "a key with no comment says so:\n{words}"
        );
    }

    #[test]
    fn loaded_and_not_loaded_and_unknown_are_words() {
        let mut snap = typical();
        snap.keys[2].loaded = None;
        let mut app = on_keys(snap);
        let text = text_of(&mut app, 100, 30);
        let row = |name: &str| text.lines().find(|l| l.contains(name)).unwrap().to_string();
        assert!(row("id_ed25519_homelab").contains(" loaded "), "{text}");
        assert!(row("id_rsa_old").contains("not loaded"), "{text}");
        assert!(row("deploy").contains("unknown"), "{text}");
    }

    // ---- permissions -----------------------------------------------------------------

    #[test]
    fn a_key_that_is_too_open_is_flagged_in_words_and_says_how_to_fix_it() {
        let mut app = on_keys(typical());
        app.handle_key(key('j'));
        let words = flat(&text_of(&mut app, 100, 30));
        assert!(
            words.contains("Warning: Other users can read this private key (permissions 0644)"),
            "{words}"
        );
        assert!(
            words.contains("ssh will refuse to use it. Press f to set it to 0600."),
            "{words}"
        );
        // The footer wraps when there are many keys to list.
        let text = text_of(&mut app, 100, 30);
        let footer = text.lines().rev().take(2).collect::<Vec<_>>().join(" ");
        assert!(footer.contains("f fix permissions"), "{footer}");
    }

    #[test]
    fn a_link_that_is_too_open_says_bifrost_will_not_change_it() {
        let mut snap = typical();
        snap.keys[1].symlink = true;
        let mut app = on_keys(snap);
        app.handle_key(key('j'));
        let text = text_of(&mut app, 100, 30);
        let words = flat(&text);
        assert!(
            words.contains("symbolic link, so Bifrost will not change it"),
            "{words}"
        );
        assert!(!words.contains("Press f"), "{words}");
        assert!(!text.lines().last().unwrap().contains("fix permissions"));
    }

    #[test]
    fn the_question_names_the_key_and_the_mode_it_will_get() {
        let mut app = on_keys(typical());
        app.handle_key(key('j'));
        app.handle_key(key('f'));
        let text = text_of(&mut app, 100, 30);
        let words = flat(&text);
        assert!(
            words.contains("Change the permissions of 'id_rsa_old'?"),
            "{words}"
        );
        assert!(words.contains("0600"), "{words}");
        assert!(
            words.contains("Press y to change it, or n to cancel."),
            "{words}"
        );
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("y change to 0600") && footer.contains("n/Esc cancel"),
            "{footer}"
        );
    }

    #[test]
    fn where_permissions_are_not_checked_the_screen_says_so_instead_of_claiming_all_is_well() {
        let mut snap = typical();
        for key in &mut snap.keys {
            key.permissions = Permissions::Unchecked;
        }
        let mut app = on_keys(snap);
        let text = text_of(&mut app, 100, 30);
        assert!(
            text.contains("Permissions are not checked on this system."),
            "{text}"
        );
        let row = text.lines().find(|l| l.contains("deploy")).unwrap();
        assert!(!row.contains(" ok"), "unchecked is not ok: {row}");
        assert!(!text.contains("too open"));
    }

    // ---- the agent ---------------------------------------------------------------------

    fn agent_screen(agent: AgentState) -> String {
        let mut snap = typical();
        snap.agent = agent;
        for key in &mut snap.keys {
            key.loaded = None;
        }
        flat(&text_of(&mut on_keys(snap), 100, 30))
    }

    #[test]
    fn an_agent_that_is_not_running_is_explained_as_a_normal_state() {
        let words = agent_screen(AgentState::NotStarted);
        assert!(words.contains("Agent: not running."), "{words}");
        assert!(words.contains("This terminal has no ssh-agent"), "{words}");
        assert!(words.contains("That is normal."), "{words}");
        assert!(words.contains("eval \"$(ssh-agent -s)\""), "{words}");
        assert!(!words.contains("Error:"), "it is not an error: {words}");
    }

    #[test]
    fn an_agent_that_is_gone_says_so_differently_from_one_never_started() {
        let words = agent_screen(AgentState::Unreachable);
        assert!(words.contains("Agent: not running."), "{words}");
        assert!(
            words.contains("SSH_AUTH_SOCK points to an agent that is not answering"),
            "{words}"
        );
    }

    #[test]
    fn an_agent_that_could_not_be_checked_or_told_says_what_it_knows() {
        let words = agent_screen(AgentState::Unavailable(
            "ssh-add did not answer within 3 seconds.".to_string(),
        ));
        assert!(words.contains("Agent: could not be checked."), "{words}");
        assert!(
            words.contains("ssh-add did not answer within 3 seconds."),
            "{words}"
        );
        let words = agent_screen(AgentState::Unknown("something new".to_string()));
        assert!(words.contains("Agent: could not be told."), "{words}");
        assert!(words.contains("ssh-add said: something new"), "{words}");
    }

    #[test]
    fn an_agent_with_no_keys_and_with_many_are_counted() {
        assert!(
            agent_screen(AgentState::Running { hashes: vec![] })
                .contains("Agent: running, holding no keys.")
        );
        assert!(
            agent_screen(AgentState::Running {
                hashes: vec![HASH_A.to_string(), HASH_B.to_string()]
            })
            .contains("Agent: running, holding 2 keys.")
        );
    }

    // ---- nothing to list ------------------------------------------------------------------

    #[test]
    fn no_key_pairs_says_what_a_pair_is_and_how_to_make_one() {
        let mut app = on_keys(snapshot(Vec::new()));
        let words = flat(&text_of(&mut app, 100, 30));
        assert!(
            words.contains("No key pairs were found in /home/dev/.ssh."),
            "{words}"
        );
        assert!(
            words.contains("private key file with a .pub file of the same name"),
            "{words}"
        );
        assert!(words.contains("ssh-keygen -t ed25519"), "{words}");
        assert!(
            !words.contains("Name Type Agent"),
            "no empty table: {words}"
        );
    }

    #[test]
    fn a_folder_that_does_not_exist_is_said_plainly() {
        let mut snap = snapshot(Vec::new());
        snap.missing_dir = true;
        let words = flat(&text_of(&mut on_keys(snap), 100, 30));
        assert!(
            words.contains("The folder /home/dev/.ssh does not exist, so there are no keys yet."),
            "{words}"
        );
    }

    #[test]
    fn a_folder_that_cannot_be_read_is_an_error_with_the_reason() {
        let mut snap = snapshot(Vec::new());
        snap.problem = Some(
            "Could not read the folder /home/dev/.ssh: Permission denied (os error 13)".to_string(),
        );
        let words = flat(&text_of(&mut on_keys(snap), 100, 30));
        assert!(
            words.contains("Error: Could not read the folder /home/dev/.ssh: Permission denied"),
            "{words}"
        );
    }

    #[test]
    fn without_a_home_directory_the_screen_says_so() {
        let snap = KeysSnapshot::unavailable("Could not find your home directory.");
        let words = flat(&text_of(&mut on_keys(snap), 100, 30));
        assert!(words.contains("Your ssh keys"), "{words}");
        assert!(
            words.contains("Error: Could not find your home directory."),
            "{words}"
        );
    }

    #[test]
    fn a_key_ssh_keygen_could_not_read_is_listed_with_the_reason() {
        let mut snap = typical();
        snap.keys[2].fingerprint = Err("ssh-keygen could not read it: not a key".to_string());
        snap.keys[2].loaded = None;
        let mut app = on_keys(snap);
        app.handle_key(key('j'));
        app.handle_key(key('j'));
        let text = text_of(&mut app, 100, 30);
        let row = text.lines().find(|l| l.contains("> deploy")).unwrap();
        assert!(row.contains(" ? "), "the type is unknown: {row}");
        assert!(
            flat(&text).contains("Error: ssh-keygen could not read it: not a key"),
            "{text}"
        );
    }

    #[test]
    fn a_truncated_scan_says_so() {
        let mut snap = typical();
        snap.truncated = true;
        let text = text_of(&mut on_keys(snap), 100, 30);
        assert!(
            text.contains("Only the first 200 key pairs are listed."),
            "{text}"
        );
    }

    // ---- outside text ----------------------------------------------------------------------

    #[test]
    fn names_comments_and_paths_are_cleaned_and_the_footer_says_so() {
        let mut hostile = entry("evil\x1b]0;pwned\x07\u{202e}key", Permissions::Fine, false);
        hostile.private = PathBuf::from("/home/dev/.ssh/evil\x1b[31m");
        hostile.fingerprint = Ok(Fingerprint {
            bits: 256,
            hash: HASH_A.to_string(),
            comment: Some("c\x1b[2Jomment \u{202e}gpj.exe".to_string()),
            key_type: "ED25519".to_string(),
        });
        let mut snap = snapshot(vec![hostile]);
        snap.dir = PathBuf::from("/home/\x1b[31mdev/.ssh");
        snap.agent = AgentState::Unknown("said \x1b[0m\u{2066}this".to_string());
        let mut app = on_keys(snap);
        let terminal = super::super::testing::draw(&mut app, 100, 30);
        let text = screen_text(&terminal);
        assert!(
            text.contains("non-printable characters were hidden"),
            "{text}"
        );
        assert!(text.contains("?]0;pwned?"), "{text}");
        for cell in terminal.backend().buffer().content() {
            assert!(
                !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                "{:?}",
                cell.symbol()
            );
        }
    }

    #[test]
    fn the_status_after_a_fix_is_cleaned_too() {
        let mut app = on_keys(typical());
        app.handle_response(
            &Request::FixKeyPermissions {
                file_name: "x".to_string(),
            },
            Response::PermissionsFixed(Err("bad \x1b[31m\u{202e}thing".to_string())),
        );
        let terminal = super::super::testing::draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(!cell.symbol().chars().any(crate::sanitize::is_unsafe_char));
        }
        assert!(
            screen_text(&terminal).contains("Error: Could not change the permissions of 'x': bad")
        );
    }

    // ---- sizes ---------------------------------------------------------------------------------

    #[test]
    fn at_120x36_everything_fits() {
        let mut app = on_keys(typical());
        let text = text_of(&mut app, 120, 36);
        assert!(
            text.contains("id_ed25519_homelab") && text.contains("Fingerprint"),
            "{text}"
        );
        assert!(
            text.contains("Private") && text.contains("Public"),
            "{text}"
        );
        assert!(
            !text.contains("keys 1-"),
            "no scroll indicator when all fit:\n{text}"
        );
    }

    #[test]
    fn on_the_smallest_terminal_the_list_keeps_rows_and_the_warning_stays_visible() {
        let mut app = on_keys(typical());
        app.handle_key(key('j'));
        let text = text_of(&mut app, 60, 15);
        assert!(
            text.contains("> id_rsa_old"),
            "the selected row is visible:\n{text}"
        );
        assert!(
            flat(&text).contains("Warning: Other users can read"),
            "the problem comes first:\n{text}"
        );
        for line in text.lines() {
            assert!(display_width(line) <= 60, "{line}");
        }
    }

    #[test]
    fn a_long_list_scrolls_with_the_selection_and_shows_where_it_is() {
        let keys: Vec<KeyEntry> = (0..40)
            .map(|n| entry(&format!("key{n:02}"), Permissions::Fine, false))
            .collect();
        let mut app = on_keys(snapshot(keys));
        let first = text_of(&mut app, 80, 20);
        assert!(first.contains("keys 1-"), "{first}");
        for _ in 0..39 {
            app.handle_key(key('j'));
            let _ = text_of(&mut app, 80, 20);
        }
        let last = text_of(&mut app, 80, 20);
        assert!(last.contains("> key39"), "{last}");
        assert!(last.contains("of 40"), "{last}");
        assert!(!last.contains("key00"), "{last}");
    }

    #[test]
    fn the_rows_that_fit_are_reported_back_so_that_scrolling_can_follow() {
        let keys: Vec<KeyEntry> = (0..40)
            .map(|n| entry(&format!("key{n:02}"), Permissions::Fine, false))
            .collect();
        let mut app = on_keys(snapshot(keys));
        let (_, metrics) = draw_with(&mut app, &Theme::ansi16(), 80, 20);
        assert!(metrics.keys_rows >= MIN_LIST_ROWS, "{metrics:?}");
        assert!(metrics.keys_rows < 40);
    }

    #[test]
    fn a_very_long_name_is_cut_and_never_overflows() {
        let long = "n".repeat(200);
        let mut app = on_keys(snapshot(vec![entry(&long, Permissions::Fine, false)]));
        let text = text_of(&mut app, 60, 20);
        for line in text.lines() {
            assert!(display_width(line) <= 60, "{line}");
        }
        assert!(text.contains("..."), "{text}");
    }

    #[test]
    fn no_color_uses_none_and_keeps_the_meaning() {
        let mut app = on_keys(typical());
        app.handle_key(key('j'));
        let theme = Theme::plain();
        let colored = |app: &mut App| colored_cells_of(&draw_with(app, &theme, 100, 30).0);
        assert_eq!(colored(&mut app), 0);
        app.handle_key(key('f'));
        assert_eq!(colored(&mut app), 0);
        assert!(
            text_of(&mut app, 100, 30).contains("0644 too open"),
            "words, not color"
        );
    }

    #[test]
    fn the_details_sit_directly_under_the_list_however_tall_the_terminal() {
        let mut app = on_keys(typical());
        let text = text_of(&mut app, 100, 36);
        let lines: Vec<&str> = text.lines().collect();
        let last_row = lines.iter().position(|l| l.contains("deploy")).unwrap();
        let details = lines
            .iter()
            .position(|l| l.contains("Fingerprint"))
            .unwrap();
        assert!(
            details - last_row <= 2,
            "a gap of {} lines:\n{text}",
            details - last_row
        );
    }

    // ---- the form for a new key ------------------------------------------------------------------

    fn typing(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_key(key(c));
        }
    }

    fn with_form() -> App {
        let mut app = on_keys(typical());
        app.handle_key(key('g'));
        app
    }

    fn cursor_row(terminal: &mut ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let text = screen_text(terminal);
        let cursor = terminal.get_cursor_position().unwrap();
        text.lines().nth(usize::from(cursor.y)).unwrap().to_string()
    }

    #[test]
    fn the_form_names_its_fields_and_warns_about_the_passphrase_before_it_happens() {
        let mut app = with_form();
        let text = text_of(&mut app, 120, 36);
        for expected in [
            "New key",
            "Make a new ed25519 key.",
            "> File name",
            "id_ed25519",
            "Comment",
            "Letters, digits",
            "Next, ssh-keygen asks for a passphrase.",
            "Bifrost never sees it.",
            "anyone who copies the key file can use the key.",
        ] {
            assert!(flat(&text).contains(expected), "{expected}:\n{text}");
        }
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("Tab next field")
                && footer.contains("Enter next / make the key")
                && footer.contains("Esc cancel"),
            "{footer}"
        );
        assert!(
            !footer.contains("q quit"),
            "the list's keys are not on offer"
        );
    }

    #[test]
    fn the_cursor_sits_after_the_text_of_the_field_that_has_the_focus() {
        let mut app = with_form();
        let mut terminal = draw(&mut app, 100, 30);
        let row = cursor_row(&mut terminal);
        assert!(
            row.contains("> File name") && row.contains("id_ed25519"),
            "{row}"
        );
        let cursor = terminal.get_cursor_position().unwrap();
        // Columns, not bytes: the border characters are several bytes wide.
        let start = row.find("id_ed25519").unwrap();
        let column = row[..start].chars().count() + "id_ed25519".len();
        assert_eq!(usize::from(cursor.x), column);

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        typing(&mut app, "work");
        let mut terminal = draw(&mut app, 100, 30);
        let row = cursor_row(&mut terminal);
        assert!(row.contains("> Comment") && row.contains("work"), "{row}");
        assert!(
            screen_text(&terminal).contains("  File name"),
            "the other field is not marked"
        );
        assert!(screen_text(&terminal).contains("Optional: a label"));
    }

    #[test]
    fn a_complaint_is_shown_under_its_field_and_goes_when_the_field_is_edited() {
        let mut app = with_form();
        typing(&mut app, " x");
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let text = text_of(&mut app, 100, 30);
        assert!(
            flat(&text).contains("Error: The file name may only contain letters"),
            "{text}"
        );
        assert!(
            flat(&text).contains("never sees it"),
            "the warning stays:\n{text}"
        );

        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(!text_of(&mut app, 100, 30).contains("Error:"));
    }

    #[test]
    fn on_the_smallest_terminal_the_form_keeps_the_complaint_and_the_passphrase_warning() {
        let mut app = with_form();
        typing(&mut app, " x");
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let mut terminal = draw(&mut app, 60, 15);
        let text = screen_text(&terminal);
        assert!(flat(&text).contains("Error:"), "{text}");
        assert!(flat(&text).contains("Bifrost never sees it."), "{text}");
        assert!(
            flat(&text).contains("use the key."),
            "the whole warning:\n{text}"
        );
        let cursor = terminal.get_cursor_position().unwrap();
        assert!(cursor.x < 60 && cursor.y < 15);
        assert!(cursor_row(&mut terminal).contains("File name"));
    }

    #[test]
    fn a_very_long_name_scrolls_inside_the_box_and_the_cursor_stays_in_it() {
        let mut app = with_form();
        typing(&mut app, &"x".repeat(200));
        let mut terminal = draw(&mut app, 60, 15);
        let text = screen_text(&terminal);
        for line in text.lines() {
            assert!(display_width(line) <= 60, "{line}");
        }
        let cursor = terminal.get_cursor_position().unwrap();
        assert!(cursor.x < 59, "inside the popup: {}", cursor.x);
        assert!(cursor_row(&mut terminal).contains("File name"));
    }

    #[test]
    fn what_is_typed_into_the_form_is_cleaned_before_it_is_drawn() {
        let mut app = with_form();
        typing(&mut app, "a\u{202e}b");
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        typing(&mut app, "c\u{2066}d");
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(!cell.symbol().chars().any(crate::sanitize::is_unsafe_char));
        }
    }

    #[test]
    fn the_message_after_a_tool_failed_is_cleaned_too() {
        let mut app = on_keys(typical());
        app.handle_response(
            &Request::GenerateKey {
                file_name: "x".to_string(),
                comment: None,
            },
            Response::KeyGenerated(crate::tui::app::HandoverResult::Ran(
                crate::ssh::connect::Outcome {
                    exit: crate::ssh::connect::Exit::Code(1),
                    stderr: b"boom \x1b]0;title\x07 \xe2\x80\xaeevil\n".to_vec(),
                    interrupted: false,
                },
            )),
        );
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(!cell.symbol().chars().any(crate::sanitize::is_unsafe_char));
        }
        assert!(screen_text(&terminal).contains("Could not make the key 'x'"));
    }

    #[test]
    fn the_form_needs_no_color_to_be_understood() {
        let mut app = with_form();
        let text = text_of(&mut app, 100, 30);
        assert!(
            text.contains("> File name"),
            "the focus is a marker, not a color"
        );
        let terminal = draw_with(&mut app, &Theme::plain(), 100, 30).0;
        assert!(screen_text(&terminal).contains("> File name"));
    }

    // ---- the dialog that sends a public key --------------------------------------------------------

    fn key_of(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// The keys screen of an app that has these hosts saved.
    fn on_keys_with_hosts(hosts: Vec<crate::domain::Host>, snapshot: KeysSnapshot) -> App {
        let mut app = app_with(hosts, Vec::new());
        app.handle_key(key('K'));
        let request = app.take_request().unwrap();
        app.handle_response(&request, Response::Keys(snapshot));
        app
    }

    fn many_hosts(count: usize) -> Vec<crate::domain::Host> {
        (0..count)
            .map(|n| host(&format!("host{n:02}"), &format!("10.0.0.{}", n + 1)))
            .collect()
    }

    fn choosing() -> App {
        let mut app = on_keys(typical());
        app.handle_key(key('c'));
        app
    }

    #[test]
    fn the_dialog_lists_the_hosts_with_where_each_one_is_and_marks_the_choice() {
        let mut app = on_keys_with_hosts(
            vec![host("web", "web.example.com"), {
                let mut db = host("db", "10.0.0.5");
                db.user = Some("admin".to_string());
                db.port = Some(2222);
                db
            }],
            typical(),
        );
        app.handle_key(key('c'));
        let text = text_of(&mut app, 120, 36);
        assert!(text.contains("Send public key"), "{text}");
        assert!(
            flat(&text).contains("Send the public key of 'id_ed25519_homelab' to which host?"),
            "{text}"
        );
        assert!(flat(&text).contains("> db admin@10.0.0.5:2222"), "{text}");
        assert!(flat(&text).contains("web web.example.com"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("Up/Down j/k choose")
                && footer.contains("Enter select")
                && footer.contains("Esc cancel"),
            "{footer}"
        );
        assert!(
            !footer.contains("q quit"),
            "the list's keys are not on offer"
        );
    }

    #[test]
    fn the_question_names_the_key_the_host_and_what_sending_does() {
        let mut app = choosing();
        app.handle_key(key_of(KeyCode::Enter));
        let text = text_of(&mut app, 120, 36);
        let words = flat(&text);
        for expected in [
            "Send the public key of 'id_ed25519_homelab' to 'web'?",
            "Key ed25519 (dev laptop) SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw Host 192.0.2.1",
            "It is added to ~/.ssh/authorized_keys there",
            "whoever has the matching private key can log in",
            "ssh may ask for a password first.",
            "Press y to send it, or n to go back.",
        ] {
            assert!(words.contains(expected), "{expected}:\n{text}");
        }
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("y send the key") && footer.contains("n/Esc back"),
            "{footer}"
        );
    }

    #[test]
    fn on_the_smallest_terminal_the_question_keeps_its_last_line() {
        // Whatever the names, at the smallest size the way to answer is on screen,
        // with the key, and the fingerprint is never cut in the middle.
        for (host_name, key_name) in [
            ("web", "id_ed25519_homelab"),
            ("host00", "id_ed25519_homelab"),
            (
                "a-long-host-name-for-a-server",
                "a-key-with-a-very-long-file-name-of-sixty-four-chars-x",
            ),
        ] {
            let mut snapshot = typical();
            snapshot.keys[0].name = key_name.to_string();
            let mut app = on_keys_with_hosts(vec![host(host_name, "192.0.2.1")], snapshot);
            app.handle_key(key('c'));
            app.handle_key(key_of(KeyCode::Enter));
            let text = text_of(&mut app, 60, 15);
            let words = flat(&text);
            assert!(
                words.contains("Press y to send it, or n to go back."),
                "{host_name}/{key_name}:\n{text}"
            );
            assert!(words.contains("Key ed25519"), "{text}");
            assert!(
                words.contains("SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw"),
                "the fingerprint is whole:\n{text}"
            );
            assert!(words.contains("Host 192.0.2.1"), "{text}");
            for line in text.lines() {
                assert!(display_width(line) <= 60, "{line}");
            }
        }
    }

    #[test]
    fn many_hosts_scroll_with_the_choice_and_the_rows_that_fit_are_reported() {
        let mut app = on_keys_with_hosts(many_hosts(30), typical());
        app.handle_key(key('c'));
        let mut terminal = draw(&mut app, 60, 15);
        let text = screen_text(&terminal);
        assert!(text.contains("hosts 1-"), "{text}");
        assert!(text.contains("of 30"), "{text}");
        assert!(text.contains("> host00"), "{text}");
        let shown = text.lines().filter(|line| line.contains(" host")).count();
        assert!((3..=12).contains(&shown), "{shown} rows:\n{text}");

        app.handle_key(key_of(KeyCode::End));
        terminal = draw(&mut app, 60, 15);
        let text = screen_text(&terminal);
        assert!(
            text.contains("> host29"),
            "the choice stays in view:\n{text}"
        );
        assert!(
            text.contains("of 30") && !text.contains("hosts 1-"),
            "{text}"
        );
        assert!(!text.contains("host00"), "{text}");
    }

    #[test]
    fn a_few_hosts_all_fit_and_say_nothing_about_scrolling() {
        let mut app = choosing();
        let text = text_of(&mut app, 100, 30);
        assert!(!text.contains("hosts 1-"), "{text}");
    }

    #[test]
    fn a_key_comment_in_the_question_is_cleaned_like_all_external_text() {
        let mut snapshot = typical();
        if let Ok(found) = &mut snapshot.keys[0].fingerprint {
            found.comment = Some("evil\x1b]0;pwned\x07 \u{202e}text".to_string());
        }
        let mut app = on_keys_with_hosts(vec![host("web", "192.0.2.1")], snapshot);
        app.handle_key(key('c'));
        app.handle_key(key_of(KeyCode::Enter));
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(!cell.symbol().chars().any(crate::sanitize::is_unsafe_char));
        }
        let text = screen_text(&terminal);
        assert!(
            text.contains("evil"),
            "the comment is still shown, cleaned:\n{text}"
        );
        assert!(
            flat(&text).contains("non-printable characters were hidden"),
            "and the footer says so:\n{text}"
        );
    }

    #[test]
    fn the_message_after_sending_is_shown_at_the_bottom_of_the_keys_screen() {
        let mut app = choosing();
        app.handle_response(
            &Request::CopyKey {
                file_name: "id_ed25519_homelab".to_string(),
                connect: crate::tui::app::ConnectRequest {
                    name: "web".to_string(),
                    args: crate::ssh::command::build_copy_args(
                        &host("web", "192.0.2.1"),
                        &crate::domain::Hosts::from_vec(vec![host("web", "192.0.2.1")]).unwrap(),
                    )
                    .unwrap(),
                    known_hosts: Vec::new(),
                },
            },
            Response::KeyCopied(crate::tui::app::HandoverResult::Ran(
                crate::ssh::connect::Outcome {
                    exit: crate::ssh::connect::Exit::Code(1),
                    stderr: b"bad \x1b[31m\xe2\x80\xaething\n".to_vec(),
                    interrupted: false,
                },
            )),
        );
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(!cell.symbol().chars().any(crate::sanitize::is_unsafe_char));
        }
        assert!(
            flat(&screen_text(&terminal))
                .contains("Error: 'web' ran the command that adds the key"),
            "{}",
            screen_text(&terminal)
        );
    }

    // ---- the question about using a key that was sent ------------------------------

    /// The keys screen just after the key `key_name` was sent to `db`, which has
    /// `identity_file` (or none).
    fn after_sending(key_name: &str, identity_file: Option<&str>) -> App {
        let mut db = host("db", "192.0.2.2");
        db.identity_file = identity_file.map(str::to_string);
        let mut snapshot = typical();
        snapshot.keys[0].name = key_name.to_string();
        let mut app = on_keys_with_hosts(vec![db], snapshot);
        app.handle_key(key('c'));
        app.handle_key(key_of(KeyCode::Enter));
        app.handle_key(key('y'));
        let request = app.take_request().unwrap();
        assert!(matches!(request, Request::CopyKey { .. }));
        app.handle_response(
            &request,
            Response::KeyCopied(crate::tui::app::HandoverResult::Ran(
                crate::ssh::connect::Outcome {
                    exit: crate::ssh::connect::Exit::Code(0),
                    stderr: Vec::new(),
                    interrupted: false,
                },
            )),
        );
        app
    }

    #[test]
    fn the_question_names_the_key_the_host_and_what_will_be_set() {
        let mut app = after_sending("id_ed25519_homelab", None);
        let text = text_of(&mut app, 100, 30);
        let words = flat(&text);
        for expected in [
            "Use this key?",
            "Use this key for 'db' from now on?",
            "'id_ed25519_homelab' was just sent to 'db'.",
            "sets the host's identity file to ~/.ssh/id_ed25519_homelab",
            "ssh offers only that key when you connect to it.",
            "Press y to use it, or n to leave the host as it is.",
        ] {
            assert!(words.contains(expected), "{expected}:\n{text}");
        }
        assert!(
            !words.contains("replaces"),
            "a host with no key replaces nothing:\n{text}"
        );
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("y use it") && footer.contains("n/Esc leave it"),
            "{footer}"
        );
        // What was just said stays at the bottom, above the footer.
        assert!(
            words.contains("Sent the public key of 'id_ed25519_homelab' to 'db'."),
            "{text}"
        );
    }

    #[test]
    fn a_host_with_another_key_is_told_what_would_be_replaced() {
        let mut app = after_sending("id_ed25519_homelab", Some("~/.ssh/old_key"));
        let words = flat(&text_of(&mut app, 100, 30));
        assert!(
            words.contains("This replaces ~/.ssh/old_key, which the host uses now."),
            "{words}"
        );
    }

    #[test]
    fn on_the_smallest_terminal_the_question_keeps_the_replacement_and_the_answer() {
        for identity in [None, Some("~/.ssh/old_key_with_a_rather_long_name_indeed")] {
            for key_name in [
                "id_ed25519_homelab",
                "a-key-with-a-very-long-file-name-of-sixty-four-chars-x",
            ] {
                let mut app = after_sending(key_name, identity);
                let text = text_of(&mut app, 60, 15);
                let words = flat(&text);
                assert!(
                    words.contains("Press y to use it, or n to leave the host as it is."),
                    "{key_name} {identity:?}:\n{text}"
                );
                assert!(words.contains("Use this key for 'db'"), "{text}");
                if identity.is_some() {
                    assert!(words.contains("This replaces"), "{text}");
                }
                for line in text.lines() {
                    assert!(display_width(line) <= 60, "{line}");
                }
            }
        }
    }

    #[test]
    fn a_key_name_from_outside_in_the_question_is_cleaned() {
        // A bidi override passes the checks for a path, and must not be drawn. (A
        // host's own identity file with one never gets here: ssh is not given it.)
        let mut app = after_sending("evil\u{202e}key", None);
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(
                !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                "{:?}",
                cell.symbol()
            );
        }
        let text = screen_text(&terminal);
        assert!(text.contains("evil"), "{text}");
        assert!(
            flat(&text).contains("non-printable characters were hidden"),
            "the footer says so:\n{text}"
        );
    }

    #[test]
    fn the_answer_line_does_not_depend_on_color() {
        let mut app = after_sending("id_ed25519_homelab", None);
        let terminal = draw_with(&mut app, &Theme::plain(), 100, 30).0;
        let text = screen_text(&terminal);
        assert!(flat(&text).contains("Press y to use it"), "{text}");
        assert!(text.contains("y use it"), "{text}");
    }

    // ---- the question before deleting a key -------------------------------------------

    fn question(used_by: &[&str]) -> DeleteQuestion {
        DeleteQuestion {
            key: "id_ed25519_homelab".to_string(),
            private: "/home/dev/.ssh/id_ed25519_homelab".to_string(),
            public: "/home/dev/.ssh/id_ed25519_homelab.pub".to_string(),
            symlink: false,
            used_by: used_by.iter().map(|name| (*name).to_string()).collect(),
            loaded: false,
            input: crate::tui::input::TextInput::default(),
            mismatch: false,
        }
    }

    /// The popup's own text, with its wraps and indents made single spaces.
    fn popup_text(
        question: &DeleteQuestion,
        width: u16,
        height: u16,
    ) -> (String, Vec<String>, (usize, usize)) {
        let (lines, cursor) = delete_lines(
            question,
            &Theme::ansi16(),
            Rect::new(0, 0, width, height),
            &mut Cleaner::default(),
        );
        let rows: Vec<String> = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect();
        (
            rows.join(" ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            rows,
            cursor,
        )
    }

    const WARNING: &str = "Bifrost cannot know which servers have this key in their authorized_keys. \
        Deleting it means losing access to those servers until another key is installed.";

    #[test]
    fn the_question_says_plainly_that_the_servers_cannot_be_known_and_access_is_lost() {
        for (used, width, height) in [
            (vec![], 100, 30),
            (vec!["db"], 100, 30),
            (vec!["db", "web"], 80, 24),
            (vec!["db"], 60, 15),
            (vec![], 60, 15),
        ] {
            let (text, _, _) = popup_text(&question(&used), width, height);
            assert!(
                text.contains(WARNING),
                "{used:?} at {width}x{height}: {text}"
            );
            assert!(
                text.contains("Delete the key 'id_ed25519_homelab'?"),
                "{text}"
            );
            assert!(text.contains("Type the key's name to confirm:"), "{text}");
        }
    }

    #[test]
    fn the_hosts_that_use_the_key_are_listed_before_asking_and_no_host_is_said_too() {
        let (text, _, _) = popup_text(&question(&["db", "web"]), 100, 30);
        assert!(
            text.contains("Used by: db, web. Their key file is this key, and would be gone."),
            "{text}"
        );
        assert!(!text.contains("No saved host"), "{text}");
        let (none, _, _) = popup_text(&question(&[]), 100, 30);
        assert!(
            none.contains("No saved host has this key as its key file."),
            "{none}"
        );
        assert!(!none.contains("Used by"), "{none}");
    }

    #[test]
    fn a_long_list_of_hosts_is_cut_with_how_many_more_and_a_small_terminal_cuts_it_further() {
        let names: Vec<String> = (0..20).map(|n| format!("host{n:02}")).collect();
        let hosts: Vec<&str> = names.iter().map(String::as_str).collect();
        let (text, _, _) = popup_text(&question(&hosts), 100, 40);
        assert!(
            text.contains(
                "host00, host01, host02, host03, host04, host05, host06, host07 and 12 more."
            ),
            "{text}"
        );
        assert!(!text.contains("host08"), "{text}");
        // The most demanding case at the smallest size: everything that must be said
        // and a mismatch error, with the list giving way and not the line to type on.
        let mut hard = question(&hosts);
        hard.mismatch = true;
        hard.loaded = true;
        hard.symlink = true;
        let (text, rows, (col, row)) = popup_text(&hard, 60, 15);
        assert!(rows.len() <= 11, "{} rows: {rows:#?}", rows.len());
        assert!(text.contains(WARNING), "{text}");
        assert!(text.contains("Type the key's name to confirm:"), "{text}");
        assert!(
            text.contains("Error: That is not the key's name."),
            "{text}"
        );
        assert!(
            text.contains("host00") && text.contains("more."),
            "some hosts, and how many more: {text}"
        );
        assert!(
            rows[row].starts_with("> "),
            "the cursor is on the line to type on: {rows:#?}"
        );
        assert_eq!(col, 2);
    }

    #[test]
    fn what_is_only_helpful_goes_first_when_there_is_no_room_and_stays_when_there_is() {
        let mut full = question(&["db"]);
        full.loaded = true;
        full.symlink = true;
        let (roomy, rows, _) = popup_text(&full, 100, 40);
        for present in [
            "This removes /home/dev/.ssh/id_ed25519_homelab and /home/dev/.ssh/id_ed25519_homelab.pub.",
            "It is a symbolic link: only the link is removed, and the file it points to stays.",
            "The agent holds this key and keeps holding it until it is restarted or you run ssh-add -d.",
        ] {
            assert!(roomy.contains(present), "{present}: {roomy}");
        }
        assert!(
            rows.iter().any(String::is_empty),
            "spaced out when there is room"
        );

        let (tight, _, _) = popup_text(&full, 60, 15);
        assert!(
            !tight.contains("The agent holds"),
            "the agent note went first: {tight}"
        );
        assert!(tight.contains("Used by: db"), "the hosts stay: {tight}");
        assert!(tight.contains(WARNING), "the warning stays: {tight}");
    }

    #[test]
    fn the_optional_lines_go_in_a_fixed_order_as_the_room_shrinks() {
        // The agent note first, then the link note, then which files are removed: at
        // any height, a line that is there means the ones that go after it are too.
        let mut full = question(&["db"]);
        full.loaded = true;
        full.symlink = true;
        for width in [60, 100] {
            let mut seen = Vec::new();
            for height in 10..=40 {
                let (text, _, _) = popup_text(&full, width, height);
                assert!(text.contains(WARNING), "{width}x{height}: {text}");
                let present = (
                    text.contains("The agent holds"),
                    text.contains("It is a symbolic link"),
                    text.contains("This removes"),
                );
                assert!(
                    !present.0 || present.1,
                    "the agent note stays only with the link note, {width}x{height}: {text}"
                );
                assert!(
                    !present.1 || present.2,
                    "the link note stays only with the files, {width}x{height}: {text}"
                );
                seen.push(present);
            }
            // The test would mean nothing if the lines were never dropped one at a time.
            assert!(seen.contains(&(false, true, true)), "{width}: {seen:?}");
            assert!(seen.contains(&(false, false, true)), "{width}: {seen:?}");
            assert!(seen.contains(&(false, false, false)), "{width}: {seen:?}");
            assert!(seen.contains(&(true, true, true)), "{width}: {seen:?}");
        }
    }

    #[test]
    fn however_little_room_there_is_at_least_one_host_is_named() {
        let names: Vec<String> = (0..20).map(|n| format!("host{n:02}")).collect();
        let hosts: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut hard = question(&hosts);
        hard.mismatch = true;
        hard.loaded = true;
        hard.symlink = true;
        for height in 6..=15 {
            let (text, _, _) = popup_text(&hard, 60, height);
            assert!(
                text.contains("Used by: host00"),
                "a list that names nobody says nothing, at height {height}: {text}"
            );
        }
    }

    #[test]
    fn the_cursor_is_on_the_line_to_type_on_after_what_was_typed() {
        let mut q = question(&["db"]);
        q.input = crate::tui::input::TextInput::new("id_ed");
        let (_, rows, (col, row)) = popup_text(&q, 100, 30);
        assert_eq!(rows[row], "> id_ed");
        assert_eq!(col, 2 + 5);
    }

    fn delete_app(hosts_list: Vec<crate::domain::Host>, select: usize) -> App {
        let mut app = on_keys_with_hosts(hosts_list, typical());
        for _ in 0..select {
            app.handle_key(key('j'));
        }
        app.handle_key(key('D'));
        app
    }

    #[test]
    fn on_screen_the_question_shows_the_footer_and_puts_the_cursor_after_the_typed_name() {
        let mut db = host("db", "192.0.2.2");
        db.identity_file = Some("~/.ssh/id_ed25519_homelab".to_string());
        let mut app = delete_app(vec![db], 0);
        for c in "id_ed".chars() {
            app.handle_key(key(c));
        }
        let mut terminal = draw(&mut app, 100, 30);
        let text = screen_text(&terminal);
        assert!(text.contains("Delete key"), "{text}");
        assert!(
            text.contains("Delete the key 'id_ed25519_homelab'?"),
            "{text}"
        );
        assert!(text.contains("Used by: db"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("Type the key's name")
                && footer.contains("Enter delete")
                && footer.contains("Esc cancel"),
            "{footer}"
        );
        let cursor = terminal.get_cursor_position().unwrap();
        let row = text.lines().nth(usize::from(cursor.y)).unwrap();
        assert!(
            row.contains("> id_ed"),
            "the cursor is on the typing line: {row}"
        );
        let start = row.find("> id_ed").unwrap();
        assert_eq!(
            usize::from(cursor.x),
            row[..start].chars().count() + "> id_ed".len()
        );
    }

    #[test]
    fn on_the_smallest_terminal_the_question_keeps_the_warning_and_the_line_to_type_on() {
        for (select, used) in [(0, true), (1, false)] {
            let mut db = host("db", "192.0.2.2");
            if used {
                db.identity_file = Some("~/.ssh/id_ed25519_homelab".to_string());
            }
            let mut app = delete_app(vec![db], select);
            app.handle_key(key_of(KeyCode::Enter)); // a mismatch: the error line is there too
            let terminal = draw(&mut app, 60, 15);
            let text = screen_text(&terminal);
            assert!(text.contains("Type the key's name to confirm:"), "{text}");
            assert!(
                text.contains("Error: That is not the key's name."),
                "{text}"
            );
            assert!(text.contains("Bifrost cannot know which servers"), "{text}");
            assert!(
                text.contains("another key is installed."),
                "the whole warning: {text}"
            );
            for line in text.lines() {
                assert!(display_width(line) <= 60, "{line}");
            }
        }
    }

    #[test]
    fn a_key_name_and_what_is_typed_are_cleaned_and_the_footer_says_so() {
        let mut snapshot = typical();
        snapshot.keys[0].name = "evil\u{202e}key".to_string();
        let mut app = on_keys_with_hosts(vec![host("db", "192.0.2.2")], snapshot);
        app.handle_key(key('D'));
        for c in "ty\u{2066}ped".chars() {
            app.handle_key(key(c));
        }
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(
                !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                "{:?}",
                cell.symbol()
            );
        }
        assert!(
            flat(&screen_text(&terminal)).contains("non-printable characters were hidden"),
            "{}",
            screen_text(&terminal)
        );
    }

    #[test]
    fn the_result_of_deleting_is_shown_cleaned_like_every_message() {
        let mut app = on_keys_with_hosts(vec![host("db", "192.0.2.2")], typical());
        app.handle_response(
            &Request::DeleteKey {
                file_name: "x".to_string(),
            },
            Response::KeyDeleted(Err("boom \x1b[31m\u{202e}bad".to_string())),
        );
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(!cell.symbol().chars().any(crate::sanitize::is_unsafe_char));
        }
        assert!(screen_text(&terminal).contains("Error: boom"));
    }
}
