//! The ssh config screen: what importing the user's ssh config would do, what it
//! did, and where an export writes and what the user still has to do about it.
//!
//! These are text pages, on the same layout as the others (a fixed header that
//! carries the question, and a scrolling body). Everything that came from outside
//! (host names, paths, what ssh made of a host, the reasons for skipping one, the
//! warnings) goes through [`Cleaner`] on the way in.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;

use super::page::{Page, draw};
use super::{Cleaner, labeled_lines, page_block};
use crate::domain::Host;
use crate::ssh::export::{INCLUDE_LINE, TargetState};
use crate::ssh::import::ImportReport;
use crate::ssh::scan::IncludeStatus;
use crate::tui::app::{App, Metrics};
use crate::tui::effects::{ExportDone, ExportPlan, ImportPreview};
use crate::tui::sshconfig::Stage;
use crate::tui::theme::Theme;
use crate::tui::wrap::wrap;

pub(super) fn render(app: &App, theme: &Theme, frame: &mut Frame, area: Rect) -> Metrics {
    let Some(screen) = app.sshconfig() else {
        return Metrics::default();
    };
    let width = usize::from(page_block().inner(area).width);
    let mut cleaner = Cleaner::default();
    let page = match screen.stage() {
        Stage::Menu => menu(app, theme, width, &mut cleaner),
        Stage::ImportPreview(preview) => import_page(preview, false, theme, width, &mut cleaner),
        Stage::Imported(preview) => import_page(preview, true, theme, width, &mut cleaner),
        Stage::ExportPlan { plan, hosts } => export_plan(plan, *hosts, theme, width, &mut cleaner),
        Stage::Exported { done, hosts } => {
            export_done(app, done, *hosts, theme, width, &mut cleaner)
        }
    };
    draw(page, cleaner, app, theme, frame, area)
}

/// A paragraph, wrapped.
fn text(paragraph: &str, width: usize, cleaner: &mut Cleaner) -> Vec<Line<'static>> {
    labeled_lines("", Style::new(), paragraph, width, cleaner)
}

/// A paragraph indented by two spaces.
fn indented(paragraph: &str, width: usize, cleaner: &mut Cleaner) -> Vec<Line<'static>> {
    wrap(&cleaner.clean(paragraph), width.saturating_sub(2).max(1))
        .into_iter()
        .map(|piece| Line::raw(format!("  {piece}")))
        .collect()
}

fn menu(app: &App, theme: &Theme, width: usize, cleaner: &mut Cleaner) -> Page {
    let count = app.hosts().map_or(0, |hosts| hosts.as_slice().len());
    let (config, export) = match app.ssh_dir() {
        Some(dir) => (
            dir.join("config").display().to_string(),
            dir.join(crate::ssh::export::EXPORT_FILE_NAME)
                .display()
                .to_string(),
        ),
        None => (
            "your ssh config".to_string(),
            "an ssh config file".to_string(),
        ),
    };
    let mut body = vec![Line::styled("Import", theme.title)];
    body.extend(indented(
        &format!(
            "Press i to read {config}, and the files it includes, and see which of its hosts \
             would be added. Nothing is saved until you confirm."
        ),
        width,
        cleaner,
    ));
    body.push(Line::raw(""));
    body.push(Line::styled("Export", theme.title));
    let hosts = if count == 1 {
        "your 1 host".to_string()
    } else {
        format!("your {count} hosts")
    };
    body.extend(indented(
        &format!(
            "Press e to write {hosts} to {export}, an ssh config file that ssh and other tools \
             can use. Your own ssh config is never edited."
        ),
        width,
        cleaner,
    ));
    Page {
        title: "SSH config".to_string(),
        header: vec![Line::raw("What do you want to do?"), Line::raw("")],
        body,
    }
}

/// Where a host is and what it uses, as one line of text.
fn describe(host: &Host) -> String {
    let mut place = host.hostname.clone();
    if let Some(user) = &host.user {
        place = format!("{user}@{place}");
    }
    if let Some(port) = host.port {
        place = format!("{place}:{port}");
    }
    let mut parts = vec![place];
    if let Some(jump) = &host.proxy_jump {
        parts.push(format!("via {jump}"));
    }
    if let Some(key) = &host.identity_file {
        parts.push(format!("key {key}"));
    }
    parts.join(", ")
}

fn counted(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// The lists shared by the preview and by what is shown after saving.
fn import_body(
    report: &ImportReport,
    done: bool,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Vec<Line<'static>> {
    let mut body: Vec<Line<'static>> = Vec::new();
    let section = |body: &mut Vec<Line<'static>>, title: String| {
        if !body.is_empty() {
            body.push(Line::raw(""));
        }
        body.push(Line::styled(title, theme.title));
    };

    if !report.imported.is_empty() {
        let title = if done {
            format!("Imported ({})", report.imported.len())
        } else {
            format!("Will be imported ({})", report.imported.len())
        };
        section(&mut body, title);
        for name in &report.imported {
            let described = report.hosts.get(name).map_or_else(String::new, describe);
            body.extend(indented(&format!("{name}: {described}"), width, cleaner));
        }
    }
    if !report.conflicts.is_empty() {
        section(
            &mut body,
            format!(
                "Already in Bifrost, left as they are ({})",
                report.conflicts.len()
            ),
        );
        body.extend(indented(&report.conflicts.join(", "), width, cleaner));
    }
    if !report.skipped.is_empty() {
        section(
            &mut body,
            format!("Skipped, and why ({})", report.skipped.len()),
        );
        // Hosts skipped for the same reason are one entry: when the import ran out
        // of time that is every host after some point, and the reason is a sentence.
        let mut groups: Vec<(Vec<&str>, &str)> = Vec::new();
        for skipped in &report.skipped {
            match groups
                .iter_mut()
                .find(|(_, reason)| *reason == skipped.reason)
            {
                Some((names, _)) => names.push(&skipped.name),
                None => groups.push((vec![&skipped.name], &skipped.reason)),
            }
        }
        for (names, reason) in groups {
            body.extend(indented(
                &format!("{}: {reason}", names.join(", ")),
                width,
                cleaner,
            ));
        }
    }
    if !report.warnings.is_empty() {
        section(&mut body, format!("Warnings ({})", report.warnings.len()));
        for warning in &report.warnings {
            body.extend(labeled_lines(
                "Warning:",
                theme.warning,
                warning.message(),
                width,
                cleaner,
            ));
        }
    }
    body
}

fn import_page(
    preview: &ImportPreview,
    done: bool,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Page {
    let report = &preview.report;
    let config = preview.config.display().to_string();
    let mut header: Vec<Line<'static>> = Vec::new();

    if !preview.config_exists {
        header.extend(text(
            &format!("There is no ssh config at {config}, so there is nothing to import."),
            width,
            cleaner,
        ));
        header.push(Line::raw(""));
        return Page {
            title: "Import from ssh config".to_string(),
            header,
            body: import_body(report, done, theme, width, cleaner),
        };
    }

    let imported = report.imported.len();
    let mut counts = vec![format!(
        "{} {}",
        counted(imported, "host", "hosts"),
        if done { "imported" } else { "to import" }
    )];
    if !report.conflicts.is_empty() {
        counts.push(format!("{} already in Bifrost", report.conflicts.len()));
    }
    if !report.skipped.is_empty() {
        counts.push(format!("{} skipped", report.skipped.len()));
    }
    header.extend(text(
        &format!("From {config}: {}.", counts.join(", ")),
        width,
        cleaner,
    ));
    let question = match (done, imported) {
        (true, _) => "Saved. Press Enter to go back.".to_string(),
        (false, 0) => "There is nothing to import.".to_string(),
        (false, 1) => {
            "Press y to import this host, or n to cancel. Nothing is saved yet.".to_string()
        }
        (false, n) => {
            format!("Press y to import these {n} hosts, or n to cancel. Nothing is saved yet.")
        }
    };
    header.extend(text(&question, width, cleaner));
    header.push(Line::raw(""));
    Page {
        title: if done {
            "Imported".to_string()
        } else {
            "Import from ssh config".to_string()
        },
        header,
        body: import_body(report, done, theme, width, cleaner),
    }
}

fn export_plan(
    plan: &ExportPlan,
    hosts: usize,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Page {
    let target = plan.target.display().to_string();
    let mut header = text(
        &format!("Write {} to {target}.", counted(hosts, "host", "hosts")),
        width,
        cleaner,
    );
    match plan.state {
        TargetState::Missing => header.extend(text(
            "The file does not exist yet, so it will be created.",
            width,
            cleaner,
        )),
        TargetState::Generated => header.extend(text(
            "The file was made by Bifrost, so it will be replaced.",
            width,
            cleaner,
        )),
        TargetState::NotGenerated => header.extend(labeled_lines(
            "Stop:",
            theme.error,
            "That file exists and Bifrost did not make it, so it will not be touched. Move it \
             away, or delete it yourself, and try again.",
            width,
            cleaner,
        )),
    }
    if plan.state != TargetState::NotGenerated {
        header.extend(text("Press y to write it, or n to cancel.", width, cleaner));
    }
    header.push(Line::raw(""));

    let mut body = vec![Line::styled("What is written", theme.title)];
    body.extend(indented(
        "For each host: its host name, user, port, key file (with IdentitiesOnly, so only \
         that key is offered), jump host, port forwards on localhost, and agent forwarding \
         when it is on.",
        width,
        cleaner,
    ));
    body.push(Line::raw(""));
    body.push(Line::styled("What is not", theme.title));
    body.extend(indented(
        "Notes, tags and favorites stay in Bifrost. Your own ssh config is not changed: \
         afterwards Bifrost shows the one line to add to it yourself.",
        width,
        cleaner,
    ));
    body.push(Line::raw(""));
    body.push(Line::styled("Good to know", theme.title));
    body.extend(indented(
        "A jump host is written with its address only. Its own key has to be in your ssh \
         agent, or be one of ssh's default keys. Hosts changed in Bifrost later are not \
         written until you export again.",
        width,
        cleaner,
    ));
    Page {
        title: "Export to ssh config".to_string(),
        header,
        body,
    }
}

fn export_done(
    app: &App,
    done: &ExportDone,
    hosts: usize,
    theme: &Theme,
    width: usize,
    cleaner: &mut Cleaner,
) -> Page {
    let target = done.target.display().to_string();
    let config = app.ssh_dir().map_or_else(
        || "your ssh config".to_string(),
        |dir| dir.join("config").display().to_string(),
    );
    let mut header = text(
        &format!(
            "Wrote {} to {target}. Press Enter to go back.",
            counted(hosts, "host", "hosts")
        ),
        width,
        cleaner,
    );
    header.push(Line::raw(""));

    // The one line to add, shown on a line of its own so that selecting it with
    // the mouse copies it and nothing else.
    let add = |lead: &str, width: usize, cleaner: &mut Cleaner| {
        let mut lines = text(lead, width, cleaner);
        lines.push(Line::raw(""));
        lines.push(Line::raw(INCLUDE_LINE));
        lines
    };
    let mut body = Vec::new();
    match &done.include {
        Ok(IncludeStatus::Found) => body.extend(text(
            &format!("{config} already includes it, so ssh uses these hosts. Nothing more to do."),
            width,
            cleaner,
        )),
        Ok(IncludeStatus::FoundInsideBlock) => {
            body.extend(labeled_lines(
                "Warning:",
                theme.warning,
                &format!(
                    "{config} includes it, but after a Host or Match line, so ssh only uses it \
                     for that block. Move this line to the very top of the file, before \
                     anything else:"
                ),
                width,
                cleaner,
            ));
            body.push(Line::raw(""));
            body.push(Line::raw(INCLUDE_LINE));
        }
        Ok(IncludeStatus::Missing) => body.extend(add(
            &format!(
                "To use these hosts with ssh, add this line at the very top of {config}, \
                 before any Host or Match line. Bifrost does not edit that file:"
            ),
            width,
            cleaner,
        )),
        Ok(IncludeStatus::NoConfigFile) => body.extend(add(
            &format!(
                "You have no ssh config yet. To use these hosts with ssh, create {config} \
                 with this as its first line. Bifrost does not create that file:"
            ),
            width,
            cleaner,
        )),
        Err(why) => {
            body.extend(labeled_lines(
                "Warning:",
                theme.warning,
                &format!(
                    "Bifrost could not tell whether your ssh config includes the file: {why} \
                     If it does not, add this line at the very top of {config}:"
                ),
                width,
                cleaner,
            ));
            body.push(Line::raw(""));
            body.push(Line::raw(INCLUDE_LINE));
        }
    }
    Page {
        title: "Exported".to_string(),
        header,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{app_with, draw, draw_with, host, screen_text, text_of};
    use super::*;
    use crate::domain::{Hosts, Warning};
    use crate::ssh::import::SkippedHost;
    use crate::tui::effects::{ExportDone, ExportPlan, ImportPreview, Request, Response};
    use crate::tui::wrap::display_width;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::path::PathBuf;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    /// Puts a piece of text into one field of a report.
    type Poison = fn(&mut ImportReport, &str);

    fn flat(text: &str) -> String {
        text.split_whitespace()
            .filter(|word| *word != "│")
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn ssh_dir() -> PathBuf {
        PathBuf::from("/home/dev/.ssh")
    }

    /// A file of the ssh directory as the screen writes it: joined by the system, so
    /// with `\` before the name on Windows. Only what the screen makes by joining
    /// needs this; a path that a test hands to the screen is shown as it was given.
    fn in_ssh_dir(name: &str) -> String {
        ssh_dir().join(name).display().to_string()
    }

    /// The screen with `hosts` saved and the ssh directory set.
    fn on_menu(hosts: Vec<Host>) -> App {
        let mut app = app_with(hosts, Vec::new());
        app.set_ssh_dir(Some(ssh_dir()));
        app.handle_key(key('s'));
        app
    }

    fn imported_host() -> Host {
        let mut app_host = host("app", "app.example.com");
        app_host.user = Some("deploy".to_string());
        app_host.port = Some(2222);
        app_host.identity_file = Some("~/.ssh/id_app".to_string());
        app_host.proxy_jump = Some("bastion".to_string());
        app_host
    }

    fn report(imported: Vec<Host>) -> ImportReport {
        let mut all = vec![host("web", "192.0.2.1"), host("bastion", "b.example.com")];
        let names = imported.iter().map(|h| h.name.clone()).collect();
        all.extend(imported);
        ImportReport {
            hosts: Hosts::from_vec(all).unwrap(),
            imported: names,
            conflicts: Vec::new(),
            skipped: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn with_preview(report: ImportReport, config_exists: bool) -> App {
        let mut app = on_menu(vec![host("web", "192.0.2.1")]);
        app.handle_key(key('i'));
        let request = app.take_request().unwrap();
        assert!(matches!(request, Request::PreviewImport { .. }));
        app.handle_response(
            &request,
            Response::ImportPreview(Ok(ImportPreview {
                config: PathBuf::from("/home/dev/.ssh/config"),
                config_exists,
                report,
            })),
        );
        app
    }

    fn full_report() -> ImportReport {
        let mut report = report(vec![imported_host()]);
        report.conflicts = vec!["web".to_string(), "bastion".to_string()];
        report.skipped = vec![SkippedHost {
            name: "caf\u{e9}".to_string(),
            reason: "Name may only contain letters, digits, '.', '_' and '-'.".to_string(),
        }];
        report.warnings = vec![Warning::new(
            "Host 'app': ProxyCommand was dropped. Bifrost only supports ProxyJump.",
        )];
        report
    }

    // ---- the menu ---------------------------------------------------------------

    #[test]
    fn the_menu_says_which_files_it_reads_and_writes_and_how_many_hosts() {
        let mut one = on_menu(vec![host("web", "192.0.2.1")]);
        let text = flat(&text_of(&mut one, 100, 24));
        for expected in [
            "Import".to_string(),
            format!(
                "Press i to read {}, and the files it includes",
                in_ssh_dir("config")
            ),
            "Nothing is saved until you confirm.".to_string(),
            "Export".to_string(),
            format!(
                "Press e to write your 1 host to {}",
                in_ssh_dir("bifrost_config")
            ),
            "Your own ssh config is never edited.".to_string(),
        ] {
            assert!(text.contains(&expected), "{expected}:\n{text}");
        }
        let mut many = on_menu(vec![host("a", "a.example"), host("b", "b.example")]);
        assert!(flat(&text_of(&mut many, 100, 24)).contains("write your 2 hosts to"));
        let footer = text_of(&mut one, 100, 24)
            .lines()
            .last()
            .unwrap()
            .to_string();
        assert!(
            footer.contains("i import") && footer.contains("e export"),
            "{footer}"
        );
    }

    #[test]
    fn without_a_home_directory_the_menu_does_not_pretend_to_know_the_paths() {
        let mut app = app_with(vec![host("web", "192.0.2.1")], Vec::new());
        app.handle_key(key('s'));
        let text = flat(&text_of(&mut app, 100, 24));
        assert!(text.contains("read your ssh config"), "{text}");
        assert!(
            text.contains("write your 1 host to an ssh config file"),
            "{text}"
        );
        assert!(!text.contains("/home/"), "{text}");
    }

    // ---- the import preview -----------------------------------------------------

    #[test]
    fn a_preview_shows_each_kind_of_outcome_and_asks_before_saving() {
        let mut app = with_preview(full_report(), true);
        let text = text_of(&mut app, 120, 36);
        let words = flat(&text);
        for expected in [
            "From /home/dev/.ssh/config: 1 host to import, 2 already in Bifrost, 1 skipped.",
            "Press y to import this host, or n to cancel. Nothing is saved yet.",
            "Will be imported (1)",
            "app: deploy@app.example.com:2222, via bastion, key ~/.ssh/id_app",
            "Already in Bifrost, left as they are (2)",
            "web, bastion",
            "Skipped, and why (1)",
            "café: Name may only contain letters, digits, '.', '_' and '-'.",
            "Warnings (1)",
            "Warning: Host 'app': ProxyCommand was dropped. Bifrost only supports ProxyJump.",
        ] {
            assert!(words.contains(expected), "{expected}:\n{text}");
        }
        let footer = text.lines().last().unwrap();
        assert!(
            footer.contains("y import") && footer.contains("n/Esc cancel"),
            "{footer}"
        );
    }

    #[test]
    fn several_hosts_are_counted_and_the_question_says_how_many() {
        let mut second = host("cache", "cache.example.com");
        second.user = None;
        let mut app = with_preview(report(vec![imported_host(), second]), true);
        let words = flat(&text_of(&mut app, 120, 36));
        assert!(words.contains("2 hosts to import"), "{words}");
        assert!(
            words.contains("Press y to import these 2 hosts, or n to cancel."),
            "{words}"
        );
        assert!(
            words.contains("cache: cache.example.com"),
            "a host with nothing set: {words}"
        );
    }

    #[test]
    fn a_preview_with_nothing_to_import_says_so_and_offers_no_yes() {
        let mut app = with_preview(report(Vec::new()), true);
        let text = text_of(&mut app, 120, 36);
        assert!(flat(&text).contains("0 hosts to import"), "{text}");
        assert!(
            flat(&text).contains("There is nothing to import."),
            "{text}"
        );
        assert!(!text.contains("Press y"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(!footer.contains("y import"), "{footer}");
        assert!(footer.contains("Esc back"), "{footer}");
    }

    #[test]
    fn a_missing_ssh_config_is_said_in_words_and_is_not_an_error() {
        let mut app = with_preview(report(Vec::new()), false);
        let text = text_of(&mut app, 120, 36);
        assert!(
            flat(&text).contains(
                "There is no ssh config at /home/dev/.ssh/config, so there is nothing to import."
            ),
            "{text}"
        );
        assert!(!text.contains("Error"), "{text}");
    }

    #[test]
    fn after_saving_the_page_says_what_was_imported_and_what_was_left_out() {
        let mut app = with_preview(full_report(), true);
        app.handle_key(key('y'));
        let text = text_of(&mut app, 120, 36);
        let words = flat(&text);
        for expected in [
            "1 host imported, 2 already in Bifrost, 1 skipped.",
            "Saved. Press Enter to go back.",
            "Imported (1)",
            "app: deploy@app.example.com:2222",
            "Skipped, and why (1)",
            "Warnings (1)",
        ] {
            assert!(words.contains(expected), "{expected}:\n{text}");
        }
        assert!(!words.contains("Will be imported"), "{text}");
        assert!(!words.contains("Press y"), "{text}");
        assert!(text.contains("Imported "), "the title: {text}");
    }

    // ---- the export -------------------------------------------------------------

    fn with_plan(state: TargetState, hosts: usize) -> App {
        let list: Vec<Host> = (0..hosts)
            .map(|n| host(&format!("h{n}"), &format!("10.0.0.{}", n + 1)))
            .collect();
        let mut app = on_menu(list);
        app.handle_key(key('e'));
        let request = app.take_request().unwrap();
        app.handle_response(
            &request,
            Response::ExportPlan(Ok(ExportPlan {
                target: PathBuf::from("/home/dev/.ssh/bifrost_config"),
                state,
            })),
        );
        app
    }

    #[test]
    fn the_export_plan_says_how_many_hosts_where_and_what_will_happen_to_the_file() {
        let cases = [
            (
                TargetState::Missing,
                "The file does not exist yet, so it will be created.",
            ),
            (
                TargetState::Generated,
                "The file was made by Bifrost, so it will be replaced.",
            ),
        ];
        for (state, said) in cases {
            let mut app = with_plan(state, 3);
            let text = text_of(&mut app, 120, 36);
            let words = flat(&text);
            for expected in [
                "Write 3 hosts to /home/dev/.ssh/bifrost_config.",
                said,
                "Press y to write it, or n to cancel.",
                "What is written",
                "What is not",
                "Notes, tags and favorites stay in Bifrost.",
                "Your own ssh config is not changed",
                "Its own key has to be in your ssh agent",
            ] {
                assert!(words.contains(expected), "{state:?} {expected}:\n{text}");
            }
            assert!(text.lines().last().unwrap().contains("y write the file"));
        }
        let mut single = with_plan(TargetState::Missing, 1);
        assert!(flat(&text_of(&mut single, 120, 36)).contains("Write 1 host to"));
    }

    #[test]
    fn a_file_that_bifrost_did_not_make_is_a_stop_and_never_asks_to_write() {
        let mut app = with_plan(TargetState::NotGenerated, 2);
        let text = text_of(&mut app, 120, 36);
        let words = flat(&text);
        assert!(
            words.contains(
                "Stop: That file exists and Bifrost did not make it, so it will not be touched."
            ),
            "{text}"
        );
        assert!(!text.contains("Press y to write it"), "{text}");
        let footer = text.lines().last().unwrap();
        assert!(!footer.contains("write the file"), "{footer}");
    }

    fn with_done(include: Result<IncludeStatus, String>) -> App {
        let mut app = with_plan(TargetState::Missing, 2);
        app.handle_key(key('y'));
        let request = app.take_request().unwrap();
        app.handle_response(
            &request,
            Response::Exported(Ok(ExportDone {
                target: PathBuf::from("/home/dev/.ssh/bifrost_config"),
                include,
            })),
        );
        app
    }

    /// How many screen lines are exactly the include line, and nothing else.
    fn include_lines(text: &str) -> usize {
        text.lines()
            .filter(|line| {
                line.trim_matches(|c: char| c == '│' || c.is_whitespace()) == INCLUDE_LINE
                    && line.contains(&format!("│ {INCLUDE_LINE}"))
            })
            .count()
    }

    #[test]
    fn a_missing_include_is_shown_as_the_exact_line_to_add_on_a_line_of_its_own() {
        let mut app = with_done(Ok(IncludeStatus::Missing));
        let text = text_of(&mut app, 100, 30);
        let words = flat(&text);
        assert!(
            words.contains("Wrote 2 hosts to /home/dev/.ssh/bifrost_config."),
            "{text}"
        );
        assert!(
            words.contains(&format!(
                "add this line at the very top of {}, before any Host or Match line.",
                in_ssh_dir("config")
            )),
            "{text}"
        );
        assert!(words.contains("Bifrost does not edit that file"), "{text}");
        assert_eq!(include_lines(&text), 1, "the line, once, alone:\n{text}");
        assert_eq!(INCLUDE_LINE, "Include ~/.ssh/bifrost_config");
    }

    #[test]
    fn with_no_ssh_config_at_all_it_says_to_create_one_and_that_bifrost_will_not() {
        let mut app = with_done(Ok(IncludeStatus::NoConfigFile));
        let text = text_of(&mut app, 100, 30);
        let words = flat(&text);
        assert!(words.contains("You have no ssh config yet."), "{text}");
        assert!(
            words.contains(&format!(
                "create {} with this as its first line.",
                in_ssh_dir("config")
            )),
            "{text}"
        );
        assert!(
            words.contains("Bifrost does not create that file"),
            "{text}"
        );
        assert_eq!(include_lines(&text), 1, "{text}");
    }

    #[test]
    fn an_include_that_is_already_there_says_nothing_more_is_needed() {
        let mut app = with_done(Ok(IncludeStatus::Found));
        let text = text_of(&mut app, 100, 30);
        assert!(
            flat(&text).contains(&format!(
                "{} already includes it, so ssh uses these hosts.",
                in_ssh_dir("config")
            )),
            "{text}"
        );
        assert_eq!(include_lines(&text), 0, "no line to add: {text}");
    }

    #[test]
    fn an_include_after_a_host_line_is_a_warning_with_the_line_to_move() {
        let mut app = with_done(Ok(IncludeStatus::FoundInsideBlock));
        let text = text_of(&mut app, 100, 30);
        let words = flat(&text);
        assert!(
            words.contains(&format!(
                "Warning: {} includes it, but after a Host or Match line",
                in_ssh_dir("config")
            )),
            "{text}"
        );
        assert!(
            words.contains("Move this line to the very top of the file"),
            "{text}"
        );
        assert_eq!(include_lines(&text), 1, "{text}");
    }

    #[test]
    fn when_the_include_could_not_be_checked_it_says_why_and_still_shows_the_line() {
        let mut app = with_done(Err(
            "Could not read /home/dev/.ssh/config: denied".to_string()
        ));
        let text = text_of(&mut app, 100, 30);
        let words = flat(&text);
        assert!(
            words.contains(
                "Warning: Bifrost could not tell whether your ssh config includes the file"
            ),
            "{text}"
        );
        assert!(words.contains("denied"), "{text}");
        assert_eq!(include_lines(&text), 1, "{text}");
    }

    // ---- outside text, and small terminals --------------------------------------

    #[test]
    fn everything_from_outside_is_cleaned_and_the_footer_says_so() {
        // One hostile field at a time. Together they would hide each other: the
        // footer's note appears if any one of them was cleaned, and the terminal
        // drops control characters by itself, so neither says which was.
        let hostile = "evil\x1b]0;pwned\x07 \u{202e}text";
        let sources: [(&str, Poison); 4] = [
            ("a skipped name", |r, text| {
                r.skipped = vec![SkippedHost {
                    name: text.to_string(),
                    reason: "no".to_string(),
                }];
            }),
            ("a skipped reason", |r, text| {
                r.skipped = vec![SkippedHost {
                    name: "bad".to_string(),
                    reason: text.to_string(),
                }];
            }),
            ("a name already in Bifrost", |r, text| {
                r.conflicts = vec![text.to_string()];
            }),
            ("a warning", |r, text| {
                r.warnings = vec![Warning::new(text)];
            }),
        ];
        for (what, set) in sources {
            let mut report = report(vec![imported_host()]);
            set(&mut report, hostile);
            let mut app = with_preview(report, true);
            let terminal = draw(&mut app, 120, 36);
            for cell in terminal.backend().buffer().content() {
                assert!(
                    !cell.symbol().chars().any(crate::sanitize::is_unsafe_char),
                    "{what}: {:?}",
                    cell.symbol()
                );
            }
            let text = screen_text(&terminal);
            assert!(
                text.contains("evil"),
                "{what}: still shown, cleaned:\n{text}"
            );
            assert!(
                flat(&text).contains("non-printable characters were hidden"),
                "{what}: the footer says so:\n{text}"
            );
        }
    }

    #[test]
    fn a_path_from_outside_in_the_export_pages_is_cleaned_too() {
        let mut app = on_menu(vec![host("web", "192.0.2.1")]);
        app.set_ssh_dir(Some(PathBuf::from("/home/ev\x1b[31mil\u{202e}/.ssh")));
        app.handle_key(key('e'));
        let request = app.take_request().unwrap();
        app.handle_response(
            &request,
            Response::ExportPlan(Ok(ExportPlan {
                target: PathBuf::from("/home/ev\x1b[31mil\u{202e}/.ssh/bifrost_config"),
                state: TargetState::Missing,
            })),
        );
        let terminal = draw(&mut app, 100, 30);
        for cell in terminal.backend().buffer().content() {
            assert!(!cell.symbol().chars().any(crate::sanitize::is_unsafe_char));
        }
        assert!(
            flat(&screen_text(&terminal)).contains("non-printable characters were hidden"),
            "the path was cleaned, and the footer says so"
        );
    }

    #[test]
    fn on_the_smallest_terminal_every_step_keeps_its_question_and_fits() {
        // The preview: the question is in the fixed header, so it is never
        // scrolled away, however long the lists below are.
        let mut long = report(vec![imported_host()]);
        long.conflicts = (0..40).map(|n| format!("existing{n}")).collect();
        let mut app = with_preview(long, true);
        let mut terminal = draw(&mut app, 60, 15);
        let text = screen_text(&terminal);
        assert!(
            flat(&text).contains("Press y to import this host"),
            "{text}"
        );
        assert!(
            text.contains("lines 1-"),
            "it scrolls and says where: {text}"
        );
        for line in text.lines() {
            assert!(display_width(line) <= 60, "{line}");
        }
        // The export plan and the include line.
        let mut plan = with_plan(TargetState::Generated, 3);
        terminal = draw(&mut plan, 60, 15);
        assert!(flat(&screen_text(&terminal)).contains("Press y to write it, or n to cancel."));
        let mut done = with_done(Ok(IncludeStatus::Missing));
        let text = text_of(&mut done, 60, 15);
        assert_eq!(include_lines(&text), 1, "{text}");
        assert!(
            flat(&text).contains("Bifrost does not edit that file"),
            "{text}"
        );
    }

    #[test]
    fn a_long_preview_scrolls_to_its_end_and_the_position_says_so() {
        let mut long = report(vec![imported_host()]);
        long.conflicts = (0..40).map(|n| format!("existing{n}")).collect();
        let mut app = with_preview(long, true);
        // Drawing reports the limit back, as the event loop does.
        draw(&mut app, 60, 15);
        for _ in 0..200 {
            app.handle_key(key('j'));
            draw(&mut app, 60, 15);
        }
        let text = text_of(&mut app, 60, 15);
        assert!(text.contains("of "), "{text}");
        assert!(text.contains("existing39"), "the end is reachable:\n{text}");
        assert!(
            flat(&text).contains("Press y to import"),
            "the question stays:\n{text}"
        );
    }

    #[test]
    fn the_meaning_does_not_depend_on_color() {
        let mut app = with_preview(full_report(), true);
        let plain = draw_with(&mut app, &Theme::plain(), 120, 36).0;
        let text = screen_text(&plain);
        assert!(
            text.contains("Warning:") && text.contains("Will be imported"),
            "{text}"
        );
        let mut stop = with_plan(TargetState::NotGenerated, 1);
        let plain = draw_with(&mut stop, &Theme::plain(), 120, 36).0;
        assert!(screen_text(&plain).contains("Stop:"));
    }

    #[test]
    fn at_120x36_and_100x30_every_step_fits() {
        for (width, height) in [(120, 36), (100, 30), (80, 24)] {
            let mut menu = on_menu(vec![host("web", "192.0.2.1")]);
            let mut preview = with_preview(full_report(), true);
            let mut plan = with_plan(TargetState::Missing, 2);
            let mut done = with_done(Ok(IncludeStatus::Missing));
            for app in [&mut menu, &mut preview, &mut plan, &mut done] {
                let text = text_of(app, width, height);
                for line in text.lines() {
                    assert!(display_width(line) <= usize::from(width), "{line}");
                }
                assert!(text.lines().count() <= usize::from(height));
            }
        }
    }

    #[test]
    fn hosts_skipped_for_the_same_reason_are_one_entry_and_the_count_is_of_hosts() {
        let mut report = report(vec![imported_host()]);
        let out_of_time = "the import was taking too long, so the remaining hosts were not read.";
        report.skipped = ["h1", "h2", "h3"]
            .iter()
            .map(|name| SkippedHost {
                name: (*name).to_string(),
                reason: out_of_time.to_string(),
            })
            .chain([
                SkippedHost {
                    name: "café".to_string(),
                    reason: "Name may only contain letters.".to_string(),
                },
                SkippedHost {
                    name: "h4".to_string(),
                    reason: out_of_time.to_string(),
                },
            ])
            .collect();
        let mut app = with_preview(report, true);
        let text = text_of(&mut app, 120, 36);
        let words = flat(&text);
        assert!(
            words.contains("Skipped, and why (5)"),
            "hosts, not entries:\n{text}"
        );
        assert!(words.contains("5 skipped."), "{text}");
        assert!(
            words.contains(&format!("h1, h2, h3, h4: {out_of_time}")),
            "one entry, in the order they came:\n{text}"
        );
        assert_eq!(
            text.matches("the import was taking too long").count(),
            1,
            "said once:\n{text}"
        );
        assert!(
            words.contains("café: Name may only contain letters."),
            "another reason stays its own:\n{text}"
        );
    }

    #[test]
    fn a_single_skipped_host_reads_as_it_always_did() {
        let mut report = report(vec![imported_host()]);
        report.skipped = vec![SkippedHost {
            name: "broken".to_string(),
            reason: "ssh -G failed: no".to_string(),
        }];
        let mut app = with_preview(report, true);
        assert!(flat(&text_of(&mut app, 120, 36)).contains("broken: ssh -G failed: no"));
    }
}
