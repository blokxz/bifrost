//! The event loop: one thread, draw then wait for input.

use std::io;
use std::time::Duration;

use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::crossterm::event::{self, Event, KeyEvent, KeyEventKind};

use super::app::{App, Metrics};
use super::theme::Theme;
use super::ui;

/// How long to wait for input before drawing again.
///
/// A timeout is not an idle no-op: redrawing picks up a terminal resize that a
/// platform failed to report as an event.
pub const TICK: Duration = Duration::from_millis(250);

/// The key press inside an event, if it is one.
///
/// Windows reports a press and a release for every key (and some terminals also
/// report repeats), so anything but a press is dropped to avoid acting twice.
pub fn key_press(event: &Event) -> Option<KeyEvent> {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => Some(*key),
        _ => None,
    }
}

/// Waits up to `timeout` for a terminal event, using crossterm.
pub fn next_crossterm_event(timeout: Duration) -> io::Result<Option<Event>> {
    if event::poll(timeout)? {
        event::read().map(Some)
    } else {
        Ok(None)
    }
}

/// Runs until the app asks to quit.
///
/// `next_event` waits up to the given duration and returns the event that
/// arrived, or `None` on timeout. `copy` asks the terminal to copy some text
/// (see [`super::clipboard`]). Both are parameters so tests can script input
/// and record what would be copied.
pub fn run_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    theme: &Theme,
    mut next_event: impl FnMut(Duration) -> io::Result<Option<Event>>,
    mut copy: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    while !app.should_quit() {
        let mut metrics = Metrics::default();
        terminal
            .draw(|frame| metrics = ui::render(app, theme, frame))
            .map_err(|err| io::Error::other(err.to_string()))?;
        app.apply_metrics(metrics);

        let event = next_event(TICK)?;
        if let Some(key) = event.as_ref().and_then(key_press) {
            app.handle_key(key);
            if let Some(text) = app.take_copy_request() {
                copy(&text)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Hosts;
    use crate::tui::app::Screen;
    use crate::tui::persist::testing::FakeStore;
    use crate::tui::startup::Startup;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyModifiers, MouseEvent, MouseEventKind};
    use std::collections::VecDeque;

    fn key_event(code: KeyCode, kind: KeyEventKind) -> Event {
        Event::Key(KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind))
    }

    fn press(c: char) -> Event {
        key_event(KeyCode::Char(c), KeyEventKind::Press)
    }

    #[test]
    fn only_presses_are_key_presses() {
        assert!(key_press(&key_event(KeyCode::Char('q'), KeyEventKind::Press)).is_some());
        assert!(key_press(&key_event(KeyCode::Char('q'), KeyEventKind::Release)).is_none());
        assert!(key_press(&key_event(KeyCode::Char('q'), KeyEventKind::Repeat)).is_none());
    }

    #[test]
    fn other_events_are_not_key_presses() {
        assert!(key_press(&Event::Resize(80, 24)).is_none());
        assert!(key_press(&Event::FocusGained).is_none());
        assert!(key_press(&Event::Paste("q".to_string())).is_none());
        let mouse = Event::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert!(key_press(&mouse).is_none());
    }

    /// Runs the loop on a test terminal, feeding it `script`. When the script
    /// runs out the source fails, so a loop that should have stopped by then
    /// but did not shows up as an error instead of hanging.
    fn run(script: Vec<Option<Event>>) -> (io::Result<()>, App) {
        let mut app = App::new(Startup::loaded(
            Hosts::new(),
            FakeStore::default(),
            Vec::new(),
        ));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut script: VecDeque<_> = script.into();
        let result = run_loop(
            &mut terminal,
            &mut app,
            &Theme::ansi16(),
            |_| {
                script
                    .pop_front()
                    .ok_or_else(|| io::Error::other("script exhausted"))
            },
            |_| Ok(()),
        );
        (result, app)
    }

    #[test]
    fn a_press_of_q_ends_the_loop() {
        let (result, app) = run(vec![Some(press('q'))]);
        result.unwrap();
        assert!(app.should_quit());
    }

    #[test]
    fn a_release_of_q_does_not_end_the_loop() {
        let release = key_event(KeyCode::Char('q'), KeyEventKind::Release);
        let (result, app) = run(vec![Some(release)]);
        assert_eq!(result.unwrap_err().to_string(), "script exhausted");
        assert!(!app.should_quit());
    }

    #[test]
    fn a_press_and_release_pair_acts_once() {
        // On Windows '?' arrives as press then release: help must open, not
        // open and immediately close again.
        let script = vec![
            Some(press('?')),
            Some(key_event(KeyCode::Char('?'), KeyEventKind::Release)),
            Some(press('q')),
        ];
        let (result, app) = run(script);
        result.unwrap();
        assert_eq!(app.screen(), Screen::Help);
    }

    #[test]
    fn timeouts_and_resizes_keep_the_loop_running() {
        let script = vec![None, Some(Event::Resize(100, 30)), None, Some(press('q'))];
        let (result, app) = run(script);
        result.unwrap();
        assert!(app.should_quit());
    }

    #[test]
    fn keys_are_routed_to_the_app_between_draws() {
        let script = vec![
            Some(press('?')),
            Some(press('?')),
            Some(press('?')),
            Some(press('q')),
        ];
        let (result, app) = run(script);
        result.unwrap();
        assert_eq!(app.screen(), Screen::Help);
    }

    #[test]
    fn an_event_source_error_stops_the_loop() {
        let (result, _) = run(Vec::new());
        assert_eq!(result.unwrap_err().to_string(), "script exhausted");
    }

    #[test]
    fn the_loop_reports_the_scroll_limit_back_to_the_app() {
        let mut app = App::new(Startup::loaded(
            Hosts::new(),
            FakeStore::default(),
            Vec::new(),
        ));
        let mut terminal = Terminal::new(TestBackend::new(60, 15)).unwrap();
        // Open the help, which is longer than the screen, and scroll far past
        // its end. Without the limit fed back after each draw this would end
        // at 100.
        let mut script: VecDeque<_> = std::iter::once(Some(press('?')))
            .chain((0..100).map(|_| Some(press('j'))))
            .chain([Some(press('q'))])
            .collect();
        run_loop(
            &mut terminal,
            &mut app,
            &Theme::ansi16(),
            |_| Ok(script.pop_front().unwrap()),
            |_| Ok(()),
        )
        .unwrap();
        assert!(app.scroll() > 0, "the help scrolled");
        assert!(
            app.scroll() < 100,
            "but stopped at its end: {}",
            app.scroll()
        );
    }

    #[test]
    fn the_loop_reports_the_number_of_visible_rows_to_the_list() {
        use crate::domain::Host;
        let hosts = Hosts::from_vec(
            (0..40)
                .map(|n| Host::new(format!("host-{n:02}"), "192.0.2.1"))
                .collect(),
        )
        .unwrap();
        let mut app = App::new(Startup::loaded(hosts, FakeStore::default(), Vec::new()));
        let mut terminal = Terminal::new(TestBackend::new(60, 15)).unwrap();
        let mut script: VecDeque<_> = [
            Some(key_event(KeyCode::PageDown, KeyEventKind::Press)),
            Some(press('q')),
        ]
        .into();
        run_loop(
            &mut terminal,
            &mut app,
            &Theme::ansi16(),
            |_| Ok(script.pop_front().unwrap()),
            |_| Ok(()),
        )
        .unwrap();
        // One screenful down: more than one row, fewer than all of them.
        let selected = app.list().selected.clone().unwrap();
        let row: usize = selected.trim_start_matches("host-").parse().unwrap();
        assert!((2..20).contains(&row), "{selected}");
    }

    #[test]
    fn a_copy_request_reaches_the_copy_hook_once_and_only_for_key_presses() {
        use crate::domain::Host;
        let mut web = Host::new("web", "web.example.com");
        web.user = Some("deploy".to_string());
        let hosts = Hosts::from_vec(vec![web]).unwrap();
        let mut app = App::new(Startup::loaded(hosts, FakeStore::default(), Vec::new()));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut script: VecDeque<_> = [
            // A release of `c` is not a key press: nothing happens.
            Some(key_event(KeyCode::Char('c'), KeyEventKind::Release)),
            Some(press('c')),
            Some(press('x')),
            Some(press('q')),
        ]
        .into();
        let mut copied = Vec::new();
        run_loop(
            &mut terminal,
            &mut app,
            &Theme::ansi16(),
            |_| Ok(script.pop_front().unwrap()),
            |text| {
                copied.push(text.to_string());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(copied, ["ssh -l deploy -- web.example.com"]);
    }

    #[test]
    fn a_failing_copy_hook_stops_the_loop_with_its_error() {
        use crate::domain::Host;
        let hosts = Hosts::from_vec(vec![Host::new("web", "web.example.com")]).unwrap();
        let mut app = App::new(Startup::loaded(hosts, FakeStore::default(), Vec::new()));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut script: VecDeque<_> = [Some(press('c'))].into();
        let result = run_loop(
            &mut terminal,
            &mut app,
            &Theme::ansi16(),
            |_| Ok(script.pop_front().unwrap()),
            |_| Err(io::Error::other("terminal gone")),
        );
        assert_eq!(result.unwrap_err().to_string(), "terminal gone");
    }
}
