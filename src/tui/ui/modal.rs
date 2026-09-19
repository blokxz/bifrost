//! Small boxes drawn over a screen: the jump host list, the question about
//! discarding changes, and (later) the delete confirmation.

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};

use crate::tui::theme::Theme;
use crate::tui::wrap::display_width;

/// The rectangle a popup with `lines` of content occupies inside `area`: as wide
/// as its content needs (within limits), centered, and never larger than `area`.
pub(super) fn popup_area(area: Rect, lines: &[Line<'_>], title: &str) -> Rect {
    let content = lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or(0)
        .max(display_width(title));
    // Borders and padding take 4 columns and 2 rows.
    let wanted_width = u16::try_from(content + 4).unwrap_or(u16::MAX).max(32);
    let width = wanted_width.min(area.width.saturating_sub(2)).max(1);
    let wanted_height = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
    let height = wanted_height.min(area.height.saturating_sub(2)).max(1);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

/// Draws a popup with a title and returns the rectangle of its content.
pub(super) fn render_popup(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    theme: &Theme,
) -> Rect {
    let target = popup_area(area, &lines, title);
    let block = Block::bordered()
        .padding(Padding::horizontal(1))
        .title(Span::styled(format!(" {title} "), theme.title));
    let inner = block.inner(target);
    frame.render_widget(Clear, target);
    frame.render_widget(block, target);
    frame.render_widget(Paragraph::new(lines), inner);
    inner
}

/// Draws text across the whole width of `area`, with a line above and below it
/// but nothing at the sides and no padding, so that selecting it with the mouse
/// copies the text and nothing else.
pub(super) fn render_panel(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    theme: &Theme,
) {
    let wanted = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
    let height = wanted.min(area.height).max(1);
    let target = Rect {
        x: area.x,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width: area.width,
        height,
    };
    let block = Block::new()
        .borders(Borders::TOP | Borders::BOTTOM)
        .title(Span::styled(format!(" {title} "), theme.title));
    let inner = block.inner(target);
    frame.render_widget(Clear, target);
    frame.render_widget(block, target);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Puts the cursor inside `area` at `(column, row)`, clamped to it.
pub(super) fn place_cursor(frame: &mut Frame, area: Rect, column: usize, row: usize) {
    let x = area.x + u16::try_from(column).unwrap_or(u16::MAX);
    let y = area.y + u16::try_from(row).unwrap_or(u16::MAX);
    frame.set_cursor_position(Position::new(
        x.min(area.right().saturating_sub(1)),
        y.min(area.bottom().saturating_sub(1)),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_popup_is_centered_and_fits_its_content() {
        let area = Rect::new(0, 0, 80, 24);
        let lines = vec![Line::raw("hello"), Line::raw("world")];
        let popup = popup_area(area, &lines, "Title");
        assert_eq!(popup.height, 4);
        assert_eq!(
            popup.width, 32,
            "narrow content still gets a readable width"
        );
        assert_eq!(popup.x, (80 - 32) / 2);
        assert_eq!(popup.y, (24 - 4) / 2);
    }

    #[test]
    fn a_popup_grows_with_wide_content_but_stays_inside_the_screen() {
        let area = Rect::new(0, 0, 60, 15);
        let wide = vec![Line::raw("x".repeat(200))];
        let popup = popup_area(area, &wide, "T");
        assert_eq!(popup.width, 58);
        let tall: Vec<Line<'static>> = (0..50).map(|_| Line::raw("row")).collect();
        let popup = popup_area(area, &tall, "T");
        assert_eq!(popup.height, 13);
        assert!(popup.right() <= area.right() && popup.bottom() <= area.bottom());
    }

    #[test]
    fn a_tiny_area_does_not_underflow() {
        let popup = popup_area(Rect::new(0, 0, 1, 1), &[Line::raw("a")], "T");
        assert!(popup.width >= 1 && popup.height >= 1);
    }
}
