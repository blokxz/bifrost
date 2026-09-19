//! Color palette for the Bifrost TUI.
//!
//! Source of truth: `docs/ui/README.md` (Palette section). Widgets must take
//! every color from a [`Theme`]; never hardcode a `Color` in a widget.

use ratatui::style::{Color, Modifier, Style};

/// How many colors the terminal can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// 24-bit colors: the exact palette from the design.
    TrueColor,
    /// The 16 standard ANSI colors, mapped to the closest match.
    Ansi16,
    /// No colors at all (the user set `NO_COLOR`). Emphasis uses modifiers only.
    Monochrome,
}

impl ColorMode {
    /// Detects the color mode from the environment.
    ///
    /// - `NO_COLOR` set to any non-empty value → [`ColorMode::Monochrome`] (<https://no-color.org>).
    /// - `COLORTERM=truecolor|24bit` → [`ColorMode::TrueColor`].
    /// - `WT_SESSION` set (Windows Terminal, which does not set `COLORTERM`) → [`ColorMode::TrueColor`].
    /// - Anything else → [`ColorMode::Ansi16`].
    pub fn detect() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let colorterm = std::env::var("COLORTERM").ok();
        let windows_terminal = std::env::var_os("WT_SESSION").is_some();
        Self::from_env_values(no_color, colorterm.as_deref(), windows_terminal)
    }

    fn from_env_values(no_color: bool, colorterm: Option<&str>, windows_terminal: bool) -> Self {
        if no_color {
            return Self::Monochrome;
        }
        let truecolor = colorterm
            .is_some_and(|v| v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit"));
        if truecolor || windows_terminal {
            Self::TrueColor
        } else {
            Self::Ansi16
        }
    }
}

/// The resolved palette. Field names match the tokens in `docs/ui/README.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub mode: ColorMode,
    /// Screen background.
    pub bg: Color,
    /// Inset boxes (fingerprints, input line).
    pub bg_deep: Color,
    /// Default text.
    pub text: Color,
    /// Emphasis, selected row text.
    pub bright: Color,
    /// Labels, hints, secondary text.
    pub muted: Color,
    /// Background screen behind a modal.
    pub ghost: Color,
    /// Unfocused panel borders.
    pub border: Color,
    /// Selected row background.
    pub selection: Color,
    /// Key hint background.
    pub keycap: Color,
    /// Focus, primary actions, cursor.
    pub accent: Color,
    /// Tags, TOML sections.
    pub violet: Color,
    /// Warnings, favorites, jump hosts.
    pub amber: Color,
    /// Errors, danger, security alerts.
    pub red: Color,
    /// OK states, success.
    pub green: Color,
}

impl Theme {
    /// Builds the theme for the detected terminal.
    pub fn detect() -> Self {
        Self::new(ColorMode::detect())
    }

    pub fn new(mode: ColorMode) -> Self {
        match mode {
            ColorMode::TrueColor => Self::truecolor(),
            ColorMode::Ansi16 => Self::ansi16(),
            ColorMode::Monochrome => Self::monochrome(),
        }
    }

    fn truecolor() -> Self {
        Self {
            mode: ColorMode::TrueColor,
            bg: rgb(0x11131a),
            bg_deep: rgb(0x0b0d12),
            text: rgb(0xcdd3de),
            bright: rgb(0xf2f4f8),
            muted: rgb(0x7c8599),
            ghost: rgb(0x343a4a),
            border: rgb(0x2e3445),
            selection: rgb(0x1c2a33),
            keycap: rgb(0x262b38),
            accent: rgb(0x5fd7c3),
            violet: rgb(0xb39dfa),
            amber: rgb(0xf5c86b),
            red: rgb(0xff7a93),
            green: rgb(0x8bd67a),
        }
    }

    /// Backgrounds use `Reset` so the user's own terminal background shows through.
    fn ansi16() -> Self {
        Self {
            mode: ColorMode::Ansi16,
            bg: Color::Reset,
            bg_deep: Color::Reset,
            text: Color::Reset,
            bright: Color::White,
            muted: Color::DarkGray,
            ghost: Color::DarkGray,
            border: Color::DarkGray,
            selection: Color::DarkGray,
            keycap: Color::DarkGray,
            accent: Color::Cyan,
            violet: Color::Magenta,
            amber: Color::Yellow,
            red: Color::LightRed,
            green: Color::Green,
        }
    }

    fn monochrome() -> Self {
        Self {
            mode: ColorMode::Monochrome,
            bg: Color::Reset,
            bg_deep: Color::Reset,
            text: Color::Reset,
            bright: Color::Reset,
            muted: Color::Reset,
            ghost: Color::Reset,
            border: Color::Reset,
            selection: Color::Reset,
            keycap: Color::Reset,
            accent: Color::Reset,
            violet: Color::Reset,
            amber: Color::Reset,
            red: Color::Reset,
            green: Color::Reset,
        }
    }

    /// Base style for the whole screen.
    pub fn base(&self) -> Style {
        Style::new().fg(self.text).bg(self.bg)
    }

    /// Panel border: `accent` when focused, `border` otherwise.
    pub fn panel_border(&self, focused: bool) -> Style {
        let style = Style::new().fg(if focused { self.accent } else { self.border });
        if focused && self.mode == ColorMode::Monochrome {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    /// Panel title: `accent` when focused, `muted` otherwise.
    pub fn panel_title(&self, focused: bool) -> Style {
        let style = Style::new().fg(if focused { self.accent } else { self.muted });
        if focused && self.mode == ColorMode::Monochrome {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    /// Selected row in a list or table. Without colors it falls back to reversed video
    /// so the selection is still visible.
    pub fn selected_row(&self) -> Style {
        match self.mode {
            ColorMode::Monochrome => Style::new().add_modifier(Modifier::REVERSED),
            _ => Style::new().fg(self.bright).bg(self.selection),
        }
    }

    /// Key name in the footer hints (the "keycap").
    pub fn keycap(&self) -> Style {
        match self.mode {
            ColorMode::Monochrome => Style::new().add_modifier(Modifier::BOLD),
            _ => Style::new().fg(self.bright).bg(self.keycap),
        }
    }

    /// Label next to a keycap, and any secondary text.
    pub fn hint(&self) -> Style {
        Style::new().fg(self.muted)
    }

    /// Colors of the five letters "b", "i", "f", "r", "o" in the wordmark
    /// ("st" uses `bright`). Also used for the five segments of the launcher's rainbow line.
    pub fn wordmark(&self) -> [Color; 5] {
        [self.red, self.amber, self.green, self.accent, self.violet]
    }
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_colors(t: &Theme) -> [Color; 14] {
        [
            t.bg, t.bg_deep, t.text, t.bright, t.muted, t.ghost, t.border, t.selection,
            t.keycap, t.accent, t.violet, t.amber, t.red, t.green,
        ]
    }

    #[test]
    fn no_color_wins_over_everything() {
        assert_eq!(ColorMode::from_env_values(true, Some("truecolor"), true), ColorMode::Monochrome);
    }

    #[test]
    fn colorterm_truecolor_and_24bit_are_detected() {
        assert_eq!(ColorMode::from_env_values(false, Some("truecolor"), false), ColorMode::TrueColor);
        assert_eq!(ColorMode::from_env_values(false, Some("24BIT"), false), ColorMode::TrueColor);
    }

    #[test]
    fn windows_terminal_is_truecolor() {
        assert_eq!(ColorMode::from_env_values(false, None, true), ColorMode::TrueColor);
    }

    #[test]
    fn unknown_terminal_falls_back_to_ansi16() {
        assert_eq!(ColorMode::from_env_values(false, None, false), ColorMode::Ansi16);
        assert_eq!(ColorMode::from_env_values(false, Some("yes"), false), ColorMode::Ansi16);
    }

    #[test]
    fn truecolor_matches_the_documented_palette() {
        let t = Theme::new(ColorMode::TrueColor);
        assert_eq!(t.bg, Color::Rgb(0x11, 0x13, 0x1a));
        assert_eq!(t.accent, Color::Rgb(0x5f, 0xd7, 0xc3));
        assert_eq!(t.red, Color::Rgb(0xff, 0x7a, 0x93));
        assert_eq!(t.muted, Color::Rgb(0x7c, 0x85, 0x99));
    }

    #[test]
    fn ansi16_never_uses_rgb() {
        let t = Theme::new(ColorMode::Ansi16);
        assert!(all_colors(&t).iter().all(|c| !matches!(c, Color::Rgb(..))));
    }

    #[test]
    fn monochrome_uses_no_colors_but_keeps_selection_visible() {
        let t = Theme::new(ColorMode::Monochrome);
        assert!(all_colors(&t).iter().all(|c| *c == Color::Reset));
        assert!(t.selected_row().add_modifier.contains(Modifier::REVERSED));
    }
}
