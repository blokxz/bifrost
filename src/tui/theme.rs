//! Colors and text styles.
//!
//! There is a single theme, built from the terminal's 16 ANSI colors so it
//! follows the user's own palette. With `NO_COLOR` set, the same theme is used
//! without any color. Color is never the only carrier of meaning: errors and
//! warnings also start with a text label, and emphasis uses bold and reverse
//! video, which survive without color.

use ratatui::style::{Color, Modifier, Style};

use crate::sysenv::{Env, non_empty};

/// The styles the screens draw with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Theme {
    /// Screen titles.
    pub title: Style,
    /// The `Error:` label.
    pub error: Style,
    /// The `Warning:` label.
    pub warning: Style,
    /// Key names in the footer and in the help.
    pub key: Style,
    /// Secondary text such as scroll positions.
    pub muted: Style,
}

impl Theme {
    /// The default theme, using the 16 ANSI colors.
    pub fn ansi16() -> Self {
        Theme {
            title: Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            error: Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            warning: Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            key: Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
            muted: Style::new().fg(Color::DarkGray),
        }
    }

    /// The same theme with no color at all, for `NO_COLOR`.
    pub fn plain() -> Self {
        Theme {
            title: Style::new().add_modifier(Modifier::BOLD),
            error: Style::new().add_modifier(Modifier::BOLD),
            warning: Style::new().add_modifier(Modifier::BOLD),
            key: Style::new().add_modifier(Modifier::BOLD),
            muted: Style::new().add_modifier(Modifier::DIM),
        }
    }

    /// Picks the theme for an environment: [`Theme::plain`] when `NO_COLOR` is
    /// set to a non-empty value (see <https://no-color.org>), otherwise
    /// [`Theme::ansi16`].
    pub fn from_env(env: Env<'_>) -> Self {
        if non_empty(env, "NO_COLOR").is_some() {
            Theme::plain()
        } else {
            Theme::ansi16()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysenv::testing::fake_env;
    use std::ffi::OsString;

    fn styles(theme: &Theme) -> [Style; 5] {
        [
            theme.title,
            theme.error,
            theme.warning,
            theme.key,
            theme.muted,
        ]
    }

    #[test]
    fn ansi_theme_uses_colors() {
        assert!(styles(&Theme::ansi16()).iter().any(|s| s.fg.is_some()));
    }

    #[test]
    fn plain_theme_has_no_colors() {
        for style in styles(&Theme::plain()) {
            assert_eq!(style.fg, None);
            assert_eq!(style.bg, None);
            assert_eq!(style.underline_color, None);
        }
    }

    #[test]
    fn plain_theme_still_distinguishes_emphasis_without_color() {
        let theme = Theme::plain();
        assert!(theme.error.add_modifier.contains(Modifier::BOLD));
        assert!(theme.muted.add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn no_color_selects_the_plain_theme() {
        let env = fake_env(&[("NO_COLOR", OsString::from("1"))]);
        assert_eq!(Theme::from_env(&env), Theme::plain());
    }

    #[test]
    fn empty_or_missing_no_color_keeps_the_colors() {
        let empty = fake_env(&[("NO_COLOR", OsString::new())]);
        assert_eq!(Theme::from_env(&empty), Theme::ansi16());
        let missing = fake_env(&[]);
        assert_eq!(Theme::from_env(&missing), Theme::ansi16());
    }
}
