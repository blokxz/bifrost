//! Neutralizes control characters in external text before it is shown.
//!
//! Host names, imported data, file paths, ssh output and store error messages
//! can all carry characters that a terminal interprets instead of displaying:
//! escape sequences that move the cursor, rewrite earlier output or set the
//! window title, and Unicode bidirectional controls that make text read in a
//! different order than it is stored. Everything external that the TUI renders
//! or the CLI prints goes through this module.
//!
//! The classification lives in [`is_unsafe_char`] so that every consumer agrees
//! on it; [`crate::text::escape_control`] reuses it for library error messages.

use std::borrow::Cow;

/// What each unsafe character is replaced with. Plain ASCII so it renders
/// reliably on the Windows console and on basic terminals.
pub const PLACEHOLDER: char = '?';

/// Whether a character must not reach a terminal as-is.
///
/// This covers the C0 controls (including ESC, newline and tab), DEL, the C1
/// controls (U+0080 to U+009F) and the Unicode bidirectional controls:
/// U+202A to U+202E, U+2066 to U+2069, U+200E, U+200F and U+061C.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control() || is_bidi_control(c)
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// Whether [`sanitize`] would change `input`.
pub fn has_unsafe_chars(input: &str) -> bool {
    input.chars().any(is_unsafe_char)
}

/// Replaces every unsafe character with [`PLACEHOLDER`].
///
/// Newlines and tabs are replaced too: this is for single-line text. Use
/// [`sanitize_lines`] for text that legitimately spans several lines.
pub fn sanitize(input: &str) -> Cow<'_, str> {
    if !has_unsafe_chars(input) {
        return Cow::Borrowed(input);
    }
    Cow::Owned(
        input
            .chars()
            .map(|c| if is_unsafe_char(c) { PLACEHOLDER } else { c })
            .collect(),
    )
}

/// Sanitizes each line of multi-line text and joins them with `\n`.
///
/// Line breaks (`\n` or `\r\n`) are kept as line breaks; any other unsafe
/// character, including a lone `\r`, is replaced. The result has no trailing
/// newline.
pub fn sanitize_lines(input: &str) -> String {
    input.lines().map(sanitize).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every character of `chars` must be replaced by exactly one placeholder.
    fn assert_all_replaced(chars: impl IntoIterator<Item = char>) {
        for c in chars {
            assert!(is_unsafe_char(c), "U+{:04X} should be unsafe", u32::from(c));
            let input = format!("a{c}b");
            assert_eq!(
                sanitize(&input),
                "a?b",
                "U+{:04X} should be replaced",
                u32::from(c)
            );
        }
    }

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        for text in ["", "web-01.example.com", "ünïcödé 日本語 🦀", "with spaces"] {
            assert!(matches!(sanitize(text), Cow::Borrowed(_)), "{text:?}");
            assert_eq!(sanitize(text), text);
            assert!(!has_unsafe_chars(text));
        }
    }

    #[test]
    fn c0_controls_are_replaced() {
        assert_all_replaced('\u{00}'..='\u{1F}');
    }

    #[test]
    fn escape_sequences_are_defused() {
        // The ESC is gone, so the rest is inert text.
        assert_eq!(sanitize("\x1b[31mred\x1b[0m"), "?[31mred?[0m");
        assert_eq!(sanitize("\x1b]0;evil title\x07"), "?]0;evil title?");
    }

    #[test]
    fn del_is_replaced() {
        assert_all_replaced(['\u{7F}']);
    }

    #[test]
    fn c1_controls_are_replaced() {
        assert_all_replaced('\u{80}'..='\u{9F}');
    }

    #[test]
    fn bidi_controls_are_replaced() {
        let bidi = ('\u{202A}'..='\u{202E}')
            .chain('\u{2066}'..='\u{2069}')
            .chain(['\u{200E}', '\u{200F}', '\u{061C}']);
        assert_all_replaced(bidi);
    }

    #[test]
    fn bidi_spoofing_is_visible() {
        // "gpj.exe" displayed as "exe.jpg" by a right-to-left override.
        assert_eq!(sanitize("evil\u{202E}gpj.exe"), "evil?gpj.exe");
    }

    #[test]
    fn neighbours_of_the_bidi_ranges_are_left_alone() {
        for c in [
            '\u{2029}', '\u{202F}', '\u{2065}', '\u{206A}', '\u{200D}', '\u{0620}',
        ] {
            assert!(
                !is_unsafe_char(c),
                "U+{:04X} is not a bidi control",
                u32::from(c)
            );
        }
    }

    #[test]
    fn newline_and_tab_are_replaced_in_single_line_text() {
        assert_eq!(sanitize("a\nb\tc\r"), "a?b?c?");
    }

    #[test]
    fn sanitize_lines_keeps_line_breaks_and_sanitizes_each_line() {
        assert_eq!(
            sanitize_lines("one\ntwo\x1b[2J\nthree"),
            "one\ntwo?[2J\nthree"
        );
        assert_eq!(sanitize_lines("crlf\r\nline"), "crlf\nline");
        assert_eq!(sanitize_lines("lone\rreturn"), "lone?return");
        assert_eq!(sanitize_lines("trailing\n"), "trailing");
        assert_eq!(sanitize_lines(""), "");
    }
}
