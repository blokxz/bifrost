//! Small text helpers.

use crate::sanitize::is_unsafe_char;

/// Escapes control characters so external text can be embedded in a message.
///
/// `"a\nb"` becomes `a\nb` (backslash, `n`) and ESC becomes `\u{1b}`. The
/// characters escaped are the ones [`crate::sanitize`] hides in the TUI: C0, C1,
/// DEL and the Unicode bidirectional controls, so a right-to-left override in a
/// host name cannot reorder an error message either.
pub fn escape_control(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if is_unsafe_char(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_characters_only() {
        assert_eq!(escape_control("plain host"), "plain host");
        assert_eq!(escape_control("a\nb"), "a\\nb");
        assert_eq!(escape_control("\x1b[31m"), "\\u{1b}[31m");
        assert_eq!(escape_control("tab\there"), "tab\\there");
    }

    #[test]
    fn escapes_c1_and_del() {
        assert_eq!(escape_control("a\u{85}b\u{7f}"), "a\\u{85}b\\u{7f}");
    }

    #[test]
    fn escapes_bidi_controls() {
        assert_eq!(
            escape_control("evil\u{202e}gpj.exe"),
            "evil\\u{202e}gpj.exe"
        );
        for c in [
            '\u{202a}', '\u{2066}', '\u{2069}', '\u{200e}', '\u{200f}', '\u{061c}',
        ] {
            let escaped = escape_control(&c.to_string());
            assert!(escaped.is_ascii(), "U+{:04X} left unescaped", u32::from(c));
            assert!(escaped.starts_with("\\u{"));
        }
    }

    #[test]
    fn leaves_printable_unicode_alone() {
        assert_eq!(escape_control("日本語 ü 🦀"), "日本語 ü 🦀");
    }
}
