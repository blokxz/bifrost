//! Small text helpers.

/// Escapes control characters so external text can be embedded in a message.
///
/// `"a\nb"` becomes `a\nb` (backslash, `n`) and ESC becomes `\u{1b}`.
pub fn escape_control(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_control() {
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
}
