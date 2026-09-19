//! Word wrapping to a display width.
//!
//! Screens wrap their text themselves, instead of letting a widget do it, so
//! they know exactly how many lines the text takes and can scroll to the end of
//! it. Widths are measured in terminal cells, so wide characters count double.

use ratatui::text::Span;

/// Width of `text` in terminal cells.
pub fn display_width(text: &str) -> usize {
    Span::raw(text).width()
}

/// Wraps one line of text (no line breaks in it) to at most `width` cells.
///
/// Breaks happen at spaces. A word wider than `width` is split between
/// characters. Trailing spaces are dropped where a line is broken, leading
/// spaces are kept. Empty text gives one empty line; a `width` of 0 gives none.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_width = 0;

    for token in text.split_inclusive(' ') {
        let word_width = display_width(token.trim_end_matches(' '));
        if line_width > 0 && line_width + word_width > width {
            lines.push(take_trimmed(&mut line));
            line_width = 0;
        }
        if word_width > width {
            for ch in token.chars() {
                let ch_width = display_width(ch.encode_utf8(&mut [0; 4]));
                if line_width > 0 && line_width + ch_width > width {
                    lines.push(take_trimmed(&mut line));
                    line_width = 0;
                }
                line.push(ch);
                line_width += ch_width;
            }
        } else {
            line.push_str(token);
            line_width += display_width(token);
        }
    }
    lines.push(take_trimmed(&mut line));
    lines
}

fn take_trimmed(line: &mut String) -> String {
    let trimmed = line.trim_end_matches(' ').to_string();
    line.clear();
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_is_one_line() {
        assert_eq!(wrap("hello world", 20), ["hello world"]);
    }

    #[test]
    fn empty_text_is_one_empty_line() {
        assert_eq!(wrap("", 10), [""]);
    }

    #[test]
    fn zero_width_gives_no_lines() {
        assert!(wrap("anything", 0).is_empty());
    }

    #[test]
    fn breaks_at_spaces() {
        assert_eq!(wrap("the quick brown fox", 10), ["the quick", "brown fox"]);
    }

    #[test]
    fn a_line_exactly_as_wide_as_the_limit_is_not_broken() {
        assert_eq!(wrap("abcde fghij", 11), ["abcde fghij"]);
        assert_eq!(wrap("abcde fghij", 10), ["abcde", "fghij"]);
    }

    #[test]
    fn splits_words_wider_than_the_limit() {
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(
            wrap("see /very/long/path/to/hosts.toml now", 10),
            ["see", "/very/long", "/path/to/h", "osts.toml", "now"]
        );
    }

    #[test]
    fn keeps_leading_spaces_and_drops_trailing_ones_at_breaks() {
        assert_eq!(
            wrap("  indented text here", 12),
            ["  indented", "text here"]
        );
        assert_eq!(wrap("trailing   ", 20), ["trailing"]);
    }

    #[test]
    fn wide_characters_count_double() {
        // Each of these characters is two cells wide.
        assert_eq!(display_width("日本"), 4);
        assert_eq!(wrap("日本語日本語", 6), ["日本語", "日本語"]);
    }

    #[test]
    fn a_character_wider_than_the_limit_still_makes_progress() {
        assert_eq!(wrap("日本", 1), ["日", "本"]);
    }

    #[test]
    fn no_line_exceeds_the_width() {
        let text = "Fix the reported line in the file, or restore the previous version from \
                    /home/someone/.config/bifrost/hosts.toml.bak. Bifrost has not changed the file.";
        for width in [5, 12, 30, 58] {
            for line in wrap(text, width) {
                assert!(
                    display_width(&line) <= width,
                    "width {width}: {line:?} is too wide"
                );
            }
        }
    }

    #[test]
    fn wrapping_loses_no_words() {
        let text = "alpha beta gamma delta epsilon";
        let joined = wrap(text, 8).join(" ");
        assert_eq!(joined, text);
    }
}
