//! Fuzzy matching for the host search.
//!
//! A query matches a text when its characters appear in the text in order, not
//! necessarily next to each other, ignoring case ("dbp" matches "db-prod").
//! Among the possible alignments the best one is chosen, by these rules:
//!
//! - every matched character scores;
//! - a match right after the previous one (consecutive) scores more;
//! - a match at the start of the text, or right after a separator such as `-`,
//!   `.` or `@`, scores more (so prefixes and word starts win);
//! - characters skipped between two matches, and before the first one, cost a
//!   little.
//!
//! The result carries the matched positions so the caller can highlight them.

/// Score per matched character.
const MATCH: i32 = 16;
/// Extra score when a match directly follows the previous one. It must beat
/// [`BONUS_WORD`] minus [`GAP`], so that "abc" prefers "abc" to "a-b-c".
const CONSECUTIVE: i32 = 12;
/// Extra score for a match at the very start of the text.
const BONUS_START: i32 = 24;
/// Extra score for a match at the start of a word (after a separator).
const BONUS_WORD: i32 = 10;
/// Cost per character skipped between two matches.
const GAP: i32 = 2;
/// Cost per character before the first match, up to [`LEADING_CAP`] characters.
const LEADING: i32 = 1;
const LEADING_CAP: usize = 6;

/// Far below any real score, and safe to subtract from without overflowing.
const IMPOSSIBLE: i32 = i32::MIN / 4;

/// A successful match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Higher is better. Only comparable between matches of the same query.
    pub score: i32,
    /// Character positions (not byte offsets) in the text, in increasing order.
    pub positions: Vec<usize>,
}

fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn is_separator(c: char) -> bool {
    matches!(c, '-' | '_' | '.' | '@' | ':' | '/' | ' ')
}

/// Matches `query` against `text`, ignoring case and any whitespace in the
/// query. An empty query matches everything with no positions.
pub fn fuzzy_match(query: &str, text: &str) -> Option<Match> {
    let query: Vec<char> = query
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(fold)
        .collect();
    if query.is_empty() {
        return Some(Match {
            score: 0,
            positions: Vec::new(),
        });
    }
    let original: Vec<char> = text.chars().collect();
    let folded: Vec<char> = original.iter().copied().map(fold).collect();
    let (m, n) = (query.len(), folded.len());
    if m > n {
        return None;
    }

    let bonus = |i: usize| -> i32 {
        if i == 0 {
            BONUS_START
        } else if is_separator(original[i - 1]) {
            BONUS_WORD
        } else {
            0
        }
    };

    // score[j][i]: best score of matching query[..=j] with query[j] at text[i].
    // from[j][i]: where query[j - 1] sits in that best alignment.
    let mut score = vec![vec![IMPOSSIBLE; n]; m];
    let mut from = vec![vec![usize::MAX; n]; m];

    for i in 0..n {
        if folded[i] == query[0] {
            let leading = i.min(LEADING_CAP) as i32 * LEADING;
            score[0][i] = MATCH + bonus(i) - leading;
        }
    }

    for j in 1..m {
        // run[i] is the best `score[j - 1][k] - GAP * (i - k)` over k <= i,
        // with the k that achieves it: the best earlier match to extend from
        // once the skipped characters are paid for.
        let mut run = vec![(IMPOSSIBLE, usize::MAX); n];
        for i in 0..n {
            let here = (score[j - 1][i], i);
            run[i] = if i == 0 {
                here
            } else {
                let carried = (run[i - 1].0 - GAP, run[i - 1].1);
                if here.0 >= carried.0 { here } else { carried }
            };
        }
        for i in j..n {
            if folded[i] != query[j] {
                continue;
            }
            let mut best = (IMPOSSIBLE, usize::MAX);
            if score[j - 1][i - 1] > IMPOSSIBLE {
                best = (score[j - 1][i - 1] + CONSECUTIVE, i - 1);
            }
            if i >= 2 && run[i - 2].0 > IMPOSSIBLE {
                let skipped = (run[i - 2].0 - GAP, run[i - 2].1);
                if skipped.0 > best.0 {
                    best = skipped;
                }
            }
            if best.0 > IMPOSSIBLE {
                score[j][i] = MATCH + bonus(i) + best.0;
                from[j][i] = best.1;
            }
        }
    }

    let (mut at, best) = (0..n)
        .map(|i| (i, score[m - 1][i]))
        .filter(|&(_, s)| s > IMPOSSIBLE)
        .fold(None, |top: Option<(usize, i32)>, candidate| match top {
            Some(t) if t.1 >= candidate.1 => Some(t),
            _ => Some(candidate),
        })?;

    let mut positions = vec![0; m];
    for j in (0..m).rev() {
        positions[j] = at;
        if j > 0 {
            at = from[j][at];
        }
    }
    Some(Match {
        score: best,
        positions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(query: &str, text: &str) -> i32 {
        fuzzy_match(query, text)
            .unwrap_or_else(|| panic!("{query:?} should match {text:?}"))
            .score
    }

    #[test]
    fn an_empty_query_matches_everything_with_no_positions() {
        let found = fuzzy_match("", "anything").unwrap();
        assert!(found.positions.is_empty());
        assert!(fuzzy_match("   ", "anything").is_some());
        assert!(fuzzy_match("", "").is_some());
    }

    #[test]
    fn characters_must_appear_in_order() {
        assert!(fuzzy_match("web", "web-01").is_some());
        assert!(fuzzy_match("w1", "web-01").is_some());
        assert!(fuzzy_match("bew", "web-01").is_none());
        assert!(fuzzy_match("xyz", "web-01").is_none());
    }

    #[test]
    fn a_query_longer_than_the_text_never_matches() {
        assert!(fuzzy_match("web-01-extra", "web-01").is_none());
        assert!(fuzzy_match("a", "").is_none());
    }

    #[test]
    fn a_character_cannot_be_used_twice() {
        assert!(fuzzy_match("aa", "a").is_none());
        assert!(fuzzy_match("aa", "a-a").is_some());
    }

    #[test]
    fn matching_ignores_case() {
        assert_eq!(fuzzy_match("WEB", "web-01"), fuzzy_match("web", "web-01"));
        assert!(fuzzy_match("web", "WEB-01").is_some());
    }

    #[test]
    fn whitespace_in_the_query_is_ignored() {
        assert_eq!(fuzzy_match("w e b", "web-01"), fuzzy_match("web", "web-01"));
    }

    #[test]
    fn positions_are_increasing_and_point_at_the_matched_characters() {
        let text = "db-prod-01";
        let found = fuzzy_match("dbp1", text).unwrap();
        assert!(found.positions.windows(2).all(|w| w[0] < w[1]));
        let chars: Vec<char> = text.chars().collect();
        let picked: String = found.positions.iter().map(|&p| chars[p]).collect();
        assert_eq!(picked, "dbp1");
    }

    #[test]
    fn positions_count_characters_not_bytes() {
        let found = fuzzy_match("c", "ñandú-c").unwrap();
        assert_eq!(found.positions, [6]);
    }

    #[test]
    fn the_best_alignment_is_chosen_not_the_first() {
        // Taking the first available letters would give [0, 2, 6]; the solid
        // run at the start of the last word is the better alignment.
        let found = fuzzy_match("web", "wxe-web").unwrap();
        assert_eq!(found.positions, [4, 5, 6]);
    }

    #[test]
    fn a_prefix_beats_a_match_in_the_middle() {
        assert!(score("db", "db-prod") > score("db", "prod-db"));
        assert!(score("db", "db-prod") > score("db", "mydb"));
    }

    #[test]
    fn the_start_of_a_word_beats_the_middle_of_one() {
        assert!(score("db", "prod-db") > score("db", "prodadb"));
    }

    #[test]
    fn consecutive_characters_beat_scattered_ones() {
        assert!(score("abc", "abc") > score("abc", "a-b-c"));
        assert!(score("abc", "xabc") > score("abc", "xa-b-c"));
        assert!(score("prod", "prod-1") > score("prod", "p-r-o-d"));
    }

    #[test]
    fn fewer_skipped_characters_score_higher() {
        assert!(score("ab", "a-b") > score("ab", "a---b"));
    }

    #[test]
    fn a_full_match_beats_a_partial_alignment_of_the_same_text() {
        assert!(score("web-01", "web-01") > score("web-01", "web-xx-01"));
    }

    #[test]
    fn scores_do_not_overflow_on_long_texts() {
        let text = "a".repeat(253);
        assert!(fuzzy_match(&"a".repeat(60), &text).is_some());
        assert!(fuzzy_match("b", &text).is_none());
    }
}
