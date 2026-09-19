//! The host list as the TUI shows it: which hosts, in which order, and which
//! one is selected. Pure logic, no rendering.
//!
//! Without a search the order is favorites first, then alphabetical by name
//! ignoring case. With a search only matching hosts are listed, best match
//! first (see [`super::fuzzy`] for how matches are scored).

use std::cmp::Reverse;

use super::fuzzy::fuzzy_match;
use super::input::TextInput;
use crate::domain::{Host, Hosts};

/// A match in the name outweighs the same match in the hostname, which
/// outweighs one in a tag.
const NAME_WEIGHT: i32 = 30;
const HOSTNAME_WEIGHT: i32 = 0;
const TAG_WEIGHT: i32 = -10;

/// How a search matched one host: the score, and the character positions to
/// highlight in each field (empty when the field did not match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMatch {
    pub score: i32,
    pub name: Vec<usize>,
    pub hostname: Vec<usize>,
    /// One entry per tag, in the host's tag order.
    pub tags: Vec<Vec<usize>>,
}

/// Matches a query against a host's name, hostname and tags. The query has to
/// match inside one field as a whole; the best field decides the score.
pub fn match_host(query: &str, host: &Host) -> Option<HostMatch> {
    let name = fuzzy_match(query, &host.name);
    let hostname = fuzzy_match(query, &host.hostname);
    let tags: Vec<_> = host
        .tags
        .iter()
        .map(|tag| fuzzy_match(query, tag))
        .collect();

    let score = name
        .iter()
        .map(|m| m.score + NAME_WEIGHT)
        .chain(hostname.iter().map(|m| m.score + HOSTNAME_WEIGHT))
        .chain(tags.iter().flatten().map(|m| m.score + TAG_WEIGHT))
        .max()?;

    Some(HostMatch {
        score,
        name: name.map(|m| m.positions).unwrap_or_default(),
        hostname: hostname.map(|m| m.positions).unwrap_or_default(),
        tags: tags
            .into_iter()
            .map(|m| m.map(|m| m.positions).unwrap_or_default())
            .collect(),
    })
}

/// One line of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Position of the host in [`Hosts::as_slice`].
    pub index: usize,
    /// How the search matched it; `None` when there is no search.
    pub matched: Option<HostMatch>,
}

/// Whether a query is empty once whitespace is ignored.
pub fn is_blank(query: &str) -> bool {
    query.chars().all(char::is_whitespace)
}

/// The rows to show for `query`, in display order.
pub fn rows(hosts: &Hosts, query: &str) -> Vec<Row> {
    let hosts = hosts.as_slice();
    let by_name = |index: usize| hosts[index].name.to_lowercase();

    if is_blank(query) {
        let mut rows: Vec<Row> = (0..hosts.len())
            .map(|index| Row {
                index,
                matched: None,
            })
            .collect();
        rows.sort_by_cached_key(|row| (Reverse(hosts[row.index].favorite), by_name(row.index)));
        return rows;
    }

    let mut rows: Vec<Row> = hosts
        .iter()
        .enumerate()
        .filter_map(|(index, host)| {
            match_host(query, host).map(|matched| Row {
                index,
                matched: Some(matched),
            })
        })
        .collect();
    rows.sort_by_cached_key(|row| {
        let score = row.matched.as_ref().map_or(0, |m| m.score);
        (
            Reverse(score),
            Reverse(hosts[row.index].favorite),
            by_name(row.index),
        )
    });
    rows
}

/// Where the visible window of a list starts.
///
/// `offset` is where it started before; it moves only as far as needed to keep
/// the selected row on screen, and never leaves blank space at the bottom.
pub fn window_start(offset: usize, selected: Option<usize>, visible: usize, len: usize) -> usize {
    let visible = visible.max(1);
    let mut start = offset.min(len.saturating_sub(visible));
    if let Some(position) = selected {
        if position < start {
            start = position;
        } else if position >= start + visible {
            start = position + 1 - visible;
        }
    }
    start
}

/// The list's own state: the search, the selection and the scroll position.
///
/// The selection is remembered by host name, not by row, so it follows the host
/// when the order changes (for example after toggling a favorite).
#[derive(Debug)]
pub struct ListState {
    pub query: TextInput,
    pub selected: Option<String>,
    pub offset: usize,
    /// How many rows fit on screen, as last reported by rendering.
    pub visible: usize,
}

impl Default for ListState {
    fn default() -> Self {
        ListState {
            query: TextInput::default(),
            selected: None,
            offset: 0,
            visible: 10,
        }
    }
}

impl ListState {
    /// The selected row's position in `rows`, if that host is listed.
    pub fn position(&self, hosts: &Hosts, rows: &[Row]) -> Option<usize> {
        let name = self.selected.as_deref()?;
        rows.iter()
            .position(|row| hosts.as_slice()[row.index].name == name)
    }

    /// Selects the row at `position` (clamped) and scrolls it into view. With no
    /// rows, nothing is selected.
    pub fn select(&mut self, hosts: &Hosts, rows: &[Row], position: usize) {
        match rows.get(position.min(rows.len().saturating_sub(1))) {
            Some(row) => {
                self.selected = Some(hosts.as_slice()[row.index].name.clone());
                self.offset = window_start(
                    self.offset,
                    Some(position.min(rows.len() - 1)),
                    self.visible,
                    rows.len(),
                );
            }
            None => {
                self.selected = None;
                self.offset = 0;
            }
        }
    }

    /// Keeps the selection if its host is still listed, otherwise selects the
    /// first row. Call after anything that can change the rows.
    pub fn normalize(&mut self, hosts: &Hosts, rows: &[Row]) {
        let position = self.position(hosts, rows).unwrap_or(0);
        self.select(hosts, rows, position);
    }

    pub fn select_first(&mut self, hosts: &Hosts, rows: &[Row]) {
        self.select(hosts, rows, 0);
    }

    pub fn select_last(&mut self, hosts: &Hosts, rows: &[Row]) {
        self.select(hosts, rows, rows.len().saturating_sub(1));
    }

    /// Moves the selection by `delta` rows, stopping at either end.
    pub fn move_by(&mut self, hosts: &Hosts, rows: &[Row], delta: isize) {
        let current = self.position(hosts, rows).unwrap_or(0);
        self.select(hosts, rows, current.saturating_add_signed(delta));
    }

    /// Moves by one screenful of rows.
    pub fn page(&mut self, hosts: &Hosts, rows: &[Row], down: bool) {
        let step = isize::try_from(self.visible.max(1)).unwrap_or(isize::MAX);
        self.move_by(hosts, rows, if down { step } else { -step });
    }

    /// Adopts a new on-screen row count and keeps the selection visible.
    pub fn set_visible(&mut self, hosts: &Hosts, rows: &[Row], visible: usize) {
        self.visible = visible.max(1);
        self.normalize(hosts, rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, hostname: &str, tags: &[&str], favorite: bool) -> Host {
        let mut host = Host::new(name, hostname);
        host.tags = tags.iter().map(|t| (*t).to_string()).collect();
        host.favorite = favorite;
        host
    }

    fn hosts(list: Vec<Host>) -> Hosts {
        Hosts::from_vec(list).unwrap()
    }

    fn names(hosts: &Hosts, rows: &[Row]) -> Vec<String> {
        rows.iter()
            .map(|row| hosts.as_slice()[row.index].name.clone())
            .collect()
    }

    fn sample() -> Hosts {
        hosts(vec![
            host("web", "10.0.0.1", &["prod"], false),
            host("Db", "10.0.0.2", &["prod", "db"], false),
            host("backup", "10.0.0.3", &[], true),
            host("api", "api.example.com", &["staging"], false),
            host("cache", "10.0.0.5", &[], true),
        ])
    }

    // ---- sorting ---------------------------------------------------------

    #[test]
    fn without_a_search_favorites_come_first_then_names_ignoring_case() {
        let hosts = sample();
        let rows = rows(&hosts, "");
        assert_eq!(
            names(&hosts, &rows),
            ["backup", "cache", "api", "Db", "web"]
        );
        assert!(rows.iter().all(|row| row.matched.is_none()));
    }

    #[test]
    fn a_blank_query_is_no_search() {
        let hosts = sample();
        assert_eq!(rows(&hosts, "   "), rows(&hosts, ""));
    }

    #[test]
    fn name_sorting_ignores_case() {
        let hosts = hosts(vec![
            host("bravo", "b.example.com", &[], false),
            host("Alpha", "a.example.com", &[], false),
            host("charlie", "c.example.com", &[], false),
            host("Delta", "d.example.com", &[], false),
        ]);
        assert_eq!(
            names(&hosts, &rows(&hosts, "")),
            ["Alpha", "bravo", "charlie", "Delta"]
        );
    }

    #[test]
    fn favorites_are_sorted_by_name_among_themselves() {
        let hosts = hosts(vec![
            host("zeta", "z.example.com", &[], true),
            host("alpha", "a.example.com", &[], false),
            host("beta", "b.example.com", &[], true),
        ]);
        assert_eq!(names(&hosts, &rows(&hosts, "")), ["beta", "zeta", "alpha"]);
    }

    #[test]
    fn an_empty_collection_has_no_rows() {
        assert!(rows(&Hosts::new(), "").is_empty());
        assert!(rows(&Hosts::new(), "web").is_empty());
    }

    // ---- searching -------------------------------------------------------

    #[test]
    fn a_search_lists_only_matching_hosts() {
        let hosts = sample();
        let found = rows(&hosts, "prod");
        assert_eq!(names(&hosts, &found), ["Db", "web"].map(String::from));
    }

    #[test]
    fn a_search_with_no_match_gives_no_rows() {
        let hosts = sample();
        assert!(rows(&hosts, "zzz").is_empty());
    }

    #[test]
    fn a_search_looks_in_name_hostname_and_tags() {
        let hosts = sample();
        assert_eq!(names(&hosts, &rows(&hosts, "backup")), ["backup"]);
        assert_eq!(names(&hosts, &rows(&hosts, "example")), ["api"]);
        assert_eq!(names(&hosts, &rows(&hosts, "stag")), ["api"]);
    }

    #[test]
    fn a_search_is_case_insensitive() {
        let hosts = sample();
        assert_eq!(
            names(&hosts, &rows(&hosts, "DB")),
            names(&hosts, &rows(&hosts, "db"))
        );
        assert!(!rows(&hosts, "WEB").is_empty());
    }

    #[test]
    fn a_search_is_a_subsequence_match_not_a_substring_match() {
        let hosts = sample();
        // w..b matches "web" although the letters are not adjacent in the query.
        assert_eq!(names(&hosts, &rows(&hosts, "wb")), ["web"]);
    }

    #[test]
    fn results_are_ranked_by_score_not_by_favorite_or_name() {
        let hosts = hosts(vec![
            host("aaa-mydb", "10.0.0.1", &[], true),
            host("db-main", "10.0.0.2", &[], false),
            host("prod-db", "10.0.0.3", &[], false),
        ]);
        // A prefix beats a word start, which beats the middle of a word.
        assert_eq!(
            names(&hosts, &rows(&hosts, "db")),
            ["db-main", "prod-db", "aaa-mydb"]
        );
    }

    #[test]
    fn a_match_in_the_name_outranks_the_same_match_in_the_hostname_or_a_tag() {
        let hosts = hosts(vec![
            host("alpha", "db.example.com", &[], false),
            host("beta", "10.0.0.2", &["db"], false),
            host("db", "10.0.0.3", &[], false),
        ]);
        assert_eq!(names(&hosts, &rows(&hosts, "db")), ["db", "alpha", "beta"]);
    }

    #[test]
    fn equal_scores_fall_back_to_favorites_then_name() {
        let hosts = hosts(vec![
            host("web-b", "10.0.0.1", &[], false),
            host("web-a", "10.0.0.2", &[], false),
            host("web-c", "10.0.0.3", &[], true),
        ]);
        assert_eq!(
            names(&hosts, &rows(&hosts, "web-")),
            ["web-c", "web-a", "web-b"]
        );
    }

    #[test]
    fn match_positions_are_reported_per_field() {
        let h = host("db-prod", "10.0.0.2", &["prod", "eu"], false);
        let matched = match_host("prod", &h).unwrap();
        assert_eq!(matched.name, [3, 4, 5, 6]);
        assert!(matched.hostname.is_empty());
        assert_eq!(matched.tags, [vec![0, 1, 2, 3], vec![]]);
    }

    #[test]
    fn a_host_that_matches_nowhere_has_no_match() {
        assert!(match_host("zzz", &host("web", "10.0.0.1", &["prod"], false)).is_none());
    }

    #[test]
    fn the_user_is_not_searched() {
        let mut h = host("web", "10.0.0.1", &[], false);
        h.user = Some("deploy".to_string());
        assert!(match_host("deploy", &h).is_none());
    }

    // ---- window ----------------------------------------------------------

    #[test]
    fn the_window_stays_put_while_the_selection_is_inside_it() {
        assert_eq!(window_start(5, Some(7), 10, 100), 5);
    }

    #[test]
    fn the_window_scrolls_up_and_down_to_follow_the_selection() {
        assert_eq!(window_start(5, Some(2), 10, 100), 2);
        assert_eq!(window_start(5, Some(20), 10, 100), 11);
    }

    #[test]
    fn the_window_never_leaves_blank_space_at_the_bottom() {
        assert_eq!(window_start(95, None, 10, 100), 90);
        assert_eq!(window_start(5, None, 10, 4), 0);
        assert_eq!(window_start(0, Some(0), 10, 0), 0);
    }

    // ---- selection -------------------------------------------------------

    fn state(hosts: &Hosts, visible: usize) -> (ListState, Vec<Row>) {
        let rows = rows(hosts, "");
        let mut state = ListState::default();
        state.set_visible(hosts, &rows, visible);
        (state, rows)
    }

    fn many(count: usize) -> Hosts {
        hosts(
            (0..count)
                .map(|n| host(&format!("host-{n:02}"), "10.0.0.1", &[], false))
                .collect(),
        )
    }

    #[test]
    fn the_first_row_is_selected_by_default() {
        let hosts = sample();
        let (state, _) = state(&hosts, 10);
        assert_eq!(state.selected.as_deref(), Some("backup"));
    }

    #[test]
    fn nothing_is_selected_in_an_empty_list() {
        let hosts = Hosts::new();
        let (mut state, rows) = state(&hosts, 10);
        assert_eq!(state.selected, None);
        state.move_by(&hosts, &rows, 1);
        state.select_last(&hosts, &rows);
        assert_eq!(state.selected, None);
    }

    #[test]
    fn moving_stops_at_both_ends() {
        let hosts = many(3);
        let (mut state, rows) = state(&hosts, 10);
        state.move_by(&hosts, &rows, -1);
        assert_eq!(state.selected.as_deref(), Some("host-00"));
        state.move_by(&hosts, &rows, 1);
        state.move_by(&hosts, &rows, 1);
        state.move_by(&hosts, &rows, 1);
        assert_eq!(state.selected.as_deref(), Some("host-02"));
    }

    #[test]
    fn home_and_end_jump_to_the_first_and_last_rows() {
        let hosts = many(30);
        let (mut state, rows) = state(&hosts, 10);
        state.select_last(&hosts, &rows);
        assert_eq!(state.selected.as_deref(), Some("host-29"));
        assert_eq!(state.offset, 20, "the last row is in view");
        state.select_first(&hosts, &rows);
        assert_eq!(state.selected.as_deref(), Some("host-00"));
        assert_eq!(state.offset, 0);
    }

    #[test]
    fn paging_moves_by_a_screenful() {
        let hosts = many(40);
        let (mut state, rows) = state(&hosts, 10);
        state.page(&hosts, &rows, true);
        assert_eq!(state.selected.as_deref(), Some("host-10"));
        state.page(&hosts, &rows, true);
        assert_eq!(state.selected.as_deref(), Some("host-20"));
        state.page(&hosts, &rows, false);
        assert_eq!(state.selected.as_deref(), Some("host-10"));
        for _ in 0..10 {
            state.page(&hosts, &rows, true);
        }
        assert_eq!(state.selected.as_deref(), Some("host-39"));
    }

    #[test]
    fn moving_scrolls_the_window_only_when_needed() {
        let hosts = many(30);
        let (mut state, rows) = state(&hosts, 10);
        for _ in 0..9 {
            state.move_by(&hosts, &rows, 1);
        }
        assert_eq!(state.offset, 0, "row 9 is still on the first screen");
        state.move_by(&hosts, &rows, 1);
        assert_eq!(state.offset, 1, "row 10 scrolls by one");
    }

    #[test]
    fn the_selection_follows_its_host_when_the_order_changes() {
        let mut list = vec![
            host("alpha", "10.0.0.1", &[], false),
            host("beta", "10.0.0.2", &[], false),
            host("gamma", "10.0.0.3", &[], false),
        ];
        let hosts_before = hosts(list.clone());
        let (mut state, rows_before) = state(&hosts_before, 10);
        state.select(&hosts_before, &rows_before, 2);
        assert_eq!(state.selected.as_deref(), Some("gamma"));

        list[2].favorite = true;
        let hosts_after = hosts(list);
        let rows_after = rows(&hosts_after, "");
        state.normalize(&hosts_after, &rows_after);

        assert_eq!(state.selected.as_deref(), Some("gamma"));
        assert_eq!(state.position(&hosts_after, &rows_after), Some(0));
    }

    #[test]
    fn a_selection_that_is_filtered_out_moves_to_the_first_row() {
        let hosts = sample();
        let (mut state, _) = state(&hosts, 10);
        let found = rows(&hosts, "api");
        state.normalize(&hosts, &found);
        assert_eq!(state.selected.as_deref(), Some("api"));

        let none = rows(&hosts, "zzz");
        state.normalize(&hosts, &none);
        assert_eq!(state.selected, None);
    }

    #[test]
    fn a_smaller_screen_keeps_the_selection_visible() {
        let hosts = many(30);
        let (mut state, rows) = state(&hosts, 20);
        state.select(&hosts, &rows, 15);
        assert_eq!(state.offset, 0);
        state.set_visible(&hosts, &rows, 5);
        assert_eq!(state.offset, 11);
    }
}
