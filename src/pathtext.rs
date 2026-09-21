//! Paths compared and expanded as text, by explicit rules.
//!
//! `std::path` splits a path by the rules of the system that runs it: on Windows
//! `\` separates and on Unix it is a letter of a name. A comparison built on it
//! cannot be tested for the other system, and one built on plain strings says two
//! spellings of one Windows file are two files. So the decisions Bifrost takes
//! about paths from their words (is this saved key the one on disk, is this the
//! `known_hosts` that `ssh-keygen -R` edits, is this `Include` the exported file)
//! go through here, on text, with the rules as a parameter. Production passes
//! [`Rules::native`], the only place that looks at the system; the tests pass
//! both.
//!
//! Everything here is **lexical**: the disk is not looked at and a link is not
//! followed. That is why [`same_path`] never resolves `..` (`a/../b` is not `b` when
//! `a` is a link, and some of these decisions choose which file is edited), and why
//! [`same_path_resolving_dots`] exists only for the one caller that documents
//! deciding "from the words".

/// Which system's way of writing a path is meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rules {
    /// `/` separates, case matters, `\` is a letter of a name, `//` is a root.
    Unix,
    /// `/` and `\` both separate, case does not matter, a drive (`C:`) and a
    /// network path (`\\server\share`) start a path, and the `\\?\` prefix that
    /// the system writes for a resolved path means nothing.
    Windows,
}

impl Rules {
    /// The rules of the system that is running. The one place that asks.
    pub const fn native() -> Rules {
        if cfg!(windows) {
            Rules::Windows
        } else {
            Rules::Unix
        }
    }

    fn is_windows(self) -> bool {
        self == Rules::Windows
    }
}

/// A path taken apart: where it starts, and its names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts {
    /// `""` for a relative path, `/` for a root, `//server/share/` for a network
    /// path, `c:` for the current folder of a drive and `c:/` for the root of one.
    anchor: String,
    /// The names, without `.` and empty parts. `..` is kept as it was written.
    names: Vec<String>,
}

impl Parts {
    fn has_parent_refs(&self) -> bool {
        self.names.iter().any(|name| name == "..")
    }

    /// The same, with each `..` applied to the name before it. A root and a drive
    /// have no parent: a `..` there stays where it is. In a path that starts
    /// nowhere, a `..` with nothing before it is kept.
    fn resolved(mut self) -> Parts {
        let rooted = self.anchor.ends_with('/');
        let mut names: Vec<String> = Vec::new();
        for name in self.names {
            if name != ".." {
                names.push(name);
            } else if names.last().is_some_and(|last| last != "..") {
                names.pop();
            } else if !rooted {
                names.push(name);
            }
        }
        self.names = names;
        self
    }
}

/// Takes `path` apart by `rules`: separators, the start of the path, `.` and empty
/// parts dropped, and case folded where the rules say it does not matter.
pub fn parts(path: &str, rules: Rules) -> Parts {
    let windows = rules.is_windows();
    let mut text = if windows {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    if windows {
        let plain = text
            .strip_prefix("//?/UNC/")
            .map(|rest| format!("//{rest}"))
            .or_else(|| text.strip_prefix("//?/").map(str::to_string));
        if let Some(plain) = plain {
            text = plain;
        }
    }

    let mut rest = text.as_str();
    let mut anchor = String::new();
    if windows && has_drive(rest) {
        anchor.push_str(&rest[..2].to_lowercase());
        rest = &rest[2..];
    }
    if rest.starts_with('/') {
        // `//name` starts a network path under the rules of Windows, and is only
        // a root elsewhere.
        if windows && anchor.is_empty() && rest.starts_with("//") && !rest.starts_with("///") {
            anchor.push_str("//");
        } else {
            anchor.push('/');
        }
        rest = rest.trim_start_matches('/');
    }

    let mut names: Vec<String> = rest
        .split('/')
        .filter(|name| !name.is_empty() && *name != ".")
        .map(|name| {
            if windows {
                name.to_lowercase()
            } else {
                name.to_string()
            }
        })
        .collect();
    // A network path starts at its share: `..` cannot climb above `\\server\share`.
    if anchor == "//" {
        let share = names.len().min(2);
        for name in names.drain(..share) {
            anchor.push_str(&name);
            anchor.push('/');
        }
    }
    Parts { anchor, names }
}

fn has_drive(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Whether `a` and `b` are the same path written two ways.
///
/// **Never for a path with `..` in it**, not even one that is equal to the other
/// letter for letter: `a/../b` is `b` only if `a` is not a link, the words cannot
/// say, and where this is asked a wrong yes picks the wrong file. "Not equal"
/// costs a question that is asked again, or nothing.
pub fn same_path(a: &str, b: &str, rules: Rules) -> bool {
    let a = parts(a, rules);
    // `..` is kept as written, so a `b` that has one is not equal to an `a` that has
    // none: only `a` has to be checked.
    !a.has_parent_refs() && a == parts(b, rules)
}

/// [`same_path`] with each `..` applied to the name before it, as if no name were
/// a link. Only for deciding from the words what a person meant, where a wrong
/// answer changes what is offered and never what is edited.
pub fn same_path_resolving_dots(a: &str, b: &str, rules: Rules) -> bool {
    parts(a, rules).resolved() == parts(b, rules).resolved()
}

/// `path` with a leading `~` replaced by `home`, as ssh does for the paths it is
/// given. `~/x` always means the home; `~\x` only under the rules of Windows (on
/// Unix it is a name that starts with `~`); `~user/x` is not supported and is an
/// ordinary path. Without a home, a path that needs it is `None`.
pub fn expand_tilde(path: &str, home: Option<&str>, rules: Rules) -> Option<String> {
    let Some(rest) = path.strip_prefix('~') else {
        return Some(path.to_string());
    };
    let separator = |c: char| c == '/' || (rules.is_windows() && c == '\\');
    if rest.is_empty() {
        return home.map(str::to_string);
    }
    match rest.strip_prefix(separator) {
        // Written with `/`, which separates under both rules. A home that ends in a
        // separator (the root, `C:\`) gives no doubled one.
        Some(tail) => home.map(|home| format!("{}/{tail}", home.trim_end_matches(separator))),
        None => Some(path.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOWS: Rules = Rules::Windows;
    const UNIX: Rules = Rules::Unix;

    /// Each spelling equals the first, by `same_path` and by the resolving one.
    fn all_same(rules: Rules, spellings: &[&str]) {
        for other in &spellings[1..] {
            assert!(
                same_path(spellings[0], other, rules),
                "{:?} == {other:?} under {rules:?}",
                spellings[0]
            );
            assert!(same_path_resolving_dots(spellings[0], other, rules));
        }
    }

    /// No two of these are equal, by either.
    fn none_same(rules: Rules, base: &str, others: &[&str]) {
        for other in others {
            assert!(
                !same_path(base, other, rules),
                "{base:?} != {other:?} under {rules:?}"
            );
            assert!(!same_path_resolving_dots(base, other, rules));
        }
    }

    // ---- the rules of Windows ---------------------------------------------------

    #[test]
    fn windows_paths_are_the_same_whatever_the_separator_the_case_or_the_dots() {
        all_same(
            WINDOWS,
            &[
                r"C:\Users\Dev\.ssh\known_hosts",
                "C:/Users/Dev/.ssh/known_hosts",
                r"C:\Users/Dev\.ssh/known_hosts",
                r"c:\users\dev\.ssh\known_hosts",
                r"C:\USERS\DEV\.SSH\KNOWN_HOSTS",
                r"C:\Users\Dev\.ssh\.\known_hosts",
                r"C:\Users\Dev\\.ssh\known_hosts",
                r"C:\Users\Dev\.ssh\known_hosts\",
                r"\\?\C:\Users\Dev\.ssh\known_hosts",
                r"C:\\Users\Dev\.ssh\known_hosts",
                "C://Users/Dev/.ssh/known_hosts",
            ],
        );
        all_same(
            WINDOWS,
            &[
                r"\\server\share\x",
                "//server/share/x",
                r"\\SERVER\Share\X",
                r"\\?\UNC\server\share\x",
            ],
        );
    }

    #[test]
    fn windows_paths_that_start_elsewhere_are_not_the_same() {
        none_same(
            WINDOWS,
            r"C:\Users\Dev\known_hosts",
            &[
                r"D:\Users\Dev\known_hosts",
                r"\Users\Dev\known_hosts",
                r"Users\Dev\known_hosts",
                r"C:Users\Dev\known_hosts",
                r"\\Users\Dev\known_hosts",
                r"C:\Users\Dev\known_hosts2",
                r"C:\Users\Dev",
                r"C:\Users\Other\known_hosts",
                "",
            ],
        );
        // A drive's own folder is not its root, and a network path is not a root.
        none_same(WINDOWS, "C:", &[r"C:\", "", r"\"]);
        none_same(
            WINDOWS,
            r"\\server\share\x",
            &[
                r"\server\share\x",
                r"\\\server\share\x",
                r"\\server\other\x",
            ],
        );
    }

    #[test]
    fn the_prefix_the_system_writes_for_a_resolved_path_means_nothing() {
        assert_eq!(
            parts(r"\\?\C:\a\b", WINDOWS),
            parts(r"C:\a\b", WINDOWS),
            "what canonicalize gives is the path"
        );
        // ...and only under the rules of Windows: elsewhere it is an odd name.
        assert!(!same_path(r"\\?\C:\a", r"C:\a", UNIX));
    }

    // ---- the rules of the others ------------------------------------------------

    #[test]
    fn unix_paths_are_the_same_only_up_to_separators_and_dots() {
        all_same(
            UNIX,
            &[
                "/home/dev/.ssh/known_hosts",
                "/home/dev//.ssh/known_hosts",
                "/home/dev/./.ssh/known_hosts",
                "//home/dev/.ssh/known_hosts",
                "///home/dev/.ssh/known_hosts",
                "/home/dev/.ssh/known_hosts/",
            ],
        );
        none_same(
            UNIX,
            "/home/dev/.ssh/known_hosts",
            &[
                "/home/dev/.ssh/Known_Hosts",
                "/HOME/dev/.ssh/known_hosts",
                "home/dev/.ssh/known_hosts",
                "/home/dev/.ssh/known_hosts2",
                "/home/dev/.ssh",
                "",
            ],
        );
    }

    #[test]
    fn on_unix_a_backslash_is_a_letter_and_a_drive_is_a_name() {
        none_same(UNIX, "/home/dev/a/b", &[r"/home/dev/a\b", r"\home\dev\a\b"]);
        assert!(same_path(r"/home/dev/a\b", r"/home/dev/a\b", UNIX));
        none_same(UNIX, "C:/x", &["/x", "c:/x", "/C:/x"]);
        assert_eq!(parts("C:/x", UNIX).anchor, "", "a relative path");
    }

    // ---- `..` ------------------------------------------------------------------

    #[test]
    fn a_path_with_dot_dot_is_never_the_same_as_anything() {
        for rules in [UNIX, WINDOWS] {
            for path in ["/a/../b", "/a/b/..", "..", "../a", "a/..", "/a/./../b"] {
                assert!(!same_path(path, path, rules), "{path:?} with itself");
                assert!(!same_path(path, "/b", rules), "{path:?}");
                assert!(!same_path("/b", path, rules), "{path:?}");
            }
        }
        assert!(!same_path(r"C:\a\..\b", r"C:\a\..\b", WINDOWS));
        assert!(!same_path(r"C:\a\..\b", r"C:\b", WINDOWS));
        // A name that only has dots in it is a name.
        assert!(same_path("/a/..b/c", "/a/..b/c", UNIX));
        assert!(same_path("/a/b../c", "/a/b../c", UNIX));
        assert!(same_path("/a/...", "/a/...", UNIX));
    }

    #[test]
    fn resolving_applies_each_dot_dot_to_the_name_before_it() {
        for (a, b) in [
            ("/a/b/../c", "/a/c"),
            ("/a/b/c/../../d", "/a/d"),
            ("/a/../a/b", "/a/b"),
            ("/a/b/..", "/a"),
            // Nothing above a root.
            ("/../a", "/a"),
            ("/../../a", "/a"),
            ("/a/../../b", "/b"),
        ] {
            assert!(same_path_resolving_dots(a, b, UNIX), "{a:?} == {b:?}");
        }
        for (a, b) in [
            (r"C:\a\..\b", r"C:\b"),
            (r"C:\..\..\Users", r"C:\Users"),
            (r"\\server\share\..\..\x", r"\\server\share\x"),
            (r"\\server\share\a\..\x", "//server/share/x"),
            (r"C:\a\b\..\..\c", "c:/c"),
        ] {
            assert!(same_path_resolving_dots(a, b, WINDOWS), "{a:?} == {b:?}");
        }
        // Where there is nothing to climb from, a relative path keeps its `..`.
        for rules in [UNIX, WINDOWS] {
            none_same(rules, "a", &["../a", "b/../../a"]);
            assert!(same_path_resolving_dots("../a", "../a", rules));
            assert!(!same_path_resolving_dots("../a", "/a", rules));
        }
        // Each `..` of a run is kept, and each one takes a name when there is one.
        for rules in [UNIX, WINDOWS] {
            none_same(
                rules,
                "../../a",
                &["../a", "a", "../../../a", "../../b/../a/.."],
            );
            assert!(same_path_resolving_dots("../../a", "../../a", rules));
            assert!(same_path_resolving_dots("x/../../a", "../a", rules));
            assert!(same_path_resolving_dots("a/b/../../../c", "../c", rules));
            assert!(same_path_resolving_dots(
                "a/b/../../../../c",
                "../../c",
                rules
            ));
        }
        // ...and a drive's own folder is not a root: it does not swallow it.
        assert!(!same_path_resolving_dots(r"C:..\a", r"C:a", WINDOWS));
        assert!(same_path_resolving_dots(r"C:..\a", r"C:..\a", WINDOWS));
    }

    // ---- the rules are the argument, not the system -----------------------------

    #[test]
    fn the_native_rules_are_those_of_the_system_running() {
        assert_eq!(Rules::native() == Rules::Windows, cfg!(windows));
    }

    #[test]
    fn both_rules_give_their_answer_on_every_system() {
        // The same two spellings, told apart only by the rules.
        let (a, b) = (r"/home/dev\k", "/home/dev/k");
        assert!(same_path(a, b, WINDOWS));
        assert!(!same_path(a, b, UNIX));
        let (a, b) = ("/home/dev/K", "/home/dev/k");
        assert!(same_path(a, b, WINDOWS));
        assert!(!same_path(a, b, UNIX));
    }

    // ---- ~ ---------------------------------------------------------------------

    fn tilde(path: &str, home: Option<&str>, rules: Rules) -> Option<String> {
        expand_tilde(path, home, rules)
    }

    #[test]
    fn a_tilde_is_the_home_and_what_follows_it_joins_with_a_slash() {
        for rules in [UNIX, WINDOWS] {
            let home = Some("/home/dev");
            assert_eq!(tilde("~", home, rules).as_deref(), Some("/home/dev"));
            assert_eq!(
                tilde("~/.ssh/id", home, rules).as_deref(),
                Some("/home/dev/.ssh/id")
            );
            // Nothing to expand: given back as it is, with no home needed.
            for plain in ["/x/~/y", "x~", "id", "", "C:/~"] {
                assert_eq!(tilde(plain, None, rules).as_deref(), Some(plain));
            }
            // `~user` is not supported: an ordinary path.
            assert_eq!(
                tilde("~other/.ssh/id", home, rules).as_deref(),
                Some("~other/.ssh/id")
            );
            // A path that needs the home, without one.
            assert_eq!(tilde("~", None, rules), None);
            assert_eq!(tilde("~/x", None, rules), None);
        }
    }

    #[test]
    fn a_backslash_after_the_tilde_is_the_home_only_under_the_rules_of_windows() {
        let home = Some(r"C:\Users\dev");
        assert_eq!(
            tilde(r"~\.ssh\id", home, WINDOWS).as_deref(),
            Some(r"C:\Users\dev/.ssh\id")
        );
        assert_eq!(tilde(r"~\x", None, WINDOWS), None);
        // Elsewhere it is a name that starts with a tilde, and needs no home.
        assert_eq!(
            tilde(r"~\.ssh\id", home, UNIX).as_deref(),
            Some(r"~\.ssh\id")
        );
        assert_eq!(tilde(r"~\x", None, UNIX).as_deref(), Some(r"~\x"));
        assert!(!same_path(
            &tilde(r"~\id", Some("/home/dev"), UNIX).unwrap(),
            "/home/dev/id",
            UNIX
        ));
        assert!(same_path(
            &tilde(r"~\id", Some("/home/dev"), WINDOWS).unwrap(),
            "/home/dev/id",
            WINDOWS
        ));
    }

    #[test]
    fn a_home_that_ends_in_a_separator_gives_no_doubled_one() {
        assert_eq!(tilde("~/x", Some("/"), UNIX).as_deref(), Some("/x"));
        assert_eq!(
            tilde("~/x", Some("/home/dev/"), UNIX).as_deref(),
            Some("/home/dev/x")
        );
        assert_eq!(tilde("~/x", Some(r"C:\"), WINDOWS).as_deref(), Some("C:/x"));
        assert_eq!(
            tilde("~/x", Some(r"C:\Users\dev\"), WINDOWS).as_deref(),
            Some("C:\\Users\\dev/x")
        );
    }
}
