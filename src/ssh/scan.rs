//! A minimal scan of an ssh config for `Host` names.
//!
//! This is *not* an ssh_config parser. It only finds the concrete host names
//! (following `Include`) so that each one can be resolved with `ssh -G`, which
//! is the source of truth for what the configuration means. Everything else is
//! ignored: `Match` blocks, patterns (`*`, `?`, `!`), and all other keywords.
//!
//! [`find_include`] uses the same walk to answer a different question, read-only:
//! whether the config already includes a given file.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::domain::Warning;
use crate::pathtext::{Rules, expand_tilde, same_path};
use crate::text::escape_control;

/// How deeply `Include` directives are followed.
const MAX_INCLUDE_DEPTH: usize = 8;

/// Host names found in a config, in order of appearance.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub names: Vec<String>,
    pub warnings: Vec<Warning>,
}

/// Scans `config` for host names.
///
/// Relative `Include` paths resolve against `ssh_dir` (like ssh does for the
/// user config) and a leading `~` against `home`. A missing `config` is an
/// empty result, not an error.
pub fn scan_host_names(
    config: &Path,
    ssh_dir: &Path,
    home: Option<&Path>,
) -> io::Result<ScanReport> {
    let mut scanner = Scanner {
        ssh_dir,
        home,
        names: Vec::new(),
        seen_names: HashSet::new(),
        visited: HashSet::new(),
        stack: Vec::new(),
        warnings: Vec::new(),
        target: None,
        found: None,
    };
    scanner.scan_file(config, 0, true)?;
    Ok(ScanReport {
        names: scanner.names,
        warnings: scanner.warnings,
    })
}

/// Whether an ssh config includes a given file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeStatus {
    /// There is no config file at all.
    NoConfigFile,
    /// The config has no `Include` that reaches the file.
    Missing,
    /// It has one, before any `Host` or `Match` line of the file it is in, so it
    /// applies to everything.
    Found,
    /// It has one, but after a `Host` or `Match` line: ssh then applies it only
    /// to the hosts of that block, so the file's hosts are not generally
    /// available. It has to be moved to the top.
    FoundInsideBlock,
}

/// [`find_include`]'s result: whether the config includes the file, and any
/// warning found while checking, such as an include loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeCheck {
    pub status: IncludeStatus,
    pub warnings: Vec<Warning>,
}

/// Looks for an `Include` of `target` in `config`, following `Include`s as the
/// scan for host names does, and reads nothing else. Nothing is written.
///
/// An include reaches `target` when it names it, as a path or with wildcards in
/// the file name, or when a file it includes does. A `config` that does not
/// exist is [`IncludeStatus::NoConfigFile`]; one that cannot be read is an error.
///
/// A file that includes itself, directly or through other files, is a warning:
/// ssh has no such tolerance and refuses to start with "Too many recursive
/// configuration includes", so a status that otherwise looks fine (the file is
/// included, just as it should be) can still describe a config that does not
/// work. See [`Scanner::scan_file`] for how the loop itself is not followed.
pub fn find_include(
    config: &Path,
    ssh_dir: &Path,
    home: Option<&Path>,
    target: &Path,
) -> io::Result<IncludeCheck> {
    match fs::metadata(config) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(IncludeCheck {
                status: IncludeStatus::NoConfigFile,
                warnings: Vec::new(),
            });
        }
        _ => {}
    }
    let mut scanner = Scanner {
        ssh_dir,
        home,
        names: Vec::new(),
        seen_names: HashSet::new(),
        visited: HashSet::new(),
        stack: Vec::new(),
        warnings: Vec::new(),
        target: Some(resolved(target)),
        found: None,
    };
    scanner.scan_file(config, 0, true)?;
    Ok(IncludeCheck {
        status: scanner.found.unwrap_or(IncludeStatus::Missing),
        warnings: scanner.warnings,
    })
}

/// `path` as the disk resolves it when the file exists (links followed, `.` and
/// `..` applied, on Windows the `\\?\` form), and as it was written when it does not.
fn resolved(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Whether `included` and `target` are the same file, by [`same_path`] on what the
/// disk says of them. A path that could not be resolved and still has a `..` in it is
/// not the same as anything: the words cannot say what it reaches.
fn same_file(included: &Path, target: &Path, rules: Rules) -> bool {
    same_path(
        &resolved(included).to_string_lossy(),
        &target.to_string_lossy(),
        rules,
    )
}

struct Scanner<'a> {
    ssh_dir: &'a Path,
    home: Option<&'a Path>,
    names: Vec<String>,
    seen_names: HashSet<String>,
    /// Every file scanned so far, so a diamond (two branches that legitimately
    /// include the same file) is only read once. Does not by itself say a file
    /// includes itself: [`Self::stack`] is what tells the two apart.
    visited: HashSet<PathBuf>,
    /// The files currently being expanded, outermost first: the chain of
    /// `Include`s that led here. A file already on it is a loop, not a diamond.
    stack: Vec<PathBuf>,
    warnings: Vec<Warning>,
    /// The file [`find_include`] looks for, as the disk resolves it ([`resolved`]).
    target: Option<PathBuf>,
    /// What was found about it. `Found` is not replaced by `FoundInsideBlock`.
    found: Option<IncludeStatus>,
}

impl Scanner<'_> {
    /// Reads `path` for `Host`/`Match` names and `Include`s. Follows `Include`s
    /// depth-first; a file already an ancestor of this call (on [`Self::stack`])
    /// is a loop and is warned about, not followed again, so a config that
    /// includes itself cannot hang this scan the way it hangs ssh's own.
    fn scan_file(&mut self, path: &Path, depth: usize, top_level: bool) -> io::Result<()> {
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if self.stack.contains(&key) {
            self.warnings.push(Warning::new(format!(
                "{} includes itself, directly or through other included files. ssh will \
                 refuse to start with \"Too many recursive configuration includes\" until \
                 the loop is broken.",
                path.display()
            )));
            return Ok(());
        }
        if !self.visited.insert(key.clone()) {
            return Ok(());
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) if top_level => return Err(err),
            Err(err) => {
                self.warnings.push(Warning::new(format!(
                    "Could not read the included file {}: {err}",
                    path.display()
                )));
                return Ok(());
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        self.stack.push(key);

        // Whether a `Host` or `Match` line came before, in this file.
        let mut in_block = false;
        for line in text.lines() {
            let Some((keyword, args)) = split_directive(line) else {
                continue;
            };
            match keyword.as_str() {
                "match" => in_block = true,
                "host" => {
                    in_block = true;
                    for arg in args {
                        if is_pattern(&arg) {
                            continue;
                        }
                        if self.seen_names.insert(arg.to_ascii_lowercase()) {
                            self.names.push(arg);
                        }
                    }
                }
                "include" => {
                    if depth >= MAX_INCLUDE_DEPTH {
                        self.warnings.push(Warning::new(format!(
                            "Ignored an Include in {}: includes are nested more than \
                             {MAX_INCLUDE_DEPTH} levels deep.",
                            path.display()
                        )));
                        continue;
                    }
                    for arg in args {
                        for included in self.expand_include(&arg) {
                            self.note_include(&included, in_block);
                            self.scan_file(&included, depth + 1, false)?;
                        }
                    }
                }
                _ => {}
            }
        }
        self.stack.pop();
        Ok(())
    }

    /// Records that `included` was included, if it is the file looked for.
    fn note_include(&mut self, included: &Path, in_block: bool) {
        let Some(target) = &self.target else {
            return;
        };
        if !same_file(included, target, Rules::native()) {
            return;
        }
        // Applying everywhere wins over applying to one block.
        self.found = Some(if !in_block || self.found == Some(IncludeStatus::Found) {
            IncludeStatus::Found
        } else {
            IncludeStatus::FoundInsideBlock
        });
    }

    /// Resolves an `Include` argument to files. Wildcards are supported in the
    /// last path component only.
    fn expand_include(&mut self, arg: &str) -> Vec<PathBuf> {
        let home = self.home.map(Path::to_string_lossy);
        let mut path = expand_tilde(arg, home.as_deref(), Rules::native())
            .map_or_else(|| PathBuf::from(arg), PathBuf::from);
        if !path.is_absolute() {
            path = self.ssh_dir.join(path);
        }
        let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return Vec::new();
        };
        let parent = path.parent().unwrap_or(Path::new("")).to_path_buf();

        if has_wildcard(&parent.to_string_lossy()) {
            self.warnings.push(Warning::new(format!(
                "Ignored the Include pattern {:?}: wildcards are only supported in the file \
                 name, not in directory names.",
                escape_control(arg)
            )));
            return Vec::new();
        }
        if !has_wildcard(&file_name) {
            return vec![path];
        }

        let Ok(entries) = fs::read_dir(&parent) else {
            return Vec::new();
        };
        let mut matches: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let hidden_ok = file_name.starts_with('.') || !name.starts_with('.');
                hidden_ok
                    && glob_match(&file_name, &name)
                    && fs::metadata(entry.path()).is_ok_and(|m| m.is_file())
            })
            .map(|entry| entry.path())
            .collect();
        matches.sort();
        matches
    }
}

fn has_wildcard(text: &str) -> bool {
    text.contains(['*', '?'])
}

/// Patterns cannot be resolved to a single host.
fn is_pattern(name: &str) -> bool {
    name.contains(['*', '?', '!'])
}

/// Splits a config line into a lowercase keyword and its arguments.
/// Returns `None` for blank lines and comments.
fn split_directive(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let keyword_end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let keyword = line[..keyword_end].to_ascii_lowercase();
    let mut rest = line[keyword_end..].trim_start();
    if let Some(after_equals) = rest.strip_prefix('=') {
        rest = after_equals.trim_start();
    }
    Some((keyword, tokenize(rest)))
}

/// Splits arguments on whitespace, honoring double quotes and stopping at an
/// unquoted `#` that starts a token.
fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut in_quotes = false;
    for c in text.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            '#' if !in_quotes && !started => break,
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        tokens.push(current);
    }
    tokens
}

/// Shell-style matching with `*` and `?` only.
fn glob_match(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p + 1;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_text(text: &str) -> ScanReport {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        fs::write(&config, text).unwrap();
        scan_host_names(&config, dir.path(), None).unwrap()
    }

    #[test]
    fn finds_concrete_host_names_only() {
        let report = scan_text(
            "Host web\n  HostName web.example.com\n\
             Host db1 db2 *.internal !skipped ?x\n\
             Host *\n  User me\n\
             Match host foo\n  User z\n\
             HostName ignored.example.com\n",
        );
        assert_eq!(report.names, ["web", "db1", "db2"]);
    }

    #[test]
    fn keywords_are_case_insensitive_and_accept_equals() {
        let report = scan_text("HOST upper\nhost=eq\nHost = spaced\n  host\tabc\n");
        assert_eq!(report.names, ["upper", "eq", "spaced", "abc"]);
    }

    #[test]
    fn comments_and_quotes_are_handled() {
        let report = scan_text(
            "# Host commented\nHost real # trailing comment\nHost \"quoted\"\nHost a#b\n",
        );
        assert_eq!(report.names, ["real", "quoted", "a#b"]);
    }

    #[test]
    fn duplicate_names_are_reported_once_ignoring_case() {
        let report = scan_text("Host Web\nHost web\nHost WEB other\n");
        assert_eq!(report.names, ["Web", "other"]);
    }

    #[test]
    fn a_missing_config_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let report = scan_host_names(&dir.path().join("nope"), dir.path(), None).unwrap();
        assert_eq!(report, ScanReport::default());
    }

    #[test]
    fn an_unreadable_top_level_config_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // A directory cannot be read as a file.
        assert!(scan_host_names(dir.path(), dir.path(), None).is_err());
    }

    #[test]
    fn follows_includes_relative_to_the_ssh_dir() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("conf.d")).unwrap();
        fs::write(dir.path().join("conf.d/10-a.conf"), "Host from-a\n").unwrap();
        fs::write(dir.path().join("conf.d/20-b.conf"), "Host from-b\n").unwrap();
        fs::write(dir.path().join("conf.d/.hidden"), "Host hidden\n").unwrap();
        fs::write(dir.path().join("conf.d/notes.txt"), "Host from-txt\n").unwrap();
        fs::write(dir.path().join("single"), "Host from-single\n").unwrap();
        let config = dir.path().join("config");
        fs::write(
            &config,
            "Host first\nInclude conf.d/*.conf single missing-file\nHost last\n",
        )
        .unwrap();

        let report = scan_host_names(&config, dir.path(), None).unwrap();
        assert_eq!(
            report.names,
            ["first", "from-a", "from-b", "from-single", "last"]
        );
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn tilde_includes_use_the_given_home() {
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join("extra"), "Host from-home\n").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        fs::write(&config, "Include ~/extra\n").unwrap();
        let report = scan_host_names(&config, dir.path(), Some(home.path())).unwrap();
        assert_eq!(report.names, ["from-home"]);
    }

    #[test]
    fn include_cycles_terminate() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), "Host in-a\nInclude b\n").unwrap();
        fs::write(
            dir.path().join("b"),
            "Host in-b\nInclude a\nInclude config\n",
        )
        .unwrap();
        let config = dir.path().join("config");
        fs::write(&config, "Host top\nInclude a\n").unwrap();
        let report = scan_host_names(&config, dir.path(), None).unwrap();
        assert_eq!(report.names, ["top", "in-a", "in-b"]);
    }

    #[test]
    fn deeply_nested_includes_stop_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..12 {
            fs::write(
                dir.path().join(format!("f{i}")),
                format!("Host h{i}\nInclude f{}\n", i + 1),
            )
            .unwrap();
        }
        let config = dir.path().join("config");
        fs::write(&config, "Include f0\n").unwrap();
        let report = scan_host_names(&config, dir.path(), None).unwrap();
        assert_eq!(report.names.len(), MAX_INCLUDE_DEPTH);
        assert!(report.warnings[0].message().contains("nested more than"));
    }

    #[test]
    fn wildcards_in_directory_names_are_reported_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        fs::write(&config, "Include */conf\nHost after\n").unwrap();
        let report = scan_host_names(&config, dir.path(), None).unwrap();
        assert_eq!(report.names, ["after"]);
        assert_eq!(report.warnings.len(), 1);
        assert!(
            report.warnings[0]
                .message()
                .contains("wildcards are only supported")
        );
    }

    #[test]
    fn non_utf8_content_does_not_abort_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        fs::write(&config, b"Host ok\nHost bad\xff\n".as_slice()).unwrap();
        let report = scan_host_names(&config, dir.path(), None).unwrap();
        assert_eq!(report.names[0], "ok");
        assert_eq!(report.names.len(), 2);
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.conf", "a.conf"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("*.conf", "a.txt"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("abc", "abcd"));
        assert!(glob_match("", ""));
    }

    // ---- find_include ----------------------------------------------------------

    /// A `~/.ssh` with the given files, and the export target in it.
    struct Ssh {
        dir: tempfile::TempDir,
    }

    impl Ssh {
        fn new(files: &[(&str, &str)]) -> Ssh {
            let dir = tempfile::tempdir().unwrap();
            for (name, text) in files {
                let path = dir.path().join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, text).unwrap();
            }
            Ssh { dir }
        }

        fn target(&self) -> PathBuf {
            self.dir.path().join("bifrost_config")
        }

        fn check(&self) -> io::Result<IncludeStatus> {
            self.check_full().map(|check| check.status)
        }

        /// [`Self::check`] with the warnings too.
        fn check_full(&self) -> io::Result<IncludeCheck> {
            // The home is the parent of the ssh directory, so `~/x` is `<dir>/x`.
            find_include(
                &self.dir.path().join("config"),
                self.dir.path(),
                Some(self.dir.path()),
                &self.target(),
            )
        }
    }

    #[test]
    fn no_config_file_is_told_apart_from_a_config_without_the_include() {
        let none = Ssh::new(&[("bifrost_config", "")]);
        assert_eq!(none.check().unwrap(), IncludeStatus::NoConfigFile);
        let without = Ssh::new(&[
            ("config", "Host web\n  HostName x\n"),
            ("bifrost_config", ""),
        ]);
        assert_eq!(without.check().unwrap(), IncludeStatus::Missing);
        let empty = Ssh::new(&[("config", ""), ("bifrost_config", "")]);
        assert_eq!(empty.check().unwrap(), IncludeStatus::Missing);
    }

    #[test]
    fn every_way_of_naming_the_file_counts_when_it_comes_first() {
        // `{absolute}` is the target's own path, which is only known once the
        // directory exists.
        for line in [
            "Include ~/bifrost_config",
            "Include bifrost_config",
            "Include {absolute}",
            "Include \"{absolute}\"",
            "include bifrost_config",
            "INCLUDE=bifrost_config",
            "Include bifrost_*",
            "Include *",
            "Include ./bifrost_config",
            "Include other_config bifrost_config",
            "  Include   bifrost_config   # the hosts of Bifrost",
        ] {
            let ssh = Ssh::new(&[("bifrost_config", "# Generated by Bifrost\n")]);
            let line = line.replace("{absolute}", &ssh.target().display().to_string());
            fs::write(
                ssh.dir.path().join("config"),
                format!("{line}\nHost web\n  HostName x\n"),
            )
            .unwrap();
            assert_eq!(ssh.check().unwrap(), IncludeStatus::Found, "{line}");
        }
    }

    #[test]
    fn things_that_look_like_it_but_do_not_reach_the_file_do_not_count() {
        for text in [
            "Include other_config\n",
            "Include bifrost_config.bak\n",
            "# Include bifrost_config\n",
            "Host web\n  HostName bifrost_config\n",
            "Include bifrost_config2\n",
            "Include sub/bifrost_config\n",
            "Include nothing_*\n",
            "IncludeX bifrost_config\n",
        ] {
            let ssh = Ssh::new(&[
                ("config", text),
                ("bifrost_config", ""),
                ("other_config", ""),
                ("bifrost_config.bak", ""),
                ("bifrost_config2", ""),
            ]);
            assert_eq!(ssh.check().unwrap(), IncludeStatus::Missing, "{text:?}");
        }
    }

    #[test]
    fn an_include_after_a_host_or_match_line_only_applies_to_that_block() {
        for text in [
            "Host web\n  HostName x\nInclude bifrost_config\n",
            "Match host web\n  User me\nInclude bifrost_config\n",
            "Host *\nInclude bifrost_config\n",
        ] {
            let ssh = Ssh::new(&[("config", text), ("bifrost_config", "")]);
            assert_eq!(
                ssh.check().unwrap(),
                IncludeStatus::FoundInsideBlock,
                "{text:?}"
            );
        }
        // Comments and other keywords before it do not make a block.
        let ssh = Ssh::new(&[
            (
                "config",
                "# mine\nAddKeysToAgent yes\nInclude bifrost_config\nHost web\n",
            ),
            ("bifrost_config", ""),
        ]);
        assert_eq!(ssh.check().unwrap(), IncludeStatus::Found);
    }

    #[test]
    fn the_include_that_applies_everywhere_wins_over_one_inside_a_block() {
        let ssh = Ssh::new(&[
            (
                "config",
                "Include bifrost_config\nHost web\n  HostName x\nInclude bifrost_config\n",
            ),
            ("bifrost_config", ""),
        ]);
        assert_eq!(ssh.check().unwrap(), IncludeStatus::Found);
        let reversed = Ssh::new(&[
            ("config", "Host web\nInclude bifrost_config\n"),
            ("bifrost_config", ""),
        ]);
        assert_eq!(reversed.check().unwrap(), IncludeStatus::FoundInsideBlock);
    }

    #[test]
    fn an_include_reached_through_another_included_file_counts() {
        let ssh = Ssh::new(&[
            ("config", "Include config.d/*\n"),
            ("config.d/10-mine", "Include ~/bifrost_config\n"),
            ("bifrost_config", ""),
        ]);
        assert_eq!(ssh.check().unwrap(), IncludeStatus::Found);
        // What decides is the position in the file that has the line.
        let nested = Ssh::new(&[
            ("config", "Include config.d/*\n"),
            ("config.d/10-mine", "Host x\nInclude ~/bifrost_config\n"),
            ("bifrost_config", ""),
        ]);
        assert_eq!(nested.check().unwrap(), IncludeStatus::FoundInsideBlock);
    }

    #[test]
    fn a_file_that_includes_itself_or_loops_does_not_hang() {
        let ssh = Ssh::new(&[
            ("config", "Include config\nInclude a\n"),
            ("a", "Include config\nInclude a\n"),
            ("bifrost_config", ""),
        ]);
        let check = ssh.check_full().unwrap();
        assert_eq!(check.status, IncludeStatus::Missing);
        assert!(
            !check.warnings.is_empty(),
            "the loop itself is warned about"
        );
    }

    #[test]
    fn a_status_that_looks_fine_still_warns_when_the_file_that_reaches_it_loops() {
        // config includes bifrost_config, which is exactly what should happen -
        // except bifrost_config here also includes itself, which makes ssh
        // refuse to start. `Found` alone would say everything is fine.
        let ssh = Ssh::new(&[
            ("config", "Include bifrost_config\n"),
            (
                "bifrost_config",
                "Include bifrost_config\nHost web\n  HostName x\n",
            ),
        ]);
        let check = ssh.check_full().unwrap();
        assert_eq!(check.status, IncludeStatus::Found);
        assert_eq!(check.warnings.len(), 1, "{:?}", check.warnings);
        let message = check.warnings[0].message();
        assert!(message.contains("includes itself"), "{message}");
        assert!(
            message.contains("Too many recursive configuration includes"),
            "{message}"
        );
    }

    #[test]
    fn a_loop_elsewhere_in_the_config_is_still_warned_about() {
        // The cycle is between two files that are not the export target at all;
        // ssh would still refuse the whole file for it.
        let ssh = Ssh::new(&[
            ("config", "Include a\nInclude bifrost_config\n"),
            ("a", "Include b\n"),
            ("b", "Include a\n"),
            ("bifrost_config", ""),
        ]);
        let check = ssh.check_full().unwrap();
        assert_eq!(check.status, IncludeStatus::Found);
        assert_eq!(check.warnings.len(), 1, "{:?}", check.warnings);
        assert!(check.warnings[0].message().contains("includes itself"));
    }

    #[test]
    fn two_branches_that_legitimately_share_a_file_are_not_a_loop() {
        // A diamond, not a cycle: `shared` is included from two places, but
        // never while it is still being expanded. No warning is warranted.
        let ssh = Ssh::new(&[
            ("config", "Include a\nInclude b\nInclude bifrost_config\n"),
            ("a", "Include shared\n"),
            ("b", "Include shared\n"),
            ("shared", "Host from-shared\n"),
            ("bifrost_config", ""),
        ]);
        let check = ssh.check_full().unwrap();
        assert_eq!(check.status, IncludeStatus::Found);
        assert!(check.warnings.is_empty(), "{:?}", check.warnings);
    }

    #[test]
    fn the_target_is_matched_as_a_file_not_as_text() {
        // Two spellings of one file, through a symbolic link.
        #[cfg(unix)]
        {
            let ssh = Ssh::new(&[("config", "Include linked\n"), ("bifrost_config", "")]);
            std::os::unix::fs::symlink(ssh.target(), ssh.dir.path().join("linked")).unwrap();
            assert_eq!(ssh.check().unwrap(), IncludeStatus::Found);
        }
        // A target that does not exist yet is matched by its path.
        let ssh = Ssh::new(&[("config", "Include ~/bifrost_config\n")]);
        assert_eq!(ssh.check().unwrap(), IncludeStatus::Found);
    }

    #[test]
    fn nothing_is_written_and_a_config_that_cannot_be_read_is_an_error() {
        let ssh = Ssh::new(&[
            ("config", "Include bifrost_config\n"),
            ("bifrost_config", "x"),
        ]);
        let before: Vec<_> = fs::read_dir(ssh.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        ssh.check().unwrap();
        let after: Vec<_> = fs::read_dir(ssh.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(before.len(), after.len());
        assert_eq!(fs::read_to_string(ssh.target()).unwrap(), "x");

        // A directory where the config should be: it exists and cannot be read.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("config")).unwrap();
        let result = find_include(
            &dir.path().join("config"),
            dir.path(),
            None,
            &dir.path().join("bifrost_config"),
        );
        assert!(result.is_err());
    }

    // ---- which file an include reaches: both ways of writing a path ---------------

    #[test]
    fn under_the_rules_of_windows_the_same_file_is_found_however_it_is_written() {
        // None of these exist, so the words are all there is to go by.
        let target = Path::new(r"C:\Users\Dev\.ssh\bifrost_config");
        for included in [
            r"C:\Users\Dev\.ssh\bifrost_config",
            "C:/Users/Dev/.ssh/bifrost_config",
            r"c:\users\dev\.ssh\BIFROST_CONFIG",
            r"C:\Users/Dev\.ssh/./bifrost_config",
            r"\\?\C:\Users\Dev\.ssh\bifrost_config",
        ] {
            assert!(
                same_file(Path::new(included), target, Rules::Windows),
                "{included}"
            );
        }
        for included in [
            r"D:\Users\Dev\.ssh\bifrost_config",
            r"C:\Users\Dev\.ssh\bifrost_config2",
            r"C:\Users\Dev\bifrost_config",
            r"\Users\Dev\.ssh\bifrost_config",
            "bifrost_config",
        ] {
            assert!(
                !same_file(Path::new(included), target, Rules::Windows),
                "{included}"
            );
        }
    }

    #[test]
    fn under_the_rules_of_the_others_case_and_backslashes_count() {
        let target = Path::new("/home/dev/.ssh/bifrost_config");
        for included in [
            "/home/dev/.ssh/bifrost_config",
            "/home/dev//.ssh/./bifrost_config",
        ] {
            assert!(
                same_file(Path::new(included), target, Rules::Unix),
                "{included}"
            );
        }
        for included in [
            "/home/dev/.ssh/Bifrost_Config",
            r"/home/dev/.ssh\bifrost_config",
            "bifrost_config",
        ] {
            assert!(
                !same_file(Path::new(included), target, Rules::Unix),
                "{included}"
            );
        }
    }

    #[test]
    fn a_path_that_cannot_be_resolved_and_has_dot_dot_in_it_is_not_the_file() {
        // Neither exists, so nothing says what `x/..` is.
        for rules in [Rules::Unix, Rules::Windows] {
            let target = Path::new("/home/dev/.ssh/bifrost_config");
            for included in [
                "/home/dev/.ssh/x/../bifrost_config",
                "/home/dev/.ssh/bifrost_config/../bifrost_config",
            ] {
                assert!(!same_file(Path::new(included), target, rules), "{included}");
            }
            // Nor is it when the target is the one written with it.
            let with_dots = Path::new("/home/dev/x/../.ssh/bifrost_config");
            assert!(!same_file(with_dots, with_dots, rules));
        }
    }

    #[test]
    fn a_dot_dot_that_the_disk_can_resolve_is_resolved_by_the_disk() {
        // It exists, so `sub/..` is what the disk says: the folder itself.
        let ssh = Ssh::new(&[
            ("config", "Include sub/../bifrost_config\n"),
            ("sub/keep", ""),
            ("bifrost_config", ""),
        ]);
        assert_eq!(ssh.check().unwrap(), IncludeStatus::Found);
        // Not there: only the words are left, and they are not enough.
        let absent = Ssh::new(&[("config", "Include nowhere/../bifrost_config\n")]);
        assert_eq!(absent.check().unwrap(), IncludeStatus::Missing);
    }

    #[cfg(unix)]
    #[test]
    fn an_include_through_a_link_is_the_file_it_leads_to() {
        let ssh = Ssh::new(&[
            ("real/bifrost_config", ""),
            ("config", "Include link/bifrost_config\n"),
        ]);
        std::os::unix::fs::symlink(ssh.dir.path().join("real"), ssh.dir.path().join("link"))
            .unwrap();
        let through_link = find_include(
            &ssh.dir.path().join("config"),
            ssh.dir.path(),
            Some(ssh.dir.path()),
            &ssh.dir.path().join("real/bifrost_config"),
        )
        .unwrap();
        assert_eq!(through_link.status, IncludeStatus::Found);
    }

    #[cfg(unix)]
    #[test]
    fn a_backslash_after_the_tilde_is_not_the_home_here() {
        // On Unix `~\bifrost_config` is a name in the ssh directory, and not the
        // exported file that `~/bifrost_config` would be.
        let ssh = Ssh::new(&[
            ("bifrost_config", ""),
            ("config", "Include ~\\bifrost_config\n"),
        ]);
        assert_eq!(ssh.check().unwrap(), IncludeStatus::Missing);
        let slash = Ssh::new(&[
            ("bifrost_config", ""),
            ("config", "Include ~/bifrost_config\n"),
        ]);
        assert_eq!(slash.check().unwrap(), IncludeStatus::Found);
    }

    // A disk that tells `A` from `a` (not the default one of macOS or Windows).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_in_another_case_is_another_file_on_linux() {
        let ssh = Ssh::new(&[
            ("bifrost_config", ""),
            ("config", "Include BIFROST_CONFIG\n"),
        ]);
        assert_eq!(ssh.check().unwrap(), IncludeStatus::Missing);
    }

    #[cfg(unix)]
    #[test]
    fn a_target_given_through_a_link_is_the_file_it_leads_to() {
        let ssh = Ssh::new(&[
            ("real/bifrost_config", ""),
            ("config", "Include real/bifrost_config\n"),
        ]);
        std::os::unix::fs::symlink(ssh.dir.path().join("real"), ssh.dir.path().join("link"))
            .unwrap();
        let status = find_include(
            &ssh.dir.path().join("config"),
            ssh.dir.path(),
            Some(ssh.dir.path()),
            &ssh.dir.path().join("link/bifrost_config"),
        )
        .unwrap();
        assert_eq!(status.status, IncludeStatus::Found);
    }
}
