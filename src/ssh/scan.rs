//! A minimal scan of an ssh config for `Host` names.
//!
//! This is *not* an ssh_config parser. It only finds the concrete host names
//! (following `Include`) so that each one can be resolved with `ssh -G`, which
//! is the source of truth for what the configuration means. Everything else is
//! ignored: `Match` blocks, patterns (`*`, `?`, `!`), and all other keywords.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::domain::Warning;
use crate::domain::validate::expand_tilde;
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
        warnings: Vec::new(),
    };
    scanner.scan_file(config, 0, true)?;
    Ok(ScanReport {
        names: scanner.names,
        warnings: scanner.warnings,
    })
}

struct Scanner<'a> {
    ssh_dir: &'a Path,
    home: Option<&'a Path>,
    names: Vec<String>,
    seen_names: HashSet<String>,
    visited: HashSet<PathBuf>,
    warnings: Vec<Warning>,
}

impl Scanner<'_> {
    fn scan_file(&mut self, path: &Path, depth: usize, top_level: bool) -> io::Result<()> {
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !self.visited.insert(key) {
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

        for line in text.lines() {
            let Some((keyword, args)) = split_directive(line) else {
                continue;
            };
            match keyword.as_str() {
                "host" => {
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
                            self.scan_file(&included, depth + 1, false)?;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Resolves an `Include` argument to files. Wildcards are supported in the
    /// last path component only.
    fn expand_include(&mut self, arg: &str) -> Vec<PathBuf> {
        let mut path = expand_tilde(arg, self.home).unwrap_or_else(|| PathBuf::from(arg));
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
}
