//! `bifrost list`, run as the real binary against a temporary config directory.
//!
//! The environment is set on the child process only; the test process's own
//! environment and the real config directory are never touched.

use std::path::Path;
use std::process::{Command, Output};

use bifrost_ssh::domain::{Host, Hosts};
use bifrost_ssh::store::{HOSTS_FILE, Store};

fn bifrost_list(config_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("list")
        .env("BIFROST_CONFIG_DIR", config_dir)
        .env_remove("NO_COLOR")
        .output()
        .expect("the bifrost binary should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be UTF-8")
}

#[test]
fn an_empty_store_prints_a_friendly_message_and_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let output = bifrost_list(dir.path());

    assert!(output.status.success());
    assert_eq!(stdout(&output), "");
    assert!(
        stderr(&output).contains("No saved hosts yet"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn saved_hosts_are_printed_one_per_line() {
    let dir = tempfile::tempdir().unwrap();
    // A directory that Bifrost creates itself has the private permissions it
    // expects, so loading it gives no warnings.
    let config = dir.path().join("bifrost");
    let mut hosts = Hosts::new();
    hosts.add(Host::new("web", "192.0.2.1")).unwrap();
    hosts.add(Host::new("db", "192.0.2.2")).unwrap();
    Store::at(&config).save(&hosts).unwrap();

    let output = bifrost_list(&config);

    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    let mut names: Vec<_> = text.lines().collect();
    names.sort_unstable();
    assert_eq!(names, ["db", "web"]);
    assert_eq!(stderr(&output), "");
}

#[test]
fn a_corrupt_store_fails_with_a_clear_message_and_a_non_zero_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(HOSTS_FILE),
        "version = 1\n\n[[hosts]]\nname = \"bad name\"\nhostname = \"192.0.2.1\"\n",
    )
    .unwrap();

    let output = bifrost_list(dir.path());

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    let message = stderr(&output);
    assert!(message.starts_with("bifrost: error: "), "{message}");
    assert!(message.contains(HOSTS_FILE), "{message}");
    assert!(message.contains("invalid host (line 3)"), "{message}");
    assert!(message.contains("hosts.toml.bak"), "{message}");
}

#[test]
fn control_characters_in_a_corrupt_store_never_reach_the_terminal() {
    let dir = tempfile::tempdir().unwrap();
    // A raw ESC byte inside a TOML string is a parse error, and the parser's
    // message may quote the offending line.
    std::fs::write(
        dir.path().join(HOSTS_FILE),
        "version = 1\n\n[[hosts]]\nname = \"a\x1b[2Jb\u{202e}c\"\n",
    )
    .unwrap();

    let output = bifrost_list(dir.path());

    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.starts_with("bifrost: error: "), "{message:?}");
    assert!(!message.contains('\x1b'), "{message:?}");
    assert!(!message.contains('\u{202e}'), "{message:?}");
}

#[test]
fn a_relative_config_dir_is_an_error_not_a_crash() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("list")
        .env("BIFROST_CONFIG_DIR", "relative/dir")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("absolute path"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_tui_refuses_to_start_without_a_terminal() {
    // The test harness captures stdio, so the child has no terminal.
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .env("BIFROST_CONFIG_DIR", dir.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    let message = stderr(&output);
    assert!(message.contains("interactive terminal"), "{message}");
    assert!(message.contains("bifrost list"), "{message}");
}
