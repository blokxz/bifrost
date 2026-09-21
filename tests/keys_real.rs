//! The keys code against the real `ssh-keygen` and `ssh-add`.
//!
//! `#[ignore]`: it needs the real OpenSSH tools. Run by hand, for example after
//! an OpenSSH upgrade:
//!
//! ```text
//! cargo test --test keys_real -- --ignored
//! ```
//!
//! It makes its own keys in a temporary directory and never touches `~/.ssh`. It
//! asks the agent that this session has, if any, only to list: it adds nothing.
//! The passphrase on one test key is the test's own, to show that reading keys
//! never asks for one.

use std::path::Path;
use std::process::{Command, Stdio};

use bifrost_ssh::ssh::agent::{AGENT_TIMEOUT, AgentState, list};
use bifrost_ssh::ssh::binary::{resolve_keygen, resolve_ssh_add};
use bifrost_ssh::ssh::keys::{SystemKeyTools, load_keys, parse_fingerprint};

fn make_key(keygen: &Path, dir: &Path, name: &str, kind: &[&str], passphrase: &str, comment: &str) {
    let status = Command::new(keygen)
        .args(["-q"])
        .args(kind)
        .args(["-N", passphrase, "-C", comment, "-f"])
        .arg(dir.join(name))
        .status()
        .expect("run ssh-keygen");
    assert!(status.success());
}

#[test]
#[ignore = "needs the real ssh-keygen"]
fn the_snapshot_agrees_with_what_the_real_ssh_keygen_says() {
    let keygen = resolve_keygen().expect("ssh-keygen");
    let dir = tempfile::tempdir().unwrap();
    make_key(
        &keygen,
        dir.path(),
        "plain",
        &["-t", "ed25519"],
        "",
        "dev laptop (work) <me@x>",
    );
    make_key(
        &keygen,
        dir.path(),
        "locked",
        &["-t", "rsa", "-b", "2048"],
        "test-only",
        "",
    );
    make_key(
        &keygen,
        dir.path(),
        "ecdsa",
        &["-t", "ecdsa", "-b", "256"],
        "",
        "ecdsa key",
    );
    std::fs::write(dir.path().join("config"), "Host x\n").unwrap();

    let tools = SystemKeyTools {
        keygen: Some(&keygen),
        ssh_add: None,
    };
    let snapshot = load_keys(&tools, dir.path());
    assert_eq!(snapshot.keys.len(), 3, "{snapshot:?}");

    for entry in &snapshot.keys {
        // What the tool prints for the same file, read by the same parser.
        let output = Command::new(&keygen)
            .args(["-l", "-f"])
            .arg(&entry.public)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let expected = parse_fingerprint(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap(),
        )
        .expect("the real output parses");
        assert_eq!(entry.fingerprint.as_ref(), Ok(&expected), "{}", entry.name);
    }
    let by_name = |name: &str| snapshot.keys.iter().find(|k| k.name == name).unwrap();
    let plain = by_name("plain").fingerprint.as_ref().unwrap();
    assert_eq!(plain.type_label(), "ed25519");
    assert_eq!(plain.comment.as_deref(), Some("dev laptop (work) <me@x>"));
    // A protected key is read without a passphrase, and an empty comment is none.
    let locked = by_name("locked").fingerprint.as_ref().unwrap();
    assert_eq!(locked.type_label(), "rsa 2048");
    assert_eq!(locked.comment, None);
    assert_eq!(
        by_name("ecdsa").fingerprint.as_ref().unwrap().type_label(),
        "ecdsa 256"
    );
}

#[test]
#[ignore = "needs the real ssh-keygen"]
fn a_file_that_is_not_a_key_is_reported_not_guessed() {
    let keygen = resolve_keygen().expect("ssh-keygen");
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("fake"), "x").unwrap();
    std::fs::write(dir.path().join("fake.pub"), "this is not a key\n").unwrap();
    let tools = SystemKeyTools {
        keygen: Some(&keygen),
        ssh_add: None,
    };
    let snapshot = load_keys(&tools, dir.path());
    let reason = snapshot.keys[0].fingerprint.as_ref().unwrap_err();
    assert!(
        reason.starts_with("ssh-keygen could not read it:"),
        "{reason}"
    );
}

#[test]
#[ignore = "needs the real ssh-add"]
fn whatever_agent_this_session_has_is_understood() {
    let ssh_add = resolve_ssh_add().expect("ssh-add");
    let state = list(&ssh_add, AGENT_TIMEOUT);
    // Any of these is a state this session can be in. Only "unknown" or
    // "unavailable" would mean the wording of this OpenSSH is not understood.
    assert!(
        matches!(
            state,
            AgentState::Running { .. } | AgentState::NotStarted | AgentState::Unreachable
        ),
        "{state:?}"
    );
    println!("the agent of this session: {state:?}");
}
