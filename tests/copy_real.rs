//! Sending a public key to a real server, with the real `ssh`.
//!
//! `#[ignore]`: it needs a real server. Run by hand, for example against the
//! Incus container used for manual integration:
//!
//! ```text
//! BIFROST_TEST_SSH_TARGET=user@host[:port] cargo test --test copy_real -- --ignored --nocapture
//! ```
//!
//! What it needs from the server and from this machine:
//!
//! - This machine can already log in to the server without typing anything (an
//!   agent, or a default key), because the test has no terminal to type a
//!   password on. It runs with `BatchMode=yes`.
//! - The server's host key is already in your `known_hosts`: the test never
//!   accepts a new one.
//!
//! **It changes the server.** It adds one throwaway key, made for the test and
//! marked with a comment that names it, to `~/.ssh/authorized_keys`, and removes
//! that line again when it ends, even if a check failed. Nothing else there is
//! touched, and nothing on this machine is: the throwaway key lives in a
//! temporary directory.
//!
//! What it shows that the fake tests cannot: that the fixed remote command works
//! under the server's real shell, that the key arrives through the real ssh's
//! stdin, that sending it twice adds it once, and that the key then logs in.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bifrost_ssh::domain::{Host, Hosts};
use bifrost_ssh::ssh::authorize::read_public_key;
use bifrost_ssh::ssh::binary::resolve_ssh;
use bifrost_ssh::ssh::command::build_copy_args;
use bifrost_ssh::ssh::connect::{Exit, run_with_input};

/// What `BIFROST_TEST_SSH_TARGET` means: `user@host`, `user@host:port`,
/// `user@[ipv6]` or `user@[ipv6]:port` (the user is optional). Returns the
/// destination for ssh (no port, no brackets) and the port for `-p`.
///
/// A value that is not one of these is an error that shows it exactly as it was
/// given, so that a stray space, a newline or an odd bracket is visible, instead
/// of becoming a host name that ssh then fails to resolve.
fn parse_target(text: &str) -> Result<(String, String), String> {
    let bad = |why: &str| {
        Err(format!(
            "BIFROST_TEST_SSH_TARGET is {text:?}, which is not usable: {why}. Expected \
             user@host, user@host:port, user@[ipv6] or user@[ipv6]:port."
        ))
    };
    let text = text.trim();
    let (user, host_and_port) = match text.rsplit_once('@') {
        Some((user, rest)) => (Some(user), rest),
        None => (None, text),
    };
    if user.is_some_and(|user| user.is_empty() || !user.chars().all(is_user_char)) {
        return bad("the user has characters a user name does not");
    }

    let (host, port) = if let Some(bracketed) = host_and_port.strip_prefix('[') {
        let Some((host, after)) = bracketed.split_once(']') else {
            return bad("a '[' is not closed");
        };
        match after {
            "" => (host, None),
            after => match after.strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None => return bad("only ':port' may follow the ']'"),
            },
        }
    } else if host_and_port.matches(':').count() == 1 {
        let (host, port) = host_and_port.split_once(':').unwrap_or_default();
        (host, Some(port))
    } else {
        // No colon, or several: a bare IPv6 address has no port.
        (host_and_port, None)
    };

    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return bad("the host has characters a host name does not");
    }
    let port = match port {
        None => "22".to_string(),
        Some(port) => match port.parse::<u16>() {
            Ok(number) if number > 0 => number.to_string(),
            _ => return bad("the port is not a number from 1 to 65535"),
        },
    };
    let destination = match user {
        Some(user) => format!("{user}@{host}"),
        None => host.to_string(),
    };
    Ok((destination, port))
}

fn is_user_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// The server to test against, from `BIFROST_TEST_SSH_TARGET`, see
/// [`parse_target`]. Tests that need it say so and pass when it is not set, so
/// that `--ignored` without it is not a failure. A value that is set but wrong
/// fails the test, saying what it was.
fn target() -> Option<(String, String)> {
    let text = std::env::var("BIFROST_TEST_SSH_TARGET").ok()?;
    match parse_target(&text) {
        Ok(parsed) => Some(parsed),
        Err(problem) => panic!("{problem}"),
    }
}

/// Runs the real ssh on no terminal with `args` before `--`, and returns what it
/// printed on stdout and how it ended.
fn ssh_output(ssh: &Path, args: &[&str], destination: &str, remote: &str) -> (Option<i32>, String) {
    eprintln!("ran: ssh {} -- {destination} {remote}", args.join(" "));
    let output = Command::new(ssh)
        .args(args)
        .args(["--", destination, remote])
        .stdin(Stdio::null())
        .output()
        .expect("run the real ssh");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    )
}

/// Takes the throwaway key's line out of the server's `authorized_keys` when it
/// is dropped, whatever the test did. It logs in the way the person running the
/// test does, not with the throwaway key.
struct Cleanup {
    ssh: PathBuf,
    destination: String,
    port: String,
    marker: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        // grep exits 0 or 1 when it ran (1: nothing was left), and 2 when it did
        // not: then the file is left as it is.
        let script = format!(
            "cd && grep -vF '{m}' .ssh/authorized_keys > .ssh/.bifrost-test-tmp; \
             if [ $? -le 1 ]; then cat .ssh/.bifrost-test-tmp > .ssh/authorized_keys; fi; \
             rm -f .ssh/.bifrost-test-tmp",
            m = self.marker
        );
        let (code, _) = ssh_output(
            &self.ssh,
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                &self.port,
            ],
            &self.destination,
            &script,
        );
        if code != Some(0) {
            eprintln!(
                "COULD NOT REMOVE the throwaway key from {} ({code:?}). Remove the line with \
                 the comment {} from ~/.ssh/authorized_keys there.",
                self.destination, self.marker
            );
        }
    }
}

#[test]
#[ignore = "needs BIFROST_TEST_SSH_TARGET, a real server, and changes its authorized_keys"]
fn a_key_is_sent_once_however_often_and_then_logs_in() {
    let Some((destination, port)) = target() else {
        eprintln!("BIFROST_TEST_SSH_TARGET is not set; nothing tested");
        return;
    };
    let ssh = resolve_ssh().expect("the real ssh");

    // A key made for this test, marked so that it can be found and removed.
    let dir = tempfile::tempdir().unwrap();
    let marker = format!(
        "bifrost-copy-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let generated = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", &marker, "-f"])
        .arg(dir.path().join("throwaway"))
        .status()
        .expect("run ssh-keygen");
    assert!(generated.success());
    let key = read_public_key(dir.path(), "throwaway").expect("a valid public key");
    let blob = key.as_str().split(' ').nth(1).unwrap().to_string();

    // From here on the server holds the key, or may: take it out at the end.
    let _cleanup = Cleanup {
        ssh: ssh.clone(),
        destination: destination.clone(),
        port: port.clone(),
        marker: marker.clone(),
    };

    // The arguments Bifrost builds for a saved host that is this server, and
    // options that make ssh fail instead of asking, since there is no terminal.
    let (user, host) = match destination.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host.to_string()),
        None => (None, destination.clone()),
    };
    let mut saved = Host::new("target", host);
    saved.user = user;
    saved.port = port.parse::<u16>().ok().filter(|p| *p != 22);
    let hosts = Hosts::from_vec(vec![saved.clone()]).unwrap();
    let built = build_copy_args(&saved, &hosts).unwrap();
    let mut args: Vec<String> = built.as_slice().to_vec();
    let at = args.iter().position(|a| a == "--").unwrap();
    for (offset, option) in ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        .iter()
        .enumerate()
    {
        args.insert(at + offset, (*option).to_string());
    }

    let input = key.to_stdin().unwrap();
    for attempt in 1..=2 {
        let outcome = run_with_input(&ssh, &args, input.clone(), io::sink())
            .unwrap_or_else(|err| panic!("could not run ssh: {err}"));
        assert_eq!(
            outcome.exit,
            Exit::Code(0),
            "attempt {attempt}: ssh said {:?}",
            String::from_utf8_lossy(&outcome.stderr)
        );
    }

    // The key is in the file once, though it was sent twice.
    let with_key = [
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-p",
        &port,
        "-i",
    ];
    let key_file = dir.path().join("throwaway");
    let key_file = key_file.to_str().unwrap();
    let mut with_key: Vec<&str> = with_key.to_vec();
    with_key.push(key_file);

    let (code, out) = ssh_output(
        &ssh,
        &with_key,
        &destination,
        &format!("grep -cF '{blob}' .ssh/authorized_keys"),
    );
    assert_eq!(code, Some(0), "the new key does not log in");
    assert_eq!(out, "1", "the key must be in authorized_keys exactly once");

    // And the directory and the file are private, as the script makes them when
    // it makes them (checked only when it was Bifrost that made them: it is not
    // known here, so only that they are not open to others is asserted).
    let (code, out) = ssh_output(
        &ssh,
        &with_key,
        &destination,
        "ls -ld .ssh .ssh/authorized_keys",
    );
    assert_eq!(code, Some(0));
    for line in out.lines() {
        let mode = line.split_whitespace().next().unwrap_or_default();
        assert!(
            mode.len() >= 10 && &mode[4..] == "------",
            "not private: {line}"
        );
    }
}
