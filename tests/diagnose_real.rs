//! The classifier against what the real `ssh` prints.
//!
//! Everything here is `#[ignore]`: it needs a real ssh binary, and the last
//! group needs a real server. Run by hand:
//!
//! ```text
//! cargo test --test diagnose_real -- --ignored
//! BIFROST_TEST_SSH_TARGET=user@host cargo test --test diagnose_real -- --ignored
//! ```
//!
//! The first group needs no server: ssh fails before login in ways it can be
//! made to fail against localhost. The second group needs a server that accepts
//! SSH connections and is reachable non-interactively, such as the Incus
//! container used for manual integration. It changes nothing on the server and
//! nothing on this machine: every ssh runs with `-F /dev/null`, its own known
//! hosts file and no agent.
//!
//! These are the tests that show whether the wording `ssh::diagnose` matches is
//! still what ssh says. They were written to be run after an OpenSSH upgrade.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

use bifrost_ssh::ssh::command::KnownHostsTarget;
use bifrost_ssh::ssh::connect::{Exit, Outcome};
use bifrost_ssh::ssh::diagnose::{FailureKind, Verdict, classify, host_key_change};

/// Runs the real ssh with `args` on no terminal and reports it the way
/// `connect::run` would.
fn real_ssh(args: &[&str]) -> Outcome {
    let fixed = [
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
    ];
    // The test harness shows this when a test fails: the exact command, so that
    // a surprising result can be checked by running it by hand.
    let shown: Vec<&str> = fixed.iter().chain(args).copied().collect();
    eprintln!("ran: ssh {}", shown.join(" "));
    let output = Command::new("ssh")
        .args(fixed)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run the real ssh");
    Outcome {
        exit: Exit::Code(output.status.code().expect("ssh exits, it is not killed")),
        stderr: output.stderr,
        interrupted: false,
    }
}

fn explain(outcome: &Outcome) -> String {
    format!(
        "status {:?}, stderr {:?}",
        outcome.exit,
        String::from_utf8_lossy(&outcome.stderr)
    )
}

fn assert_failure(outcome: &Outcome, kind: FailureKind) {
    assert_eq!(outcome.exit, Exit::Code(255), "{}", explain(outcome));
    assert_eq!(
        classify(outcome),
        Verdict::Failed(kind),
        "{}",
        explain(outcome)
    );
}

// ---- no server needed ----------------------------------------------------------

#[test]
#[ignore = "needs the real ssh binary"]
fn a_closed_port_is_a_refusal() {
    assert_failure(
        &real_ssh(&["-p", "1", "127.0.0.1", "true"]),
        FailureKind::ConnectionRefused,
    );
}

#[test]
#[ignore = "needs the real ssh binary"]
fn a_name_that_does_not_exist_is_not_found() {
    assert_failure(
        &real_ssh(&["nonexistent.invalid", "true"]),
        FailureKind::CouldNotResolve,
    );
}

#[test]
#[ignore = "needs the real ssh binary"]
fn a_jump_host_that_refuses_is_a_refusal_and_not_a_closed_connection() {
    assert_failure(
        &real_ssh(&["-J", "127.0.0.1:1", "127.0.0.1", "true"]),
        FailureKind::ConnectionRefused,
    );
}

#[test]
#[ignore = "needs the real ssh binary"]
fn a_jump_host_that_cannot_be_resolved_is_not_found() {
    assert_failure(
        &real_ssh(&["-J", "nonexistent.invalid", "127.0.0.1", "true"]),
        FailureKind::CouldNotResolve,
    );
}

/// A listener on localhost that does `serve` with the first connection.
fn listener(
    serve: impl FnOnce(std::net::TcpStream) + Send + 'static,
) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            serve(stream);
        }
    });
    (port, handle)
}

#[test]
#[ignore = "needs the real ssh binary"]
fn a_server_that_hangs_up_during_the_handshake_is_a_lost_connection() {
    let (port, server) = listener(drop);
    let outcome = real_ssh(&["-p", &port.to_string(), "127.0.0.1", "true"]);
    server.join().unwrap();
    assert_failure(&outcome, FailureKind::ConnectionLost);
}

#[test]
#[ignore = "needs the real ssh binary"]
fn a_server_that_says_hello_and_hangs_up_is_a_lost_connection() {
    let (port, server) = listener(|mut stream| {
        let _ = stream.write_all(b"SSH-2.0-Fake\r\n");
        let mut ignored = [0; 64];
        let _ = stream.read(&mut ignored);
    });
    let outcome = real_ssh(&["-p", &port.to_string(), "127.0.0.1", "true"]);
    server.join().unwrap();
    assert_failure(&outcome, FailureKind::ConnectionLost);
}

#[test]
#[ignore = "needs the real ssh binary"]
fn a_server_that_is_not_ssh_is_a_lost_connection() {
    let (port, server) = listener(|mut stream| {
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
    });
    let outcome = real_ssh(&["-p", &port.to_string(), "127.0.0.1", "true"]);
    server.join().unwrap();
    assert_failure(&outcome, FailureKind::ConnectionLost);
}

// ---- a real server ---------------------------------------------------------------

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

/// ssh options that isolate a test: no config, no agent, no default keys, and a
/// known-hosts file of its own.
fn isolated<'a>(known_hosts: &'a Path, port: &'a str, more: &[&'a str]) -> Vec<String> {
    let mut args: Vec<String> = [
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-p",
        port,
        "-o",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.push(format!("UserKnownHostsFile={}", known_hosts.display()));
    args.extend(more.iter().map(|s| s.to_string()));
    args
}

fn run_against(destination: &str, args: &[String]) -> Outcome {
    let mut all: Vec<&str> = args.iter().map(String::as_str).collect();
    all.extend(["--", destination, "true"]);
    real_ssh(&all)
}

#[test]
#[ignore = "needs BIFROST_TEST_SSH_TARGET, a real server"]
fn a_key_the_server_does_not_know_is_permission_denied() {
    let Some((destination, port)) = target() else {
        eprintln!("BIFROST_TEST_SSH_TARGET is not set; nothing tested");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key");
    let generated = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .expect("run ssh-keygen");
    assert!(generated.success());
    let key = key.display().to_string();
    let args = isolated(
        &dir.path().join("known_hosts"),
        &port,
        &["-o", "StrictHostKeyChecking=accept-new", "-i", &key],
    );
    assert_failure(
        &run_against(&destination, &args),
        FailureKind::PermissionDenied,
    );
}

#[test]
#[ignore = "needs BIFROST_TEST_SSH_TARGET, a real server"]
fn an_unknown_server_under_strict_checking_is_a_rejection() {
    let Some((destination, port)) = target() else {
        eprintln!("BIFROST_TEST_SSH_TARGET is not set; nothing tested");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let args = isolated(
        &dir.path().join("known_hosts"),
        &port,
        &["-o", "StrictHostKeyChecking=yes"],
    );
    assert_failure(
        &run_against(&destination, &args),
        FailureKind::HostKeyRejected,
    );
}

#[test]
#[ignore = "needs BIFROST_TEST_SSH_TARGET, a real server"]
fn a_changed_host_key_is_recognized() {
    let Some((destination, port)) = target() else {
        eprintln!("BIFROST_TEST_SSH_TARGET is not set; nothing tested");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let known_hosts = dir.path().join("known_hosts");

    // Learn the server's real ed25519 key, then swap it for a different one for
    // the same host: the situation of a reinstalled server.
    let scan = Command::new("ssh-keyscan")
        .args(["-t", "ed25519", "-p", &port])
        .arg(
            destination
                .rsplit_once('@')
                .map_or(destination.as_str(), |(_, h)| h),
        )
        .output()
        .expect("run ssh-keyscan");
    let scanned = String::from_utf8(scan.stdout).unwrap();
    let host_field = scanned
        .split_whitespace()
        .next()
        .expect("the server offered an ed25519 host key")
        .to_string();
    let other = dir.path().join("other");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&other)
            .status()
            .unwrap()
            .success()
    );
    let other_public = std::fs::read_to_string(other.with_extension("pub")).unwrap();
    let mut fields = other_public.split_whitespace();
    let (kind, key) = (fields.next().unwrap(), fields.next().unwrap());
    std::fs::write(&known_hosts, format!("{host_field} {kind} {key}\n")).unwrap();

    let args = isolated(
        &known_hosts,
        &port,
        &[
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
        ],
    );
    let outcome = run_against(&destination, &args);
    assert_failure(&outcome, FailureKind::HostKeyChanged);

    // What the blocking screen shows and what removal is built from: read out
    // of the same real output, and tied to the host that was connected to.
    let read = host_key_change(&outcome.stderr);
    let text = explain(&outcome);
    assert_eq!(read.key_type.as_deref(), Some("ED25519"), "{text}");
    assert!(read.fingerprint.is_some(), "no fingerprint read: {text}");
    assert_eq!(
        read.line,
        Some(1),
        "the old key is on the first line: {text}"
    );
    let host = destination
        .rsplit_once('@')
        .map_or(destination.as_str(), |(_, h)| h);
    let entry = if port == "22" {
        host.to_lowercase()
    } else {
        format!("[{}]:{port}", host.to_lowercase())
    };
    let known = [KnownHostsTarget {
        entry,
        saved_name: "server".to_string(),
    }];
    let target = read.removal_target(&known, Some(&known_hosts));
    assert_eq!(
        target.map(|t| t.saved_name.as_str()),
        Some("server"),
        "the host and the file ssh named must match what was connected to: {read:?} in {text}"
    );
}

// ---- the target's format (no server needed) -----------------------------------------

#[cfg(test)]
mod target_format {
    use super::parse_target;

    fn parsed(text: &str) -> (String, String) {
        parse_target(text).unwrap_or_else(|problem| panic!("{problem}"))
    }

    fn pair(destination: &str, port: &str) -> (String, String) {
        (destination.to_string(), port.to_string())
    }

    #[test]
    fn user_host_and_port_are_split() {
        assert_eq!(
            parsed("sshunter@192.168.1.39:2222"),
            pair("sshunter@192.168.1.39", "2222")
        );
        assert_eq!(
            parsed("sshunter@192.168.1.39"),
            pair("sshunter@192.168.1.39", "22")
        );
        assert_eq!(
            parsed("dev@web.example.com:22"),
            pair("dev@web.example.com", "22")
        );
        assert_eq!(
            parsed("web.example.com:2200"),
            pair("web.example.com", "2200")
        );
    }

    #[test]
    fn ipv6_is_bracketed_only_to_carry_a_port() {
        assert_eq!(
            parsed("dev@[2001:db8::1]:2222"),
            pair("dev@2001:db8::1", "2222")
        );
        assert_eq!(parsed("dev@[2001:db8::1]"), pair("dev@2001:db8::1", "22"));
        assert_eq!(parsed("dev@2001:db8::1"), pair("dev@2001:db8::1", "22"));
    }

    #[test]
    fn surrounding_whitespace_and_a_newline_are_ignored() {
        // The usual way a shell variable or a pasted line goes wrong.
        assert_eq!(
            parsed("  sshunter@192.168.1.39:2222\n"),
            pair("sshunter@192.168.1.39", "2222")
        );
    }

    #[test]
    fn a_value_that_is_not_a_target_is_refused_and_shown_exactly() {
        for bad in [
            "sshunter@192.168.1.39[2222]",
            "sshunter@192.168.1.39:22 22",
            "sshunter@192.168.1.39:port",
            "sshunter@192.168.1.39:0",
            "sshunter@192.168.1.39:70000",
            "sshunter@[2001:db8::1",
            "sshunter@[2001:db8::1]2222",
            "@192.168.1.39",
            "sshunter@",
            "",
            "bad user@host",
            "user@ho st",
            "user@host;rm",
        ] {
            let problem = parse_target(bad).expect_err(bad);
            assert!(
                problem.contains(&format!("{:?}", bad.trim()))
                    || problem.contains("BIFROST_TEST_SSH_TARGET"),
                "{problem}"
            );
        }
        let problem = parse_target("sshunter@192.168.1.39[2222]").unwrap_err();
        assert!(
            problem.contains("\"sshunter@192.168.1.39[2222]\""),
            "{problem}"
        );
    }
}
