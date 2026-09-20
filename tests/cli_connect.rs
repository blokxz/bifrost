//! `bifrost <host>`: the real binary connecting without the TUI, with a fake ssh.
//!
//! No terminal is involved, so unlike the pseudo-terminal tests these run on
//! Windows as well. The fake ssh is a small program compiled on the fly (see
//! `cli_support`), so nothing here needs a network, a server or the real ssh.

mod cli_support;

use bifrost_ssh::domain::Host;
use cli_support::{World, same_path, stderr, stdout};

const FINGERPRINT: &str = "SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn app_host() -> Host {
    let mut host = Host::new("app", "192.0.2.7");
    host.user = Some("deploy".to_string());
    host.port = Some(2222);
    host
}

/// A world with the host `app` saved and a fake ssh that runs `script`.
fn world(script: &[&str]) -> World {
    let world = World::new();
    world.save(vec![app_host(), Host::new("web", "192.0.2.1")]);
    world.install("ssh", script);
    world
}

#[test]
fn connects_with_the_saved_hosts_arguments_to_the_absolute_ssh() {
    let world = world(&["exit 0"]);
    let output = world.run(&["app"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let (program, args) = world.started("ssh").expect("ssh was started");
    assert!(program.is_absolute(), "{program:?}");
    assert!(
        same_path(&program, &world.installed_path("ssh")),
        "{program:?}"
    );
    assert_eq!(args, ["-l", "deploy", "-p", "2222", "--", "192.0.2.7"]);
}

#[test]
fn the_exit_status_of_ssh_or_the_remote_command_is_passed_through_unchanged() {
    for status in [0, 1, 7, 42, 127, 130, 254] {
        let world = world(&[&format!("exit {status}")]);
        let output = world.run(&["app"]);
        assert_eq!(output.status.code(), Some(status), "status {status}");
        // A remote status is not a failure to explain.
        assert!(!stderr(&output).contains("bifrost:"), "{}", stderr(&output));
    }
}

#[test]
fn status_2_from_the_remote_command_is_passed_through_too() {
    // It cannot be told apart by the status alone, which is what the message on
    // stderr is for: Bifrost's own errors say `bifrost: error:`.
    let world = world(&["exit 2"]);
    let output = world.run(&["app"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stderr(&output), "");
}

#[test]
fn ssh_s_stdout_and_stderr_reach_ours_untouched() {
    let world = world(&[
        "stdout hello from the remote",
        "stderr Warning: something",
        "exit 0",
    ]);
    let output = world.run(&["app"]);
    assert_eq!(stdout(&output).trim_end(), "hello from the remote");
    assert_eq!(stderr(&output), "Warning: something\r\n");
}

#[test]
fn it_never_opens_the_interface() {
    let world = world(&["exit 0"]);
    let output = world.run(&["app"]);
    // Standard input is not a terminal: the interface would have refused.
    assert_eq!(output.status.code(), Some(0));
    for text in [stdout(&output), stderr(&output)] {
        assert!(
            !text.contains("\x1b[?1049h"),
            "the alternate screen was entered"
        );
        assert!(!text.contains("interactive terminal"), "{text}");
    }
}

#[test]
fn a_failure_is_explained_after_ssh_s_own_message_and_the_status_is_ssh_s() {
    let ssh_line = "ssh: connect to host 192.0.2.7 port 2222: Connection refused";
    let world = world(&[&format!("stderr {ssh_line}"), "exit 255"]);
    let output = world.run(&["app"]);
    let said = stderr(&output);

    assert_eq!(output.status.code(), Some(255));
    let ssh_at = said.find(ssh_line).expect("ssh's own message is shown");
    let bifrost_at = said
        .find("bifrost: Connection refused")
        .expect("the explanation");
    assert!(ssh_at < bifrost_at, "the explanation comes after:\n{said}");
    assert!(
        said.contains("'app' was reached, but nothing is accepting SSH"),
        "{said}"
    );
    assert!(said.contains("What you can try:"), "{said}");
    assert!(
        said.contains("- Check the port saved for this host"),
        "{said}"
    );
}

#[test]
fn each_known_failure_is_explained_in_plain_words() {
    for (line, title) in [
        (
            "deploy@192.0.2.7: Permission denied (publickey).",
            "The server refused the login",
        ),
        (
            "Host key verification failed.",
            "The server's identity was not accepted",
        ),
        (
            "ssh: connect to host 192.0.2.7 port 2222: Connection timed out",
            "The server did not answer",
        ),
        (
            "ssh: Could not resolve hostname x: Name or service not known",
            "The host name was not found",
        ),
        (
            "ssh: connect to host 192.0.2.7 port 2222: Network is unreachable",
            "The network is unreachable",
        ),
        (
            "Connection to 192.0.2.7 closed by remote host.",
            "The server closed the connection",
        ),
        (
            "client_loop: send disconnect: Broken pipe",
            "The connection was interrupted",
        ),
        ("something no one has seen", "The connection failed"),
    ] {
        let world = world(&[&format!("stderr {line}"), "exit 255"]);
        let output = world.run(&["app"]);
        let said = stderr(&output);
        assert_eq!(output.status.code(), Some(255), "{line}");
        assert!(
            said.contains(&format!("bifrost: {title}")),
            "{line}:\n{said}"
        );
        assert!(said.contains("What you can try:"), "{line}:\n{said}");
    }
}

#[test]
fn closing_with_tilde_dot_is_not_explained_as_an_error() {
    let world = world(&["stderr Connection to 192.0.2.7 closed.", "exit 255"]);
    let output = world.run(&["app"]);
    assert_eq!(output.status.code(), Some(255), "ssh's own status");
    assert!(!stderr(&output).contains("bifrost:"), "{}", stderr(&output));
}

#[test]
fn a_jump_host_is_connected_through() {
    let world = World::new();
    let mut client = Host::new("client", "192.0.2.2");
    client.proxy_jump = Some("bastion".to_string());
    world.save(vec![Host::new("bastion", "192.0.2.1"), client]);
    world.install("ssh", &["exit 0"]);
    let output = world.run(&["client"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let (_, args) = world.started("ssh").unwrap();
    assert_eq!(args, ["-J", "192.0.2.1:22", "--", "192.0.2.2"]);
}

#[test]
fn the_host_name_is_matched_ignoring_case() {
    let world = world(&["exit 0"]);
    assert_eq!(world.run(&["APP"]).status.code(), Some(0));
    assert!(world.started("ssh").is_some());
}

// ---- Bifrost's own errors: status 2 ------------------------------------------------

#[test]
fn an_unknown_host_is_status_2_with_the_closest_names_and_ssh_is_never_started() {
    let world = world(&["exit 0"]);
    let output = world.run(&["ap"]);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        said.contains("bifrost: error: No saved host is named 'ap'."),
        "{said}"
    );
    assert!(said.contains("Did you mean: app?"), "{said}");
    assert!(said.contains("bifrost list"), "{said}");
    assert_eq!(stdout(&output), "");
    assert!(
        world.started("ssh").is_none(),
        "ssh must not run for an unknown host"
    );
}

#[test]
fn a_store_that_cannot_be_read_is_status_2_and_names_the_file() {
    let world = World::new();
    world.install("ssh", &["exit 0"]);
    std::fs::create_dir_all(world.config_dir()).unwrap();
    std::fs::write(
        world.config_dir().join("hosts.toml"),
        "version = 1\n\n[[hosts]]\nname = \"bad name\"\nhostname = \"192.0.2.1\"\n",
    )
    .unwrap();
    let output = world.run(&["app"]);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(2));
    assert!(said.contains("bifrost: error:"), "{said}");
    assert!(said.contains("hosts.toml"), "{said}");
    assert!(world.started("ssh").is_none());
}

#[test]
fn a_config_directory_that_is_not_absolute_is_status_2() {
    let world = world(&["exit 0"]);
    let output = world.output(
        world
            .command()
            .env("BIFROST_CONFIG_DIR", "relative/dir")
            .arg("app"),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("bifrost: error:"),
        "{}",
        stderr(&output)
    );
    assert!(world.started("ssh").is_none());
}

#[test]
fn ssh_that_is_not_installed_is_status_2_and_says_what_to_install() {
    let world = World::new();
    world.save(vec![app_host()]);
    // No ssh installed anywhere it would be looked for.
    let output = world.run(&["app"]);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        said.contains("bifrost: error: Could not find the 'ssh' program."),
        "{said}"
    );
    assert!(said.contains("Install OpenSSH"), "{said}");
}

#[test]
fn a_host_that_is_not_valid_is_status_2_and_ssh_is_never_started() {
    // Written by hand, bypassing the checks that saving does.
    let world = World::new();
    world.install("ssh", &["exit 0"]);
    std::fs::create_dir_all(world.config_dir()).unwrap();
    std::fs::write(
        world.config_dir().join("hosts.toml"),
        "version = 1\n\n[[hosts]]\nname = \"web\"\nhostname = \"-oProxyCommand=evil\"\n",
    )
    .unwrap();
    let output = world.run(&["web"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        world.started("ssh").is_none(),
        "an option-looking hostname must never reach ssh"
    );
}

#[test]
fn a_hostile_host_argument_is_rejected_before_anything_runs() {
    let world = world(&["exit 0"]);
    let output = world.run(&["-oProxyCommand=evil"]);
    assert_eq!(output.status.code(), Some(2), "clap's usage error");
    assert!(world.started("ssh").is_none());
}

#[test]
fn the_hostile_name_it_reports_is_cleaned() {
    let world = world(&["exit 0"]);
    let output = world.run(&["evil\x1b[31mname"]);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(2));
    assert!(!said.contains('\x1b'), "{said:?}");
}

// ---- a changed host key -----------------------------------------------------------

fn changed_key_script(entry: &str, file: &std::path::Path) -> Vec<String> {
    vec![
        "stderr @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @".to_string(),
        "stderr The fingerprint for the ED25519 key sent by the remote host is".to_string(),
        format!("stderr {FINGERPRINT}."),
        format!("stderr Offending ED25519 key in {}:12", file.display()),
        format!("stderr Host key for {entry} has changed and you have requested strict checking."),
        "stderr Host key verification failed.".to_string(),
        "exit 255".to_string(),
    ]
}

#[test]
fn a_changed_key_prints_the_removal_command_but_never_runs_it() {
    let world = World::new();
    world.save(vec![app_host()]);
    let script = changed_key_script("[192.0.2.7]:2222", &world.known_hosts());
    let lines: Vec<&str> = script.iter().map(String::as_str).collect();
    world.install("ssh", &lines);
    // A stand-in for ssh-keygen: it must not be started.
    world.install("ssh-keygen", &["exit 0"]);

    let output = world.run(&["app"]);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(255));
    assert!(
        said.contains("bifrost: The server's identity changed"),
        "{said}"
    );
    assert!(
        said.contains("Do not continue unless you know why"),
        "{said}"
    );
    let command = if cfg!(windows) {
        "ssh-keygen -R \"[192.0.2.7]:2222\""
    } else {
        "ssh-keygen -R '[192.0.2.7]:2222'"
    };
    assert!(said.contains(command), "{said}");
    assert!(
        world.started("ssh-keygen").is_none(),
        "Bifrost never edits known_hosts, not even through ssh-keygen"
    );
}

#[test]
fn no_command_is_printed_for_a_host_bifrost_did_not_connect_through() {
    let world = World::new();
    world.save(vec![app_host()]);
    let script = changed_key_script("victim.example.com", &world.known_hosts());
    let lines: Vec<&str> = script.iter().map(String::as_str).collect();
    world.install("ssh", &lines);
    let output = world.run(&["app"]);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(255));
    assert!(
        said.contains("bifrost: The server's identity changed"),
        "{said}"
    );
    assert!(
        !said.contains("ssh-keygen -R"),
        "a name a server could have printed must not become a command:\n{said}"
    );
    assert!(said.contains("cannot tell which entry"), "{said}");
}

#[test]
fn no_command_is_printed_for_a_key_in_another_file() {
    let world = World::new();
    world.save(vec![app_host()]);
    let other = world.home().join("elsewhere");
    let script = changed_key_script("[192.0.2.7]:2222", &other);
    let lines: Vec<&str> = script.iter().map(String::as_str).collect();
    world.install("ssh", &lines);
    let output = world.run(&["app"]);
    assert!(
        !stderr(&output).contains("ssh-keygen -R"),
        "{}",
        stderr(&output)
    );
}

// ---- --help ------------------------------------------------------------------------

#[test]
fn help_documents_the_exit_status() {
    let world = World::new();
    for flag in ["--help", "-h"] {
        let output = world.run(&[flag]);
        let text = stdout(&output);
        assert_eq!(output.status.code(), Some(0));
        assert!(text.contains("Exit status of `bifrost <host>`"), "{text}");
        assert!(text.contains("Bifrost itself could not connect"), "{text}");
    }
}

// ---- how ssh can end (Unix) ---------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_crash_of_ssh_is_reported_as_128_plus_the_signal() {
    let world = world(&["abort"]);
    let output = world.run(&["app"]);
    assert_eq!(output.status.code(), Some(134), "SIGABRT is 6");
}

#[cfg(unix)]
#[test]
fn ctrl_c_ends_ssh_but_not_bifrost_and_the_status_is_130() {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    use rustix::process::{Pid, Signal, kill_process_group};

    let world = world(&["sleep 30000"]);
    let mut command = world.command();
    // Its own process group, so that the signal reaches bifrost and the fake and
    // nothing else, as the terminal's Ctrl-C would.
    let mut child = world.spawn(command.arg("app").process_group(0));

    let deadline = Instant::now() + Duration::from_secs(10);
    while world.started("ssh").is_none() {
        assert!(Instant::now() < deadline, "ssh never started");
        std::thread::sleep(Duration::from_millis(10));
    }
    let group = Pid::from_raw(child.id().try_into().unwrap()).unwrap();
    kill_process_group(group, Signal::INT).unwrap();

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "bifrost did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(130), "{status:?}");
}
