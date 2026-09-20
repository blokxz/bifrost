//! Handing the terminal to ssh and getting it back, with the real `bifrost`
//! binary in a real (pseudo) terminal and a fake `ssh` script found through
//! `PATH`, so no network and no real ssh are involved.
//!
//! Every test ends by quitting bifrost and letting `Session::finish` compare the
//! terminal's real modes with what they were at the start: whatever happened in
//! between, the shell must get its terminal back exactly.
//!
//! Unix only, like `pty.rs`: the Windows console cannot be driven this way.

#![cfg(unix)]

mod support;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use bifrost_ssh::domain::{Host, Hosts};
use bifrost_ssh::store::Store;
use support::{CTRL_C, FakeSsh, Screen, Session, assert_restored, contains_bytes, healthy_store};

const ENTER: &[u8] = b"\r";
const ESC_KEY: &[u8] = b"\x1b";
const HOME_SCREEN: &str = "Saved hosts: 2";

/// bifrost in a pty with `fake` as the only ssh. The list has two hosts and
/// `db` (192.0.2.2) is selected, so Enter connects to it.
fn start(fake: &FakeSsh) -> (tempfile::TempDir, Session) {
    let (dir, config) = healthy_store();
    let session = Session::start(&config, 24, 80, &[("PATH", &fake.path_env())]);
    (dir, session)
}

/// Waits for the list, presses Enter and returns once the fake reports it is
/// running (it prints `FAKE-READY`).
fn connect(session: &mut Session) {
    session.wait_until("the list", |s| s.alt_screen && s.contains(HOME_SCREEN));
    session.send(ENTER);
    session.wait_until("ssh running", |s| s.normal_contains("FAKE-READY"));
}

/// Waits until the list is back after a connection, with `message` on it.
fn wait_for_list_with(session: &mut Session, message: &str) {
    session.wait_until("the list again with the result", |s| {
        s.alt_screen && !s.cursor_visible && s.contains(HOME_SCREEN) && s.contains(message)
    });
}

/// Quits and checks the terminal (see the module docs).
fn quit(mut session: Session) -> Vec<u8> {
    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
    output
}

/// The settings `stty -a` reported, as words: `icanon` on, `-icanon` off.
fn words_after<'a>(screen: &'a Screen, marker: &str) -> Vec<&'a str> {
    let line = screen
        .normal_text
        .lines()
        .find(|line| line.contains(marker))
        .unwrap_or_else(|| panic!("no {marker} line in {:?}", screen.normal_text));
    line.split_whitespace().collect()
}

#[test]
fn a_clean_session_gives_ssh_a_normal_terminal_and_bifrost_gets_it_back() {
    let fake = FakeSsh::new(
        r#"echo "MODES: $(stty -a | tr ';\n' '  ')"
echo FAKE-READY
exit 0"#,
    );
    let (_dir, mut session) = start(&fake);

    connect(&mut session);
    wait_for_list_with(&mut session, "Disconnected from 'db'.");

    let screen = session.screen();
    // ssh ran on the normal screen, with a visible cursor, after a one-line
    // banner, and bifrost drew nothing there.
    let banner = screen
        .normal_text
        .find("Bifrost: connecting to db...")
        .unwrap();
    let ready = screen.normal_text.find("FAKE-READY").unwrap();
    assert!(banner < ready, "{:?}", screen.normal_text);
    assert!(!screen.hidden_cursor_on_normal_screen);
    assert!(
        !screen.normal_contains("Saved hosts"),
        "bifrost drew while ssh was running"
    );
    // ssh saw the terminal as a shell would: line editing, echo and Ctrl-C
    // signals all on.
    let modes = words_after(&screen, "MODES:");
    for on in ["icanon", "echo", "isig"] {
        assert!(modes.contains(&on), "{on} should be on: {modes:?}");
    }

    let output = quit(session);
    // Left the alternate screen for ssh, came back, and left it again at quit.
    let enters = output.windows(8).filter(|w| *w == b"\x1b[?1049h").count();
    let leaves = output.windows(8).filter(|w| *w == b"\x1b[?1049l").count();
    assert_eq!((enters, leaves), (2, 2));
}

#[test]
fn ssh_is_started_by_absolute_path_with_the_saved_hosts_arguments() {
    let fake = FakeSsh::new("echo FAKE-READY");
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut app = Host::new("app", "192.0.2.7");
    app.user = Some("deploy".to_string());
    app.port = Some(2222);
    Store::at(&config)
        .save(&Hosts::from_vec(vec![app]).unwrap())
        .unwrap();
    let mut session = Session::start(&config, 24, 80, &[("PATH", &fake.path_env())]);

    session.wait_until("the list", |s| s.contains("Saved hosts: 1"));
    session.send(ENTER);
    session.wait_until("the result", |s| s.contains("Disconnected from 'app'."));

    let (program, args) = fake.invocation();
    assert_eq!(PathBuf::from(&program), fake.program());
    assert!(PathBuf::from(&program).is_absolute());
    assert_eq!(args, ["-l", "deploy", "-p", "2222", "--", "192.0.2.7"]);
    quit(session);
}

#[test]
fn a_failing_remote_command_is_not_reported_as_a_connection_error() {
    let fake = FakeSsh::new("echo FAKE-READY\nexit 1");
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    wait_for_list_with(&mut session, "The session on 'db' ended with status 1.");
    assert!(!session.screen().contains("Warning:"));
    quit(session);
}

#[test]
fn ssh_stderr_reaches_the_terminal_untouched_and_status_255_is_a_failure() {
    // The line has color codes, as some wrappers and servers add. The user's
    // terminal gets it byte for byte; Bifrost, which does not trust a line with
    // escape sequences to be ssh's own, shows the generic failure.
    let fake = FakeSsh::new(
        r#"echo FAKE-READY
printf '\033[31mssh: connect to host 192.0.2.2 port 22: Connection refused\033[0m\n' >&2
exit 255"#,
    );
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    session.wait_until("the error screen", |s| {
        s.alt_screen && s.contains("The connection failed") && s.contains("ssh said:")
    });

    let screen = session.screen();
    assert!(
        screen.normal_contains("Connection refused"),
        "teed live: {:?}",
        screen.normal_text
    );
    session.send(ENTER);
    session.wait_until("the list", |s| s.contains(HOME_SCREEN));
    let output = quit(session);
    assert!(
        contains_bytes(&output, b"\x1b[31mssh: connect to host"),
        "the copy for the user is byte for byte what ssh wrote"
    );
}

#[test]
fn ctrl_c_at_a_prompt_ends_ssh_but_not_bifrost() {
    // A terminal in its normal mode: Ctrl-C is a signal to the whole group.
    //
    // The fake waits for a line from the terminal, as ssh does at a password
    // prompt, and does nothing else after it says it is ready. It must not start
    // another program instead (`sleep`): while a shell forks one it has signals
    // blocked, and a Ctrl-C that lands then is absorbed by the half-made child
    // and never reaches the program that runs. The test sends Ctrl-C as soon as
    // it sees the ready line, so on a busy machine, where a fork takes long, it
    // hit that window about one time in thirty and the connection never ended.
    let fake = FakeSsh::new("echo FAKE-READY\nread line");
    let (_dir, mut session) = start(&fake);
    connect(&mut session);

    session.press_ctrl_c_in_a_normal_terminal();
    wait_for_list_with(&mut session, "The connection to 'db' was cancelled.");
    assert!(
        session.is_running(),
        "Ctrl-C at ssh's prompt must not quit bifrost"
    );

    // Still alive and responsive.
    session.send(b"?");
    session.wait_until("help", |s| s.contains("These keys work in Bifrost:"));
    session.send(b"?");
    quit(session);
}

#[test]
fn ctrl_c_in_a_running_session_belongs_to_ssh() {
    // ssh in a session puts the terminal in raw mode: Ctrl-C is a byte.
    let fake = FakeSsh::new(
        r#"saved=$(stty -g)
stty raw -echo
echo FAKE-READY
byte=$(dd bs=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
stty "$saved"
echo "GOT:$byte"
exit 0"#,
    );
    let (_dir, mut session) = start(&fake);
    connect(&mut session);

    session.send(CTRL_C);
    wait_for_list_with(&mut session, "Disconnected from 'db'.");
    assert!(session.screen().normal_contains("GOT:03"));
    quit(session);
}

#[test]
fn what_is_typed_during_a_session_goes_to_ssh_and_bifrost_reads_none_of_it() {
    let fake = FakeSsh::new(
        r#"echo FAKE-READY
read line
echo "GOT-LINE:$line"
exit 0"#,
    );
    let (_dir, mut session) = start(&fake);
    connect(&mut session);

    // Every letter of this is a Bifrost command: e edits, l and h move.
    session.send(b"hello\r");
    wait_for_list_with(&mut session, "Disconnected from 'db'.");
    assert!(session.screen().normal_contains("GOT-LINE:hello"));
    assert!(!session.screen().contains("Edit host"));
    quit(session);
}

#[test]
fn input_ssh_never_read_is_thrown_away_instead_of_run_as_commands() {
    let fake = FakeSsh::new(
        r#"echo FAKE-READY
while [ ! -e "$GO" ]; do sleep 0.05; done
exit 0"#,
    );
    let (_dir, mut session) = start(&fake);
    connect(&mut session);

    // A `q` left in the terminal's input when ssh exits would quit bifrost the
    // moment it took the terminal back.
    session.send(b"q");
    fake.release();
    wait_for_list_with(&mut session, "Disconnected from 'db'.");

    // Alive, and responding to keys: had the q been kept, this would have
    // failed.
    assert!(session.is_running());
    session.send(b"?");
    session.wait_until("help", |s| s.contains("These keys work in Bifrost:"));
    session.send(b"?");
    quit(session);
}

#[test]
fn a_resize_during_a_session_is_seen_by_ssh_and_bifrost_repaints_at_the_new_size() {
    let fake = FakeSsh::new(
        // The background process is started, and `pid` set, before the ready
        // line: after it the fake only waits, so a resize can arrive at any
        // point without meeting a fork or an unset `pid`.
        r#"trap 'echo "RESIZED:$(stty size)"; kill $pid 2>/dev/null; exit 0' WINCH
sleep 20 &
pid=$!
echo "FAKE-READY:$(stty size)"
wait $pid"#,
    );
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    assert!(session.screen().normal_contains("FAKE-READY:24 80"));

    session.resize(10, 40);
    // Bifrost is not resizing anything itself while ssh runs; ssh is told.
    session.wait_until("ssh told of the new size", |s| {
        s.normal_contains("RESIZED:10 40")
    });
    // And the interface that comes back fits the terminal as it is now.
    session.wait_until("the too-small notice at the new size", |s| {
        s.alt_screen && s.contains("Terminal too small (40x10).")
    });

    session.resize(24, 80);
    session.wait_until("the list again at the original size", |s| {
        s.contains(HOME_SCREEN) && !s.contains("Terminal too small")
    });
    quit(session);
}

#[test]
fn an_ssh_killed_in_raw_mode_cannot_leave_the_terminal_raw() {
    // SIGKILL: ssh gets no chance to restore what it changed.
    let fake = FakeSsh::new("stty raw -echo\necho FAKE-READY\nkill -9 $$");
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    wait_for_list_with(&mut session, "was stopped by signal 9.");
    // `Session::finish` compares the terminal's real modes with the start: had
    // bifrost taken the raw state as "original", it would restore raw at exit.
    quit(session);
}

#[test]
fn a_process_that_keeps_ssh_s_stderr_open_cannot_hold_bifrost_up() {
    // Like a ControlPersist master: it outlives ssh with the stderr pipe open.
    let fake = FakeSsh::new("sleep 5 >/dev/null </dev/null &\necho FAKE-READY\nexit 0");
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    let started = Instant::now();

    wait_for_list_with(&mut session, "Disconnected from 'db'.");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "waited {:?} for a pipe that another process holds",
        started.elapsed()
    );
    quit(session);
}

#[test]
fn without_ssh_connecting_explains_and_touches_nothing() {
    let fake = FakeSsh::absent();
    let (_dir, config) = healthy_store();
    let mut session = Session::start(&config, 24, 80, &[("PATH", &fake.path_env_without_tools())]);
    session.wait_until("the list", |s| s.alt_screen && s.contains(HOME_SCREEN));
    session.send(ENTER);
    session.wait_until("the explanation", |s| {
        s.contains("Could not find the 'ssh' program.")
    });

    let screen = session.screen();
    assert!(screen.alt_screen, "the interface was not given away");
    assert!(screen.normal_text.is_empty(), "{:?}", screen.normal_text);
    assert!(!fake.was_started());
    quit(session);
}

#[test]
fn a_sigint_outside_a_connection_quits_cleanly() {
    let fake = FakeSsh::new("echo FAKE-READY");
    let (_dir, mut session) = start(&fake);
    session.wait_until("the list", |s| s.alt_screen && s.contains(HOME_SCREEN));

    session.sigint_bifrost_only();

    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

// ---- explaining failures ----------------------------------------------------

/// A fake ssh that prints `lines` to stderr, the way ssh does (`\r\n` line
/// ends), and exits with `status`.
fn failing_ssh(lines: &[&str], status: i32) -> FakeSsh {
    let mut body = String::from("echo FAKE-READY\n");
    for line in lines {
        assert!(!line.contains('\''), "the script quotes lines with '");
        body.push_str(&format!("printf '%s\\r\\n' '{line}' >&2\n"));
    }
    body.push_str(&format!("exit {status}"));
    FakeSsh::new(&body)
}

/// Runs a connection that fails with `lines` and checks the error screen has
/// `title` and `step`, then that Enter returns to the list.
fn assert_failure_screen(lines: &[&str], title: &str, step: &str) {
    let fake = failing_ssh(lines, 255);
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    // Everything that is asserted is waited for: a frame arrives in pieces.
    session.wait_until("the error screen", |s| {
        s.alt_screen
            && s.contains(title)
            && s.contains(step)
            && s.contains("Error:")
            && s.contains("What you can try:")
            && s.contains("o ssh output")
    });
    assert!(
        !session.screen().contains(HOME_SCREEN),
        "the list is not behind it"
    );

    session.send(ENTER);
    session.wait_until("the list again", |s| s.contains(HOME_SCREEN));
    quit(session);
}

macro_rules! failure_screen {
    ($name:ident, [$($line:expr),+], $title:expr, $step:expr) => {
        #[test]
        fn $name() {
            assert_failure_screen(&[$($line),+], $title, $step);
        }
    };
}

failure_screen!(
    permission_denied_is_explained,
    ["deploy@192.0.2.2: Permission denied (publickey)."],
    "The server refused the login",
    "Check the user name saved for this host"
);
failure_screen!(
    a_rejected_host_key_is_explained,
    ["Host key verification failed."],
    "The server's identity was not accepted",
    "answer yes only if you recognize the fingerprint"
);
failure_screen!(
    connection_refused_is_explained,
    ["ssh: connect to host 192.0.2.2 port 22: Connection refused"],
    "Connection refused",
    "Check the port saved for this host"
);
failure_screen!(
    a_timeout_is_explained,
    ["ssh: connect to host 192.0.2.2 port 22: Connection timed out"],
    "The server did not answer",
    "Check that the machine is on"
);
failure_screen!(
    an_unresolvable_name_is_explained,
    ["ssh: Could not resolve hostname nope.invalid: Name or service not known"],
    "The host name was not found",
    "Check the spelling of the host name"
);
failure_screen!(
    an_unreachable_network_is_explained,
    ["ssh: connect to host 192.0.2.2 port 22: Network is unreachable"],
    "The network is unreachable",
    "Check your network connection"
);
failure_screen!(
    a_server_closing_the_session_is_explained,
    ["Connection to 192.0.2.2 closed by remote host."],
    "The server closed the connection",
    "Connect again if you were not finished"
);
failure_screen!(
    a_broken_connection_is_explained,
    ["client_loop: send disconnect: Broken pipe"],
    "The connection was interrupted",
    "Check your network connection"
);
failure_screen!(
    an_unknown_failure_gets_a_generic_message_and_ssh_s_own_words,
    ["something no one has seen before"],
    "The connection failed",
    "something no one has seen before"
);

#[test]
fn a_jump_host_that_refuses_is_a_refusal_not_a_closed_connection() {
    // What ssh prints when the jump host refuses (captured from OpenSSH 9.6):
    // the reason, then a line about the connection through it closing.
    let fake = failing_ssh(
        &[
            "ssh: connect to host 192.0.2.1 port 22: Connection refused",
            "Connection closed by UNKNOWN port 65535",
        ],
        255,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut client = Host::new("client", "192.0.2.2");
    client.proxy_jump = Some("bastion".to_string());
    Store::at(&config)
        .save(&Hosts::from_vec(vec![Host::new("bastion", "192.0.2.1"), client]).unwrap())
        .unwrap();
    let mut session = Session::start(&config, 24, 80, &[("PATH", &fake.path_env())]);
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));
    session.send(b"j"); // bastion is first; the client is second
    session.send(ENTER);

    session.wait_until("the refusal", |s| {
        s.alt_screen && s.contains("Connection refused") && s.contains("What you can try:")
    });
    let (_, args) = fake.invocation();
    assert!(args.contains(&"-J".to_string()), "{args:?}");
    session.send(ENTER);
    quit(session);
}

#[test]
fn a_remote_exit_status_is_never_explained_as_a_connection_failure() {
    // The last thing ssh printed looks like an error, but the status is the
    // remote command's: 1, not ssh's own 255.
    let fake = failing_ssh(
        &["ssh: connect to host 192.0.2.2 port 22: Connection refused"],
        1,
    );
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    wait_for_list_with(&mut session, "The session on 'db' ended with status 1.");
    assert!(!session.screen().contains("What you can try:"));
    quit(session);
}

#[test]
fn the_output_page_shows_what_ssh_printed_and_hostile_bytes_never_reach_the_terminal() {
    // A server's banner reaches stderr: escape sequences (a clear screen, a
    // window title) and a right-to-left override.
    let fake = FakeSsh::new(
        r#"echo FAKE-READY
printf 'harmless first line\r\n' >&2
printf '\033[2J\033]0;pwned\007evil\342\200\256gpj.exe\r\n' >&2
printf 'last line\033[31m red\r\n' >&2
exit 255"#,
    );
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    // The last line has an escape sequence in it, so it is not believed to be
    // ssh's own message: the failure is "not recognized", and the lines are
    // quoted cleaned.
    session.wait_until("the error screen with ssh's words", |s| {
        s.alt_screen && s.contains("ssh said:") && s.contains("last line?[31m red")
    });

    session.send(b"o");
    session.wait_until("the output page", |s| {
        s.alt_screen && s.contains("What ssh printed") && s.contains("harmless first line")
    });
    let page = session.screen();
    assert!(
        page.contains("?[2J?]0;pwned?evil?gpj.exe"),
        "{}",
        page.text()
    );
    assert!(
        page.contains("non-printable characters were hidden"),
        "{}",
        page.text()
    );

    // Back where it came from: the error, then the list.
    session.send(b"o");
    session.wait_until("the error again", |s| s.contains("What you can try:"));
    session.send(ESC_KEY);
    session.wait_until("the list", |s| s.contains(HOME_SCREEN));

    let output = quit(session);
    // The user's own copy of ssh's stderr on the normal screen is verbatim
    // (that is ssh talking to the user's terminal, as it always would), but
    // everything Bifrost drew after taking the terminal back is clean.
    let split = output
        .windows(8)
        .rposition(|w| w == b"\x1b[?1049h")
        .expect("the interface came back");
    let after_handover = &output[split..];
    assert!(
        !contains_bytes(after_handover, b"\x1b]0;"),
        "a title-setting sequence from ssh's output was drawn"
    );
    assert!(!contains_bytes(after_handover, "\u{202e}".as_bytes()));
    assert!(!contains_bytes(after_handover, b"pwned\x07"));
    assert!(
        contains_bytes(&output, b"\x1b]0;pwned\x07"),
        "the copy for the user is byte for byte what ssh wrote"
    );
}

#[test]
fn o_on_the_list_reads_the_output_of_a_connection_that_did_not_fail() {
    let fake =
        FakeSsh::new("echo FAKE-READY\nprintf 'Warning: Permanently added x.\\r\\n' >&2\nexit 0");
    let (_dir, mut session) = start(&fake);
    connect(&mut session);
    wait_for_list_with(&mut session, "Disconnected from 'db'.");

    session.send(b"o");
    session.wait_until("the output", |s| {
        s.contains("Warning: Permanently added x.") && s.contains("What ssh printed")
    });
    session.send(ESC_KEY);
    session.wait_until("the list", |s| s.contains(HOME_SCREEN));
    quit(session);
}

// ---- a changed host key -----------------------------------------------------

const FINGERPRINT: &str = "SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA";
const KNOWN_HOSTS_CONTENT: &str = "sentinel: bifrost must never edit this file itself\n";

/// A home directory with a `known_hosts` that only a test can tell was edited.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".ssh")).unwrap();
        std::fs::write(dir.path().join(".ssh/known_hosts"), KNOWN_HOSTS_CONTENT).unwrap();
        Home { dir }
    }

    fn path(&self) -> &str {
        self.dir.path().to_str().unwrap()
    }

    fn known_hosts_is_untouched(&self) -> bool {
        std::fs::read_to_string(self.dir.path().join(".ssh/known_hosts")).unwrap()
            == KNOWN_HOSTS_CONTENT
    }
}

/// A fake ssh that reports a changed key of `entry`, whose old key is in `file`
/// (a shell expression, so `$HOME` works), followed by a fake `ssh-keygen`
/// that does `keygen`.
fn changed_key_ssh(entry: &str, file: &str, keygen: &str) -> FakeSsh {
    let fake = FakeSsh::new(&format!(
        r#"echo FAKE-READY
printf '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n' >&2
printf 'The fingerprint for the ED25519 key sent by the remote host is\r\n' >&2
printf '{FINGERPRINT}.\r\n' >&2
printf 'Offending ED25519 key in %s:12\r\n' "{file}" >&2
printf 'Host key for {entry} has changed and you have requested strict checking.\r\n' >&2
printf 'Host key verification failed.\r\n' >&2
exit 255"#
    ));
    fake.add_program("ssh-keygen", keygen);
    fake
}

const KEYGEN_REMOVES: &str = r#"printf '# Host 192.0.2.2 found: line 1\n%s/.ssh/known_hosts updated.\nOriginal contents retained as known_hosts.old\n' "$HOME"
exit 0"#;

fn start_at(fake: &FakeSsh, home: &Home) -> (tempfile::TempDir, Session) {
    let (dir, config) = healthy_store();
    let session = Session::start(
        &config,
        24,
        100,
        &[("PATH", &fake.path_env()), ("HOME", home.path())],
    );
    (dir, session)
}

/// Runs to the blocking screen: `db` (192.0.2.2) failed with a changed key.
fn to_the_blocking_screen(session: &mut Session) {
    connect(session);
    session.wait_until("the blocking screen", |s| {
        s.alt_screen
            && s.contains("Stop: the server's identity changed")
            && s.contains("Enter/Esc abort (safe)")
    });
}

#[test]
fn a_changed_key_blocks_shows_what_ssh_reported_and_enter_aborts() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    // The frame arrives in pieces: wait for everything that is asserted.
    session.wait_until("the whole screen", |s| {
        s.contains(FINGERPRINT)
            && s.contains("(ED25519)")
            && s.contains("intercepting the connection")
            && s.contains("r remove old key...")
    });

    // Abort is the default: Enter, and nothing else has happened.
    session.send(ENTER);
    session.wait_until("the list", |s| {
        s.contains(HOME_SCREEN) && !s.contains("Stop:")
    });
    assert!(
        fake.program_arguments("ssh-keygen").is_none(),
        "ssh-keygen ran"
    );
    assert!(home.known_hosts_is_untouched());
    quit(session);
}

#[test]
fn esc_aborts_too() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    session.send(ESC_KEY);
    session.wait_until("the list", |s| {
        s.contains(HOME_SCREEN) && !s.contains("Stop:")
    });
    assert!(fake.program_arguments("ssh-keygen").is_none());
    quit(session);
}

#[test]
fn no_other_key_does_anything_while_the_screen_blocks() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);

    // Each of these quits, opens help, edits, adds or trusts, elsewhere.
    session.send(b"q?eafcwt/x y");
    // Still here, and still answering to its own keys: `d` reads ssh's output.
    session.send(b"d");
    session.wait_until("ssh's output", |s| {
        s.contains("What ssh printed") && s.contains("REMOTE HOST IDENTIFICATION HAS CHANGED!")
    });
    assert!(session.is_running());
    session.send(ESC_KEY);
    session.wait_until("the blocking screen again", |s| {
        s.contains("Stop: the server's identity changed") && s.contains("Enter/Esc abort")
    });
    assert!(fake.program_arguments("ssh-keygen").is_none());
    assert!(!session.screen().contains("Remove the old key"));
    session.send(ENTER);
    session.wait_until("the list", |s| s.contains(HOME_SCREEN));
    quit(session);
}

#[test]
fn removing_the_old_key_takes_the_host_name_and_runs_ssh_keygen_dash_r() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);

    session.send(b"r");
    session.wait_until("the confirmation", |s| {
        s.contains("Remove the old key of 'db'?")
            && s.contains("Type the host name to confirm:")
            && s.cursor_visible
    });

    // A wrong name is refused in words, and nothing runs.
    session.send(b"web\r");
    session.wait_until("the refusal", |s| {
        s.contains("That is not the host's name.")
    });
    assert!(fake.program_arguments("ssh-keygen").is_none());

    // The exact name (after erasing the wrong one) removes.
    session.send(b"\x7f\x7f\x7f");
    session.send(b"db\r");
    session.wait_until("the result on the list", |s| {
        s.alt_screen && s.contains(HOME_SCREEN) && s.contains("Removed the old key of 'db'")
    });
    let screen = session.screen();
    assert!(screen.contains("known_hosts.old"), "{}", screen.text());
    assert!(screen.contains("Connect again"), "{}", screen.text());

    // ssh-keygen was started exactly as `ssh-keygen -R <host>`, on the default
    // file (no -f), and Bifrost did not touch the file itself.
    assert_eq!(
        fake.program_arguments("ssh-keygen").unwrap(),
        ["-R", "192.0.2.2"]
    );
    assert!(home.known_hosts_is_untouched());
    quit(session);
}

#[test]
fn esc_at_the_prompt_cancels_and_runs_nothing() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    session.send(b"r");
    session.wait_until("the confirmation", |s| s.contains("Type the host name"));
    session.send(b"db");
    session.send(ESC_KEY);
    session.wait_until("the screen without the box", |s| {
        s.contains("Stop: the server's identity changed") && !s.contains("Type the host name")
    });
    assert!(fake.program_arguments("ssh-keygen").is_none());
    session.send(ENTER);
    session.wait_until("the list", |s| s.contains(HOME_SCREEN));
    quit(session);
}

#[test]
fn ctrl_c_at_the_prompt_quits_and_runs_nothing() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    session.send(b"r");
    session.wait_until("the confirmation", |s| s.contains("Type the host name"));
    session.send(b"db");
    session.send(CTRL_C);
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
    assert!(fake.program_arguments("ssh-keygen").is_none());
}

#[test]
fn a_removal_that_removes_nothing_is_not_reported_as_one() {
    let home = Home::new();
    // Exit status 0, as the real tool does, and no entry.
    let fake = changed_key_ssh(
        "192.0.2.2",
        "$HOME/.ssh/known_hosts",
        "printf 'Host 192.0.2.2 not found in known_hosts\\n'\nexit 0",
    );
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    session.send(b"r");
    session.wait_until("the confirmation", |s| s.contains("Type the host name"));
    session.send(b"db\r");
    session.wait_until("the warning", |s| {
        s.contains("found no entry for 'db'") && s.contains("nothing was removed")
    });
    let screen = session.screen();
    assert!(
        screen.contains("Stop: the server's identity changed"),
        "still blocked"
    );
    assert!(!screen.contains("Removed the old key"));
    session.send(ENTER);
    quit(session);
}

#[test]
fn a_failing_ssh_keygen_says_so_and_the_screen_stays() {
    let home = Home::new();
    let fake = changed_key_ssh(
        "192.0.2.2",
        "$HOME/.ssh/known_hosts",
        "printf 'Cannot stat known_hosts: Permission denied\\n' >&2\nexit 255",
    );
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    session.send(b"r");
    session.wait_until("the confirmation", |s| s.contains("Type the host name"));
    session.send(b"db\r");
    session.wait_until("the error", |s| {
        s.contains("The old key was not removed") && s.contains("Cannot stat known_hosts")
    });
    assert!(
        session
            .screen()
            .contains("Stop: the server's identity changed")
    );
    session.send(ENTER);
    quit(session);
}

#[test]
fn a_missing_ssh_keygen_is_explained() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    std::fs::remove_file(fake.program().with_file_name("ssh-keygen")).unwrap();
    let (dir, config) = healthy_store();
    let _keep = dir;
    // The only directory on the PATH is the fake's, which now has no ssh-keygen
    // (the fake ssh needs only shell builtins).
    let mut session = Session::start(
        &config,
        24,
        100,
        &[
            ("PATH", &fake.path_env_without_tools()),
            ("HOME", home.path()),
        ],
    );
    to_the_blocking_screen(&mut session);
    session.send(b"r");
    session.wait_until("the confirmation", |s| s.contains("Type the host name"));
    session.send(b"db\r");
    session.wait_until("the explanation", |s| {
        s.contains("Could not find the 'ssh-keygen' program")
    });
    assert!(home.known_hosts_is_untouched());
    session.send(ENTER);
    quit(session);
}

#[test]
fn no_removal_is_offered_for_a_host_bifrost_did_not_connect_through() {
    let home = Home::new();
    // What a server could print in a banner: another host's name.
    let fake = changed_key_ssh(
        "victim.example.com",
        "$HOME/.ssh/known_hosts",
        KEYGEN_REMOVES,
    );
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    let screen = session.screen();
    assert!(!screen.contains("remove old key"), "{}", screen.text());
    assert!(
        screen.contains("Bifrost will not remove a key here"),
        "{}",
        screen.text()
    );
    session.send(b"r");
    session.send(b"db\r");
    session.send(ENTER);
    session.wait_until("the list", |s| s.contains(HOME_SCREEN));
    assert!(fake.program_arguments("ssh-keygen").is_none());
    assert!(home.known_hosts_is_untouched());
    quit(session);
}

#[test]
fn no_removal_is_offered_for_a_key_kept_in_another_file() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.2", "/etc/ssh/ssh_known_hosts", KEYGEN_REMOVES);
    let (_dir, mut session) = start_at(&fake, &home);
    to_the_blocking_screen(&mut session);
    let screen = session.screen();
    assert!(!screen.contains("remove old key"), "{}", screen.text());
    // The file is shown as information, not offered as a target.
    assert!(
        screen.contains("/etc/ssh/ssh_known_hosts, line 12"),
        "{}",
        screen.text()
    );
    session.send(b"r");
    session.send(ENTER);
    session.wait_until("the list", |s| s.contains(HOME_SCREEN));
    assert!(fake.program_arguments("ssh-keygen").is_none());
    quit(session);
}

#[test]
fn a_jump_host_whose_key_changed_asks_for_the_jump_host_s_name() {
    let home = Home::new();
    let fake = changed_key_ssh("192.0.2.1", "$HOME/.ssh/known_hosts", KEYGEN_REMOVES);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut client = Host::new("client", "192.0.2.2");
    client.proxy_jump = Some("bastion".to_string());
    Store::at(&config)
        .save(&Hosts::from_vec(vec![Host::new("bastion", "192.0.2.1"), client]).unwrap())
        .unwrap();
    let mut session = Session::start(
        &config,
        24,
        100,
        &[("PATH", &fake.path_env()), ("HOME", home.path())],
    );
    session.wait_until("the list", |s| s.contains("Saved hosts: 2"));
    session.send(b"j"); // bastion, then client
    session.send(ENTER);
    session.wait_until("the blocking screen", |s| {
        s.contains("The key that 'bastion' presented") && s.contains("r remove old key...")
    });

    session.send(b"r");
    session.wait_until("the confirmation", |s| {
        s.contains("Remove the old key of 'bastion'?")
    });
    session.send(b"client\r"); // the host being connected to is not the one
    session.wait_until("the refusal", |s| {
        s.contains("That is not the host's name.")
    });
    assert!(fake.program_arguments("ssh-keygen").is_none());
    session.send(b"\x7f\x7f\x7f\x7f\x7f\x7f");
    session.send(b"bastion\r");
    session.wait_until("the result", |s| {
        s.contains("Removed the old key of 'bastion'")
    });
    assert_eq!(
        fake.program_arguments("ssh-keygen").unwrap(),
        ["-R", "192.0.2.1"]
    );
    quit(session);
}
