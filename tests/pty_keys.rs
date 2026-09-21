//! The keys screen in the real binary, in a pseudo-terminal.
//!
//! `ssh-keygen` and `ssh-add` are fake scripts found through `PATH`, and `HOME` is
//! a temporary directory holding a `.ssh` of fake key files, so nothing here
//! touches the real keys, the real agent or the real home.
//!
//! Unix only, like the other pseudo-terminal tests.

#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bifrost_ssh::ssh::authorize::REMOTE_COMMAND;
use bifrost_ssh::store::{HOSTS_FILE, Store};
use support::{CTRL_C, FakeSsh, Session, assert_restored, contains_bytes, healthy_store};

const HOME_SCREEN: &str = "Saved hosts: 2";

/// A home with `~/.ssh` holding key pairs of the given modes, and files that are
/// not keys.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new(keys: &[(&str, u32)]) -> Home {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        for (name, mode) in keys {
            fs::write(ssh.join(name), "not a real private key\n").unwrap();
            fs::set_permissions(ssh.join(name), fs::Permissions::from_mode(*mode)).unwrap();
            fs::write(ssh.join(format!("{name}.pub")), "not a real public key\n").unwrap();
            fs::set_permissions(
                ssh.join(format!("{name}.pub")),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        for other in ["config", "known_hosts", "authorized_keys"] {
            fs::write(ssh.join(other), "x\n").unwrap();
            fs::set_permissions(ssh.join(other), fs::Permissions::from_mode(0o644)).unwrap();
        }
        Home { dir }
    }

    fn path(&self) -> &str {
        self.dir.path().to_str().unwrap()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(".ssh").join(name)
    }

    fn mode(&self, name: &str) -> u32 {
        fs::metadata(self.file(name)).unwrap().permissions().mode() & 0o7777
    }
}

/// What the fake `ssh-keygen -l -f <public>` prints for each key.
const KEYGEN: &str = r#"case "$3" in
  */id_ed25519.pub) echo '256 SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw work laptop (ED25519)' ;;
  */old.pub) echo '2048 SHA256:Crv2UD7RjSr55ym7z5Nso5T9YwtVbduZ6xUVvnj9VtE no comment (RSA)' ;;
  */work.pub) echo '256 SHA256:Crv2UD7RjSr55ym7z5Nso5T9YwtVbduZ6xUVvnj9VtE me on my laptop (ED25519)' ;;
  */id_ed25519_2.pub) echo '256 SHA256:Crv2UD7RjSr55ym7z5Nso5T9YwtVbduZ6xUVvnj9VtE new (ED25519)' ;;
  *) echo "$3 is not a public key file." >&2; exit 1 ;;
esac"#;

/// An agent that holds the ed25519 key.
const AGENT_WITH_KEY: &str =
    "echo '256 SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw work laptop (ED25519)'";

const NO_AGENT: &str =
    "echo 'Could not open a connection to your authentication agent.' >&2\nexit 2";

fn fakes(keygen: &str, ssh_add: &str) -> FakeSsh {
    let fake = FakeSsh::new("exit 0");
    fake.add_program("ssh-keygen", keygen);
    fake.add_program("ssh-add", ssh_add);
    fake
}

fn start(fake: &FakeSsh, home: &Home) -> (tempfile::TempDir, Session) {
    let (dir, _config, session) = start_at(fake, home);
    (dir, session)
}

/// [`start`], and the folder of the saved hosts as well, for tests that look at
/// what was saved.
fn start_at(fake: &FakeSsh, home: &Home) -> (tempfile::TempDir, PathBuf, Session) {
    let (dir, config) = healthy_store();
    let session = start_with_config(fake, home, &config);
    (dir, config, session)
}

fn start_with_config(fake: &FakeSsh, home: &Home, config: &Path) -> Session {
    Session::start(
        config,
        30,
        100,
        &[("PATH", &fake.path_env()), ("HOME", home.path())],
    )
}

/// Waits for the list, presses K and waits for the keys screen with `ready`.
///
/// It also waits for `r refresh`, which only the keys screen's footer has: the
/// list's footer shares words with it (`Up/Down j/k move`), so waiting for those
/// can be satisfied by the list's footer while the keys screen is still being
/// drawn, and a test that then asserts a word is absent reads a half-drawn screen.
fn open_keys(session: &mut Session, ready: impl Fn(&support::Screen) -> bool) {
    session.wait_until("the list", |s| s.alt_screen && s.contains(HOME_SCREEN));
    session.send(b"K");
    session.wait_until("the keys screen", |s| {
        s.alt_screen && s.contains("Keys in ") && s.contains("r refresh") && ready(s)
    });
}

fn quit(mut session: Session) {
    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

#[test]
fn k_lists_the_key_pairs_with_what_ssh_keygen_and_the_agent_say() {
    let home = Home::new(&[("id_ed25519", 0o600), ("old", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);

    // The frame arrives in pieces: wait for everything that is asserted.
    open_keys(&mut session, |s| {
        s.contains("id_ed25519")
            && s.contains("rsa 2048")
            && s.contains("Agent: running, holding 1 key.")
            && s.contains("Up/Down j/k move")
    });
    let screen = session.screen();
    let row = |name: &str| {
        screen
            .lines()
            .into_iter()
            .find(|l| l.contains(name))
            .unwrap()
    };
    assert!(row("> id_ed25519").contains("ed25519") && row("> id_ed25519").contains(" loaded "));
    assert!(row("  old").contains("rsa 2048") && row("  old").contains("not loaded"));
    // Only pairs are keys.
    for other in ["config", "known_hosts", "authorized_keys"] {
        assert!(
            !screen.contains(other),
            "{other} is not a key:\n{}",
            screen.text()
        );
    }
    quit(session);
}

#[test]
fn only_public_files_reach_ssh_keygen_and_ssh_add_is_only_asked_to_list() {
    let home = Home::new(&[("id_ed25519", 0o600), ("old", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("Agent: running"));

    // The last call each fake saw. Bifrost never gave a private file to
    // ssh-keygen, and never gave ssh-add anything but `-l`.
    let keygen_args = fake.program_arguments("ssh-keygen").unwrap();
    assert_eq!(keygen_args[..2], ["-l", "-f"]);
    assert!(keygen_args[2].ends_with(".pub"), "{keygen_args:?}");
    assert!(keygen_args[2].starts_with(home.path()), "{keygen_args:?}");
    assert_eq!(fake.program_arguments("ssh-add").unwrap(), ["-l"]);
    quit(session);
}

#[test]
fn an_agent_that_is_not_running_is_explained_and_no_key_is_claimed_loaded_or_not() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(KEYGEN, NO_AGENT);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("Agent: not running.") && s.contains("That is normal.") && s.contains("unknown")
    });
    let screen = session.screen();
    assert!(!screen.contains("Error:"), "{}", screen.text());
    assert!(!screen.contains("not loaded"), "{}", screen.text());
    quit(session);
}

#[test]
fn a_key_that_is_too_open_is_flagged_and_the_fix_changes_it_on_disk_only_after_y() {
    let home = Home::new(&[("id_ed25519", 0o644), ("old", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("0644 too open")
            && s.contains("Warning: Other users can read")
            && s.contains("f fix permissions")
    });

    // No: nothing changes.
    session.send(b"f");
    session.wait_until("the question", |s| {
        s.contains("Change the permissions of 'id_ed25519'?") && s.contains("y change to 0600")
    });
    session.send(b"n");
    session.wait_until("the list again", |s| {
        !s.contains("Change the permissions") && s.contains("0644 too open")
    });
    assert_eq!(home.mode("id_ed25519"), 0o644);

    // Yes: exactly the private key of that pair, on disk, and the list is read again.
    session.send(b"f");
    session.wait_until("the question again", |s| {
        s.contains("Change the permissions")
    });
    session.send(b"y");
    session.wait_until("the result", |s| {
        s.contains("Changed the permissions of 'id_ed25519' to 0600")
            && !s.contains("too open")
            && !s.contains("Change the permissions")
    });
    assert_eq!(home.mode("id_ed25519"), 0o600);
    assert_eq!(
        home.mode("id_ed25519.pub"),
        0o644,
        "the public key is left alone"
    );
    assert_eq!(home.mode("old"), 0o600);
    assert_eq!(
        home.mode("config"),
        0o644,
        "and so is everything that is not a key"
    );
    quit(session);
}

#[test]
fn esc_at_the_question_cancels_it_and_leaves_the_keys_screen_open() {
    let home = Home::new(&[("id_ed25519", 0o644)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("f fix permissions"));
    session.send(b"f");
    session.wait_until("the question", |s| s.contains("Change the permissions"));
    session.send(b"\x1b");
    session.wait_until("the question gone, the keys still there", |s| {
        !s.contains("Change the permissions")
            && s.contains("Keys in ")
            && s.contains("f fix permissions")
    });
    assert_eq!(home.mode("id_ed25519"), 0o644);
    quit(session);
}

#[test]
fn a_symbolic_link_is_never_offered_a_fix_and_what_it_points_to_is_untouched() {
    let home = Home::new(&[]);
    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("real");
    fs::write(&target, "x").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&target, home.file("id_ed25519")).unwrap();
    fs::write(home.file("id_ed25519.pub"), "x").unwrap();
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("symbolic link, so Bifrost will not change it")
    });
    assert!(!session.screen().contains("f fix permissions"));

    session.send(b"f");
    session.wait_until("the explanation", |s| {
        s.contains("does not change its permissions")
    });
    assert!(!session.screen().contains("Change the permissions of"));
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    quit(session);
}

#[test]
fn no_keys_and_no_folder_are_said_plainly() {
    let home = Home::new(&[]);
    let fake = fakes(KEYGEN, NO_AGENT);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("No key pairs were found"));
    session.send(b"\x1b");
    session.wait_until("the list", |s| {
        s.contains(HOME_SCREEN) && !s.contains("Keys in ")
    });
    quit(session);

    fs::remove_dir_all(home.file("")).unwrap();
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("does not exist, so there are no keys yet")
    });
    quit(session);
}

#[test]
fn hostile_comments_and_agent_output_never_reach_the_terminal() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(
        r#"printf '256 SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw evil\033]0;pwned\007 \342\200\256gpj.exe (ED25519)\n'"#,
        r#"printf 'said \033[31mred\033[0m and \342\200\246\n' >&2
exit 3"#,
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("Agent: could not be told.")
            && s.contains("non-printable characters were hidden")
    });
    let output = {
        session.send(b"q");
        let (status, output) = session.finish();
        assert!(status.success(), "{status:?}");
        assert_restored(&output);
        output
    };
    assert!(
        !contains_bytes(&output, b"\x1b]0;pwned"),
        "a title-setting sequence was drawn"
    );
    assert!(!contains_bytes(&output, "\u{202e}".as_bytes()));
    assert!(!contains_bytes(&output, b"\x1b[31mred"));
}

#[test]
fn an_agent_that_never_answers_is_given_three_seconds_and_the_screen_still_opens() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    // `exec`: the process that hangs is the one that is killed.
    let fake = fakes(KEYGEN, "exec sleep 60");
    let (_dir, mut session) = start(&fake, &home);
    session.wait_until("the list", |s| s.alt_screen && s.contains(HOME_SCREEN));
    let started = Instant::now();
    session.send(b"K");
    session.wait_until("the keys screen", |s| {
        s.contains("Agent: could not be checked.") && s.contains("did not answer within 3 seconds")
    });
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(3),
        "gave up early: {waited:?}"
    );
    assert!(waited < Duration::from_secs(9), "took too long: {waited:?}");
    assert!(
        session.screen().contains("id_ed25519"),
        "the keys are shown regardless"
    );
    quit(session);
}

#[test]
fn ctrl_c_and_esc_leave_the_keys_screen_cleanly() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    session.send(b"\x1b");
    session.wait_until("the list", |s| {
        s.contains(HOME_SCREEN) && !s.contains("Keys in ")
    });
    session.send(b"K");
    session.wait_until("the keys again", |s| s.contains("Keys in "));
    session.send(CTRL_C);
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

#[test]
fn refresh_reads_the_keys_again_and_the_help_comes_back_to_the_keys() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));

    // A key made meanwhile appears after r.
    fs::write(home.file("old"), "x").unwrap();
    fs::set_permissions(home.file("old"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(home.file("old.pub"), "x").unwrap();
    session.send(b"r");
    session.wait_until("the new key", |s| s.contains("rsa 2048"));

    session.send(b"?");
    session.wait_until("the help", |s| s.contains("These keys work in Bifrost:"));
    session.send(b"\x1b");
    session.wait_until("the keys again", |s| {
        s.contains("Keys in ") && s.contains("rsa 2048")
    });
    quit(session);
}

// ---- making a key and adding it to the agent ------------------------------------------------

/// A fake `ssh-keygen` that makes a key when asked to, and lists as `KEYGEN` does.
/// `on_generate` is what it does for `-t ed25519 -f <path> [-C <comment>]`.
fn keygen_making(on_generate: &str) -> String {
    format!("if [ \"$1\" = \"-t\" ]; then\n{on_generate}\nfi\n{KEYGEN}")
}

/// Makes the key where it was asked to, having noted what it was given and
/// whether it had a terminal to ask for a passphrase on.
const MAKES_THE_KEY: &str = r#"printf '%s\n' "$@" > "$HOME/generate-args"
if [ -t 0 ] && [ -t 1 ]; then echo tty > "$HOME/generate-tty"; fi
echo 'FAKE-KEYGEN: making the key'
printf 'a private key\n' > "$4"
chmod 600 "$4"
printf 'a public key\n' > "$4.pub"
exit 0"#;

/// An agent that starts empty and holds the ed25519 key once `ssh-add` ran with
/// something else than `-l`.
const AGENT_THAT_TAKES_KEYS: &str = r#"if [ "$1" = "-l" ]; then
  if [ -e "$HOME/added" ]; then
    echo '256 SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw work laptop (ED25519)'
    exit 0
  fi
  echo 'The agent has no identities.'
  exit 1
fi
printf '%s\n' "$@" > "$HOME/add-args"
if [ -t 0 ] && [ -t 1 ]; then echo tty > "$HOME/add-tty"; fi
echo 'FAKE-ADD: identity added'
touch "$HOME/added"
exit 0"#;

/// What a screen says, with line breaks and runs of spaces made single spaces,
/// for text that wrapped.
fn said(screen: &support::Screen) -> String {
    screen
        .text()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Presses g on the keys screen and waits for the form.
fn open_form(session: &mut Session) {
    session.send(b"g");
    session.wait_until("the form", |s| {
        s.contains("New key") && s.contains("> File name") && s.contains("Bifrost never sees it.")
    });
}

/// Empties the focused field of the form.
fn empty_field(session: &mut Session) {
    session.send(&[0x7f; 40]);
}

#[test]
fn g_makes_a_key_with_ssh_keygen_on_the_real_terminal_and_lists_and_selects_it() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(&keygen_making(MAKES_THE_KEY), AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    open_form(&mut session);
    assert!(
        said(&session.screen()).contains("id_ed25519_2"),
        "a name that is free is offered"
    );

    empty_field(&mut session);
    session.send(b"work\r");
    session.wait_until("the comment field", |s| s.contains("> Comment"));
    session.send(b"me on my laptop\r");
    session.wait_until("the new key, selected", |s| {
        s.contains("Made the key 'work'. Press a to add it to the agent.")
            && s.contains("> work")
            && s.contains("Keys in ")
    });

    // What ssh-keygen was given: this key and comment, and no passphrase.
    let args = fs::read_to_string(home.dir.path().join("generate-args")).unwrap();
    assert_eq!(
        args.lines().collect::<Vec<_>>(),
        [
            "-t".to_string(),
            "ed25519".to_string(),
            "-f".to_string(),
            home.file("work").display().to_string(),
            "-C".to_string(),
            "me on my laptop".to_string(),
        ]
    );
    // It ran on the terminal, where it can ask for the passphrase.
    assert!(home.dir.path().join("generate-tty").exists());
    assert!(
        session
            .screen()
            .normal_contains("FAKE-KEYGEN: making the key")
    );
    assert!(
        session
            .screen()
            .normal_contains("Bifrost: making the key 'work'")
    );
    assert_eq!(home.mode("work"), 0o600);
    assert_eq!(
        fs::read_to_string(home.file("id_ed25519")).unwrap(),
        "not a real private key\n",
        "the other key is untouched"
    );
    quit(session);
}

#[test]
fn a_key_made_without_a_comment_is_made_without_c() {
    let home = Home::new(&[]);
    let fake = fakes(&keygen_making(MAKES_THE_KEY), NO_AGENT);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("No key pairs were found"));
    open_form(&mut session);
    session.send(b"\r\r");
    session.wait_until("the key", |s| s.contains("Made the key 'id_ed25519'."));
    let args = fs::read_to_string(home.dir.path().join("generate-args")).unwrap();
    assert_eq!(
        args.lines().collect::<Vec<_>>(),
        [
            "-t".to_string(),
            "ed25519".to_string(),
            "-f".to_string(),
            home.file("id_ed25519").display().to_string(),
        ]
    );
    quit(session);
}

#[test]
fn a_bad_name_never_reaches_ssh_keygen_and_the_form_says_why() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(&keygen_making(MAKES_THE_KEY), AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    open_form(&mut session);

    // The first row of each complaint: the popup wraps the rest.
    for (typed, complaint) in [
        ("-key", "Error: The file name cannot start with '-'"),
        ("-oProxyCommand=x", "Error: The file name may only contain"),
        ("config", "Error: 'config' is a file that ssh reads"),
        ("ID_ED25519", "Error: There is already a key"),
    ] {
        empty_field(&mut session);
        session.send(typed.as_bytes());
        session.send(b"\r");
        session.wait_until("the complaint", |s| said(s).contains(complaint));
        assert!(session.screen().contains("New key"), "the form stays open");
    }
    assert!(
        !home.dir.path().join("generate-args").exists(),
        "ssh-keygen was never run"
    );
    session.send(b"\x1b");
    session.wait_until("the form closed", |s| {
        !s.contains("New key") && s.contains("Keys in ")
    });
    quit(session);
}

#[test]
fn a_name_that_exists_on_disk_but_is_not_listed_is_refused_and_nothing_is_overwritten() {
    // A private key without its .pub is not listed, so the form does not know.
    let home = Home::new(&[]);
    fs::write(home.file("id_ed25519"), "precious\n").unwrap();
    let fake = fakes(&keygen_making(MAKES_THE_KEY), NO_AGENT);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("No key pairs were found"));
    open_form(&mut session);
    session.send(b"\r\r");
    session.wait_until("the refusal", |s| {
        said(s).contains("already exists") && said(s).contains("never overwrites a key")
    });
    assert_eq!(
        fs::read_to_string(home.file("id_ed25519")).unwrap(),
        "precious\n"
    );
    assert!(!home.dir.path().join("generate-args").exists());
    quit(session);
}

#[test]
fn ctrl_c_while_ssh_keygen_asks_cancels_the_key_and_bifrost_goes_on() {
    let home = Home::new(&[]);
    // Says it is ready, then waits for a line, as it does at the passphrase
    // prompt. It starts nothing after the ready line (see pty_connect.rs).
    let fake = fakes(
        &keygen_making("echo FAKE-READY\nread line\nexit 1"),
        NO_AGENT,
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("No key pairs were found"));
    open_form(&mut session);
    session.send(b"\r\r");
    session.wait_until("ssh-keygen waiting", |s| s.normal_contains("FAKE-READY"));

    session.press_ctrl_c_in_a_normal_terminal();
    session.wait_until("the cancellation", |s| {
        s.alt_screen && s.contains("Making the key was cancelled.")
    });
    assert!(
        session.is_running(),
        "Ctrl-C at ssh-keygen must not quit bifrost"
    );
    quit(session);
}

#[test]
fn a_failed_key_says_what_ssh_keygen_said_last() {
    let home = Home::new(&[]);
    let fake = fakes(
        &keygen_making("echo 'first thing' >&2\necho 'disk full' >&2\nexit 1"),
        NO_AGENT,
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("No key pairs were found"));
    open_form(&mut session);
    session.send(b"\r\r");
    session.wait_until("the error", |s| {
        said(s).contains(
            "Error: Could not make the key 'id_ed25519': ssh-keygen ended with status 1: disk full",
        )
    });
    assert!(!session.screen().contains("first thing"));
    quit(session);
}

#[test]
fn a_missing_ssh_keygen_is_said_when_making_a_key_not_before() {
    let home = Home::new(&[]);
    // Only ssh and ssh-add are found; the PATH holds nothing else.
    let fake = FakeSsh::new("exit 0");
    fake.add_program("ssh-add", NO_AGENT);
    let (_dir, config) = healthy_store();
    let mut session = Session::start(
        &config,
        30,
        100,
        &[
            ("PATH", &fake.path_env_without_tools()),
            ("HOME", home.path()),
        ],
    );
    open_keys(&mut session, |s| s.contains("No key pairs were found"));
    open_form(&mut session);
    session.send(b"\r\r");
    session.wait_until("the explanation", |s| {
        said(s).contains("Error: Could not find the 'ssh-keygen' program")
    });
    assert!(
        session.screen().contains("Keys in "),
        "still on the keys screen"
    );
    quit(session);
}

#[test]
fn a_adds_the_key_with_ssh_add_on_the_real_terminal_and_the_list_shows_it_loaded() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_THAT_TAKES_KEYS);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("not loaded") && s.contains("a add to agent")
    });

    session.send(b"a");
    session.wait_until("the key loaded", |s| {
        s.alt_screen
            && s.contains("Added 'id_ed25519' to the agent.")
            && s.contains(" loaded ")
            && !s.contains("not loaded")
            && !s.contains("a add to agent")
    });
    let args = fs::read_to_string(home.dir.path().join("add-args")).unwrap();
    assert_eq!(
        args.lines().collect::<Vec<_>>(),
        [home.file("id_ed25519").display().to_string()],
        "the path of the key, and nothing else"
    );
    assert!(home.dir.path().join("add-tty").exists());
    assert!(session.screen().normal_contains("FAKE-ADD: identity added"));
    assert!(
        session
            .screen()
            .normal_contains("Bifrost: adding the key 'id_ed25519'")
    );
    quit(session);
}

#[test]
fn a_failed_add_says_what_ssh_add_said_and_the_key_is_still_not_loaded() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let agent = r#"if [ "$1" = "-l" ]; then echo 'The agent has no identities.'; exit 1; fi
echo 'Bad passphrase' >&2
exit 1"#;
    let fake = fakes(KEYGEN, agent);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("a add to agent"));
    session.send(b"a");
    session.wait_until("the error", |s| {
        said(s).contains(
            "Error: Could not add 'id_ed25519' to the agent: ssh-add ended with status 1: Bad passphrase",
        ) && s.contains("not loaded")
    });
    quit(session);
}

#[test]
fn ctrl_c_while_ssh_add_asks_cancels_and_bifrost_goes_on() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let agent = r#"if [ "$1" = "-l" ]; then echo 'The agent has no identities.'; exit 1; fi
echo FAKE-READY
read line
exit 1"#;
    let fake = fakes(KEYGEN, agent);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("a add to agent"));
    session.send(b"a");
    session.wait_until("ssh-add waiting", |s| s.normal_contains("FAKE-READY"));
    session.press_ctrl_c_in_a_normal_terminal();
    session.wait_until("the cancellation", |s| {
        s.alt_screen && s.contains("Adding the key was cancelled.")
    });
    assert!(session.is_running());
    quit(session);
}

#[test]
fn ssh_add_is_not_run_for_a_key_it_is_bound_to_refuse_or_an_agent_that_is_not_there() {
    let home = Home::new(&[("id_ed25519", 0o644)]);
    let fake = fakes(KEYGEN, AGENT_THAT_TAKES_KEYS);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("0644 too open"));
    session.send(b"a");
    session.wait_until("the advice", |s| {
        said(s).contains("ssh-add refuses a private key that other users can read. Press f")
    });
    assert!(!home.dir.path().join("add-args").exists());
    quit(session);

    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(KEYGEN, NO_AGENT);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("Agent: not running."));
    session.send(b"a");
    session.wait_until("the explanation", |s| {
        said(s).contains("no ssh agent answering in this session")
    });
    assert_eq!(fake.program_arguments("ssh-add").unwrap(), ["-l"]);
    quit(session);
}

// ---- sending a public key to a host ------------------------------------------------------------

/// A public key with a comment that a shell would run if it ever read it as
/// commands. It is a valid public key line, so it is sent, and it must arrive
/// as text.
const PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOgZC7Rr8bQm3Kz1x2yFq4mUu0q5m0oH1n7eV1j9XxYp me on $(touch pwned) `id` ; \"q\" 'q' \\n";

impl Home {
    /// Makes `name.pub` hold `text` and a line break.
    fn set_public(&self, name: &str, text: &str) {
        fs::write(self.file(&format!("{name}.pub")), format!("{text}\n")).unwrap();
    }

    fn read(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.dir.path().join(name)).ok()
    }
}

/// Fakes with `ssh_body` as the ssh, and the usual keygen and agent.
fn fakes_with_ssh(ssh_body: &str) -> FakeSsh {
    let fake = FakeSsh::new(ssh_body);
    fake.add_program("ssh-keygen", KEYGEN);
    fake.add_program("ssh-add", AGENT_WITH_KEY);
    fake
}

/// An ssh that asks for a password on the terminal, as the real one does, while
/// its stdin is the pipe the key comes on.
///
/// The terminal is its stdout here (`<&1`), where the real ssh would open
/// `/dev/tty`: the test harness gives the program no controlling terminal, so
/// there is no `/dev/tty` to open. A person's session always has one.
const ASKS_FOR_A_PASSWORD: &str = r#"printf 'FAKE-PASSWORD: '
read pw <&1
printf '%s' "$pw" > "$HOME/typed-password"
cat > "$HOME/sent-stdin"
touch "$HOME/ssh-ran"
exit 0"#;

/// Waits for the question that follows a successful send, and answers no: for
/// the tests that are about the send and not about using the key.
fn decline_the_key(session: &mut Session, host: &str) {
    session.wait_until("the question about using the key", |s| {
        said(s).contains(&format!("Use this key for '{host}' from now on?"))
            && s.contains("y use it")
    });
    session.send(b"n");
    session.wait_until("the question answered", |s| {
        said(s).contains(&format!("'{host}' was left as it was.")) && !s.contains("Use this key?")
    });
}

/// Presses c on the keys screen, picks `db` (the first host: they are listed by
/// name) and waits for the question.
fn ask_to_send(session: &mut Session) {
    session.send(b"c");
    session.wait_until("the hosts", |s| {
        s.contains("Send the public key of 'id_ed25519' to which host?")
            && s.contains("> db")
            && s.contains("192.0.2.2")
            && s.contains("Enter select")
    });
    session.send(b"\r");
    session.wait_until("the question", |s| {
        s.contains("to 'db'?")
            && s.contains("Press y to send it, or n to go back.")
            && s.contains("y send the key")
    });
}

fn with_a_public_key() -> Home {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    home.set_public("id_ed25519", PUBLIC_KEY);
    home
}

#[test]
fn c_sends_the_key_on_stdin_and_ssh_asks_for_the_password_on_the_real_terminal() {
    let home = with_a_public_key();
    let fake = fakes_with_ssh(ASKS_FOR_A_PASSWORD);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);
    assert!(
        home.read("ssh-ran").is_none(),
        "asking sends nothing: ssh has not run"
    );

    session.send(b"y");
    session.wait_until("ssh asking for the password", |s| {
        s.normal_contains("FAKE-PASSWORD:") && s.normal_contains("Bifrost: sending the public key")
    });
    session.send(b"secret\r");
    session.wait_until("the result on the keys screen", |s| {
        s.alt_screen
            && s.contains("Sent the public key of 'id_ed25519' to 'db'.")
            && s.contains("Keys in ")
    });

    // What ssh got on stdin: the line and one line break, exactly, whatever the
    // comment holds. And it got the password from the terminal, not from Bifrost.
    assert_eq!(home.read("sent-stdin").unwrap(), format!("{PUBLIC_KEY}\n"));
    assert_eq!(home.read("typed-password").unwrap(), "secret");
    assert!(!home.dir.path().join("pwned").exists());

    // What ssh was asked to run: the fixed command, after the destination, and
    // nothing of the key on the command line.
    let (_, args) = fake.invocation();
    assert_eq!(
        args,
        [
            "-T",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "--",
            "192.0.2.2",
            REMOTE_COMMAND,
        ]
    );
    assert!(
        !args
            .iter()
            .any(|a| a.contains("AAAA") || a.contains("touch pwned")),
        "the key is not in the arguments: {args:?}"
    );
    decline_the_key(&mut session, "db");
    quit(session);
}

#[test]
fn n_or_esc_at_the_question_sends_nothing_and_runs_no_ssh() {
    let home = with_a_public_key();
    let fake = fakes_with_ssh(ASKS_FOR_A_PASSWORD);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);

    session.send(b"n");
    session.wait_until("back at the hosts", |s| {
        s.contains("to which host?") && !s.contains("Press y to send it")
    });
    session.send(b"\r");
    session.wait_until("the question again", |s| s.contains("Press y to send it"));
    session.send(b"\x1b");
    session.wait_until("back at the hosts", |s| s.contains("to which host?"));
    session.send(b"\x1b");
    session.wait_until("the keys", |s| {
        !s.contains("Send public key") && s.contains("Keys in ")
    });
    assert!(home.read("ssh-ran").is_none());
    quit(session);
}

#[test]
fn a_file_that_is_not_exactly_one_public_key_is_refused_before_ssh_runs() {
    for (bad, said) in [
        ("not a real public key", "does not start with a key type"),
        (
            "command=\"sh -c 'curl x|sh'\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 evil",
            "does not start with a key type",
        ),
        (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 one\nssh-rsa AAAAB3NzaC1yc2E two",
            "more than one line",
        ),
        (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 bell\x07",
            "control characters",
        ),
    ] {
        let home = Home::new(&[("id_ed25519", 0o600)]);
        home.set_public("id_ed25519", bad);
        let fake = fakes_with_ssh(ASKS_FOR_A_PASSWORD);
        let (_dir, mut session) = start(&fake, &home);
        open_keys(&mut session, |s| s.contains("id_ed25519"));
        ask_to_send(&mut session);
        session.send(b"y");
        session.wait_until("the refusal", |s| {
            s.alt_screen && said_in(s, "Error: ", said)
        });
        assert!(home.read("ssh-ran").is_none(), "{bad:?}: ssh was run");
        assert!(home.read("sent-stdin").is_none(), "{bad:?}");
        quit(session);
    }
}

/// Whether the status line has `prefix` and then `said` somewhere after it.
fn said_in(screen: &support::Screen, prefix: &str, said: &str) -> bool {
    let text = said_text(screen);
    text.find(prefix)
        .is_some_and(|at| text[at..].contains(said))
}

fn said_text(screen: &support::Screen) -> String {
    screen
        .text()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn a_refused_login_is_explained_on_the_error_screen_and_goes_back_to_the_keys() {
    let home = with_a_public_key();
    let fake = fakes_with_ssh(
        "echo 'deploy@192.0.2.2: Permission denied (publickey,password).' >&2\nexit 255",
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);
    session.send(b"y");
    session.wait_until("the explanation", |s| {
        s.alt_screen
            && s.contains("The server refused the login")
            && s.contains("What you can try:")
    });
    session.send(b"\x1b");
    session.wait_until("the keys screen", |s| {
        s.alt_screen && s.contains("Keys in ") && !s.contains("The server refused the login")
    });
    quit(session);
}

#[test]
fn a_command_the_server_ran_and_that_failed_is_told_apart_from_a_connection_failure() {
    let home = with_a_public_key();
    let fake = fakes_with_ssh(
        "cat > /dev/null\necho \"mkdir: cannot create directory '.ssh': Permission denied\" >&2\nexit 3",
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);
    session.send(b"y");
    session.wait_until("the result", |s| {
        s.alt_screen
            && said_in(s, "Error: 'db' ran the command", "failed (status 3)")
            && said_in(s, "It said:", "mkdir: cannot create directory")
            && s.contains("Keys in ")
    });
    assert!(!session.screen().contains("What you can try"));
    quit(session);
}

#[test]
fn a_changed_host_key_stops_on_the_blocking_screen_and_nothing_is_removed() {
    let home = with_a_public_key();
    let fake = fakes_with_ssh(
        r#"cat > /dev/null
printf '%s\r\n' '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @' \
  'The fingerprint for the ED25519 key sent by the remote host is' \
  'SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA.' \
  "Offending ED25519 key in $HOME/.ssh/known_hosts:12" \
  'Host key for 192.0.2.2 has changed and you have requested strict checking.' \
  'Host key verification failed.' >&2
exit 255"#,
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);
    session.send(b"y");
    session.wait_until("the blocking screen", |s| {
        s.alt_screen && s.contains("Stop: the server's identity changed")
    });
    session.send(b"\r");
    session.wait_until("the keys screen", |s| {
        s.alt_screen && s.contains("Keys in ") && !s.contains("identity changed")
    });
    // Only the listing ever reached ssh-keygen: nothing was removed.
    assert_eq!(
        fake.program_arguments("ssh-keygen").unwrap()[..2],
        ["-l", "-f"]
    );
    quit(session);
}

#[test]
fn ctrl_c_at_the_password_prompt_cancels_the_send_and_bifrost_goes_on() {
    let home = with_a_public_key();
    // Says it is ready, then waits on the terminal for the password, and starts
    // nothing after the ready line (see pty_connect.rs).
    let fake = fakes_with_ssh("echo FAKE-READY\nread pw <&1\nexit 1");
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);
    session.send(b"y");
    session.wait_until("ssh waiting", |s| s.normal_contains("FAKE-READY"));
    session.press_ctrl_c_in_a_normal_terminal();
    session.wait_until("the cancellation", |s| {
        s.alt_screen && s.contains("Sending the key was cancelled.")
    });
    assert!(
        session.is_running(),
        "Ctrl-C at ssh's prompt must not quit bifrost"
    );
    quit(session);
}

#[test]
fn what_is_typed_while_the_key_is_being_sent_is_not_run_as_commands_afterwards() {
    let home = with_a_public_key();
    // ssh reads none of the typed input from the terminal; it waits for $GO.
    let fake = fakes_with_ssh(
        "cat > /dev/null\necho FAKE-READY\nwhile [ ! -e \"$GO\" ]; do sleep 0.05; done\nexit 0",
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);
    session.send(b"y");
    session.wait_until("ssh running", |s| s.normal_contains("FAKE-READY"));
    // In Bifrost these are commands: q quits, g opens a form.
    session.send(b"qgq");
    // Let the terminal deliver it before ssh ends.
    std::thread::sleep(Duration::from_millis(300));
    fake.release();
    session.wait_until("the result", |s| {
        s.alt_screen && s.contains("Sent the public key of 'id_ed25519' to 'db'.")
    });
    assert!(session.is_running(), "a typed q must not quit");
    assert!(!session.screen().contains("New key"));
    decline_the_key(&mut session, "db");
    quit(session);
}

#[test]
fn a_host_that_has_forwards_and_agent_forwarding_gets_neither_when_a_key_is_sent() {
    use bifrost_ssh::domain::{Forward, Host, Hosts};
    use bifrost_ssh::store::Store;

    let home = with_a_public_key();
    let fake = fakes_with_ssh("cat > /dev/null\nexit 0");
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut busy = Host::new("busy", "192.0.2.7");
    busy.forward_agent = true;
    busy.local_forwards.push(Forward {
        listen_port: 8080,
        dest_host: "localhost".to_string(),
        dest_port: 80,
    });
    let mut hosts = Hosts::new();
    hosts.add(busy).unwrap();
    Store::at(&config).save(&hosts).unwrap();
    let mut session = Session::start(
        &config,
        30,
        100,
        &[("PATH", &fake.path_env()), ("HOME", home.path())],
    );
    // One host is saved, so the list says so: not what `open_keys` waits for.
    session.wait_until("the list", |s| s.alt_screen && s.contains("Saved hosts: 1"));
    session.send(b"K");
    session.wait_until("the keys screen", |s| {
        s.contains("Keys in ") && s.contains("id_ed25519")
    });
    session.send(b"c\r");
    session.wait_until("the question", |s| s.contains("Press y to send it"));
    session.send(b"y");
    session.wait_until("the result", |s| s.contains("Sent the public key"));
    let (_, args) = fake.invocation();
    assert!(
        !args
            .iter()
            .any(|a| a == "-A" || a == "-L" || a.contains("8080")),
        "{args:?}"
    );
    decline_the_key(&mut session, "busy");
    quit(session);
}

// ---- using a key that was sent, and choosing the identity file ---------------------------------

const CTRL_S: &[u8] = b"\x13";

/// The saved hosts of `config`, by name, with the identity file each has.
fn identity_files(config: &Path) -> Vec<(String, Option<String>)> {
    let mut hosts: Vec<(String, Option<String>)> = Store::at(config)
        .load()
        .unwrap()
        .hosts
        .as_slice()
        .iter()
        .map(|host| (host.name.clone(), host.identity_file.clone()))
        .collect();
    hosts.sort();
    hosts
}

/// Sends the key of `id_ed25519` to `db` and waits for the question about using
/// it, having typed a password on the fake ssh's prompt.
fn send_and_wait_for_the_question(session: &mut Session, replaces: Option<&str>) {
    ask_to_send(session);
    session.send(b"y");
    session.wait_until("ssh asking for the password", |s| {
        s.normal_contains("FAKE-PASSWORD:")
    });
    session.send(b"secret\r");
    // Each fragment is on one line of the popup: a phrase that wraps would be
    // joined with whatever is drawn to the left of the popup on the next line.
    session.wait_until("the question", |s| {
        let text = said(s);
        text.contains("Use this key for 'db' from now on?")
            && text.contains("Press y to use it, or n to leave the host as it is.")
            && replaces.is_none_or(|old| {
                text.contains(&format!("This replaces {old}, which the host uses now."))
            })
            && s.contains("y use it")
    });
}

#[test]
fn y_after_a_send_sets_the_hosts_key_and_saves_it_and_only_then() {
    let home = with_a_public_key();
    let fake = fakes_with_ssh(ASKS_FOR_A_PASSWORD);
    let (_dir, config, mut session) = start_at(&fake, &home);
    let before = fs::read(config.join(HOSTS_FILE)).unwrap();
    open_keys(&mut session, |s| s.contains("id_ed25519"));

    send_and_wait_for_the_question(&mut session, None);
    assert_eq!(
        fs::read(config.join(HOSTS_FILE)).unwrap(),
        before,
        "asking saved nothing"
    );
    // Nothing but y answers it: Enter, letters and q do not.
    session.send(b"\rjaq");
    assert!(session.is_running(), "a q at the question does not quit");
    assert_eq!(fs::read(config.join(HOSTS_FILE)).unwrap(), before);

    session.send(b"y");
    session.wait_until("the result", |s| {
        s.alt_screen
            && said(s).contains("'db' now uses the key 'id_ed25519' (~/.ssh/id_ed25519).")
            && !s.contains("Use this key?")
            && s.contains("Keys in ")
    });
    assert_eq!(
        identity_files(&config),
        [
            ("db".to_string(), Some("~/.ssh/id_ed25519".to_string())),
            ("web".to_string(), None)
        ]
    );
    assert!(
        Store::at(&config).backup_path().exists(),
        "the previous version is kept"
    );
    assert_eq!(
        fs::metadata(config.join(HOSTS_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    quit(session);
}

#[test]
fn n_or_esc_after_a_send_leaves_the_saved_hosts_exactly_as_they_were() {
    for answer in [&b"n"[..], &b"\x1b"[..]] {
        let home = with_a_public_key();
        let fake = fakes_with_ssh(ASKS_FOR_A_PASSWORD);
        let (_dir, config, mut session) = start_at(&fake, &home);
        let before = fs::read(config.join(HOSTS_FILE)).unwrap();
        open_keys(&mut session, |s| s.contains("id_ed25519"));
        send_and_wait_for_the_question(&mut session, None);
        session.send(answer);
        session.wait_until("the question answered", |s| {
            said(s).contains("'db' was left as it was.")
                && !s.contains("Use this key?")
                && s.contains("Keys in ")
        });
        assert_eq!(
            fs::read(config.join(HOSTS_FILE)).unwrap(),
            before,
            "{answer:?}"
        );
        quit(session);
    }
}

/// A store with `db` and `web`, where `db` has `identity_file`.
fn store_where_db_has(identity_file: &str) -> (tempfile::TempDir, PathBuf) {
    use bifrost_ssh::domain::{Host, Hosts};
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bifrost");
    let mut hosts = Hosts::new();
    hosts.add(Host::new("web", "192.0.2.1")).unwrap();
    let mut db = Host::new("db", "192.0.2.2");
    db.identity_file = Some(identity_file.to_string());
    hosts.add(db).unwrap();
    Store::at(&config).save(&hosts).unwrap();
    (dir, config)
}

#[test]
fn a_host_that_already_uses_the_key_is_not_asked_however_its_path_is_written() {
    for spelled in ["~/.ssh/id_ed25519", "HOME/.ssh/id_ed25519"] {
        let home = with_a_public_key();
        let spelled = spelled.replace("HOME", home.path());
        let (_store_dir, config) = store_where_db_has(&spelled);
        let fake = fakes_with_ssh(ASKS_FOR_A_PASSWORD);
        let mut session = start_with_config(&fake, &home, &config);
        open_keys(&mut session, |s| s.contains("id_ed25519"));
        ask_to_send(&mut session);
        session.send(b"y");
        session.wait_until("ssh asking for the password", |s| {
            s.normal_contains("FAKE-PASSWORD:")
        });
        session.send(b"secret\r");
        session.wait_until("the result and no question", |s| {
            s.alt_screen
                && said(s).contains("Sent the public key of 'id_ed25519' to 'db'.")
                && !s.contains("Use this key?")
        });
        // The list's keys work: nothing is open, so q quits.
        quit(session);
        assert_eq!(
            identity_files(&config)[0],
            ("db".to_string(), Some(spelled.clone()))
        );
    }
}

#[test]
fn a_host_with_another_key_is_told_what_would_be_replaced_and_yes_replaces_it() {
    let home = with_a_public_key();
    let (_store_dir, config) = store_where_db_has("~/.ssh/other_key");
    let fake = fakes_with_ssh(ASKS_FOR_A_PASSWORD);
    let mut session = start_with_config(&fake, &home, &config);
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    send_and_wait_for_the_question(&mut session, Some("~/.ssh/other_key"));
    session.send(b"y");
    session.wait_until("the result", |s| {
        said(s).contains("'db' now uses the key 'id_ed25519'")
    });
    assert_eq!(
        identity_files(&config)[0],
        ("db".to_string(), Some("~/.ssh/id_ed25519".to_string()))
    );
    quit(session);
}

#[test]
fn a_send_that_failed_asks_nothing() {
    let home = with_a_public_key();
    let fake = fakes_with_ssh("cat > /dev/null\necho 'mkdir: no' >&2\nexit 3");
    let (_dir, config, mut session) = start_at(&fake, &home);
    let before = fs::read(config.join(HOSTS_FILE)).unwrap();
    open_keys(&mut session, |s| s.contains("id_ed25519"));
    ask_to_send(&mut session);
    session.send(b"y");
    session.wait_until("the failure", |s| said(s).contains("'db' ran the command"));
    assert!(!session.screen().contains("Use this key?"));
    assert_eq!(fs::read(config.join(HOSTS_FILE)).unwrap(), before);
    quit(session);
}

/// Opens the add form on the identity file, with a name and a host name typed.
fn add_form_on_the_identity_file(session: &mut Session) {
    session.wait_until("the list", |s| s.alt_screen && s.contains(HOME_SCREEN));
    session.send(b"a");
    session.wait_until("the form", |s| s.contains("Add host"));
    session.send(b"app\t");
    session.send(b"app.example.com\t\t\t");
    session.wait_until("the identity file", |s| said(s).contains("> Identity file"));
}

#[test]
fn the_identity_file_is_chosen_from_the_keys_found_and_saved_as_a_path() {
    let home = Home::new(&[("id_ed25519", 0o600), ("old", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, config, mut session) = start_at(&fake, &home);
    add_form_on_the_identity_file(&mut session);

    session.send(b"\r");
    session.wait_until("the list of keys", |s| {
        let text = said(s);
        text.contains("Key file")
            && text.contains("> (none) ssh uses its default keys")
            && text.contains("id_ed25519 ed25519")
            && text.contains("old rsa 2048")
            && text.contains("Another file type a path yourself")
            && s.contains("Enter choose")
    });
    // The list is names and types, and needed no agent: ssh-add was never run.
    assert!(
        fake.program_arguments("ssh-add").is_none(),
        "the agent was asked: {:?}",
        fake.program_arguments("ssh-add")
    );
    let keygen = fake.program_arguments("ssh-keygen").unwrap();
    assert_eq!(
        keygen[..2],
        ["-l", "-f"],
        "only reading, never making: {keygen:?}"
    );

    session.send(b"j\r");
    session.wait_until("the key in the field", |s| {
        said(s).contains("Identity file ~/.ssh/id_ed25519") && !s.contains("Key file")
    });
    session.send(CTRL_S);
    session.wait_until("saved", |s| {
        s.alt_screen
            && said(s).contains("Added host 'app'.")
            && s.contains(HOME_SCREEN.replace('2', "3").as_str())
    });
    assert!(
        identity_files(&config)
            .contains(&("app".to_string(), Some("~/.ssh/id_ed25519".to_string()))),
        "{:?}",
        identity_files(&config)
    );
    quit(session);
}

#[test]
fn none_clears_the_key_and_another_file_keeps_a_path_typed_by_hand() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, config, mut session) = start_at(&fake, &home);
    add_form_on_the_identity_file(&mut session);

    // A path that is somewhere else, typed: the list keeps it under "Another file".
    session.send(b"/elsewhere/key\r");
    session.wait_until("the list with the path kept", |s| {
        said(s).contains("> Another file keeps /elsewhere/key")
    });
    session.send(b"\r");
    session.wait_until("back to typing, the path there", |s| {
        said(s).contains("Identity file /elsewhere/key") && !s.contains("Key file")
    });
    // Typing goes on where it was.
    session.send(b"2");
    session.wait_until("the path grew", |s| {
        said(s).contains("Identity file /elsewhere/key2")
    });
    // None empties it.
    session.send(b"\r");
    session.wait_until("the list", |s| s.contains("Key file"));
    session.send(b"\x1b[H"); // Home
    session.send(b"\r");
    session.wait_until("the field is empty", |s| {
        !s.contains("Key file") && !said(s).contains("/elsewhere/key2")
    });
    session.send(CTRL_S);
    session.wait_until("saved", |s| said(s).contains("Added host 'app'."));
    assert!(
        identity_files(&config).contains(&("app".to_string(), None)),
        "{:?}",
        identity_files(&config)
    );
    quit(session);
}

#[test]
fn a_path_typed_by_hand_is_saved_as_typed_and_esc_closes_the_list_without_changing_it() {
    let home = Home::new(&[("id_ed25519", 0o600)]);
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, config, mut session) = start_at(&fake, &home);
    add_form_on_the_identity_file(&mut session);
    session.send(b"/elsewhere/key");
    session.send(b"\r");
    session.wait_until("the list", |s| s.contains("Key file"));
    session.send(b"j\x1b");
    session.wait_until("the list closed, the path there", |s| {
        !s.contains("Key file") && said(s).contains("Identity file /elsewhere/key")
    });
    session.send(CTRL_S);
    session.wait_until("saved", |s| said(s).contains("Added host 'app'."));
    assert!(
        identity_files(&config).contains(&("app".to_string(), Some("/elsewhere/key".to_string()))),
        "{:?}",
        identity_files(&config)
    );
    quit(session);
}

#[test]
fn with_no_keys_the_list_says_what_to_do_and_typing_still_works() {
    let home = Home::new(&[]);
    let fake = fakes(KEYGEN, NO_AGENT);
    let (_dir, _config, mut session) = start_at(&fake, &home);
    add_form_on_the_identity_file(&mut session);
    session.send(b"\r");
    session.wait_until("the list and its note", |s| {
        let text = said(s);
        text.contains("(none)")
            && text.contains("Another file")
            && text.contains("There are no key pairs in")
            && text.contains("then g)")
    });
    session.send(b"\x1b");
    session.wait_until("the form again", |s| !s.contains("Key file"));
    quit_from_the_form(session);
}

/// Leaves the form (Esc, then y to discard) and quits from the list.
fn quit_from_the_form(mut session: Session) {
    session.send(b"\x1b");
    session.wait_until("the question", |s| s.contains("Discard changes?"));
    session.send(b"y");
    session.wait_until("the list", |s| {
        s.contains(HOME_SCREEN) && !s.contains("Add host")
    });
    quit(session);
}

#[test]
fn a_key_file_with_control_characters_in_its_name_is_never_offered_or_drawn() {
    let home = Home::new(&[("fine", 0o600)]);
    let evil = "evil\x1b]0;pwned\x07";
    fs::write(home.file(evil), "x").unwrap();
    fs::set_permissions(home.file(evil), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(home.file(&format!("{evil}.pub")), "x").unwrap();
    let fake = fakes(
        "echo '256 SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw c (ED25519)'",
        NO_AGENT,
    );
    let (_dir, _config, mut session) = start_at(&fake, &home);
    add_form_on_the_identity_file(&mut session);
    session.send(b"\r");
    session.wait_until("the list", |s| {
        s.contains("Key file") && said(s).contains("fine ed25519")
    });
    assert!(
        !session.screen().contains("pwned"),
        "{}",
        session.screen().text()
    );
    // One Esc at a time: two together are read as an Alt+Esc chord.
    session.send(b"\x1b");
    session.wait_until("the list closed", |s| !s.contains("Key file"));
    session.send(b"\x1b");
    session.wait_until("the question", |s| s.contains("Discard changes?"));
    session.send(b"y");
    session.wait_until("the list", |s| {
        s.contains(HOME_SCREEN) && !s.contains("Add host")
    });
    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
    assert!(!contains_bytes(&output, b"\x1b]0;pwned"), "a title was set");
}

// ---- deleting a key --------------------------------------------------------------------------

/// Whether some row of the screen has `fragment` in it. For text that wraps in a
/// popup, where the flattened screen would join it with what is drawn beside it.
fn row_has(screen: &support::Screen, fragment: &str) -> bool {
    screen.lines().iter().any(|line| line.contains(fragment))
}

/// A home with the keys `id_ed25519` and `old`, and files that are not keys next
/// to them: everything a deletion of one key must leave alone.
fn home_with_bystanders() -> Home {
    let home = Home::new(&[("id_ed25519", 0o600), ("old", 0o600)]);
    fs::write(
        home.file("lonely.pub"),
        "a public key with no private half\n",
    )
    .unwrap();
    home
}

const BYSTANDERS: [(&str, &str); 6] = [
    ("old", "not a real private key\n"),
    ("old.pub", "not a real public key\n"),
    ("config", "x\n"),
    ("known_hosts", "x\n"),
    ("authorized_keys", "x\n"),
    ("lonely.pub", "a public key with no private half\n"),
];

fn assert_bystanders_untouched(home: &Home) {
    for (name, text) in BYSTANDERS {
        assert_eq!(
            fs::read_to_string(home.file(name)).ok().as_deref(),
            Some(text),
            "{name} must be exactly as it was"
        );
    }
}

fn wait_for_the_delete_question(session: &mut Session, key: &str) {
    session.wait_until("the delete question", |s| {
        said(s).contains(&format!("Delete the key '{key}'?"))
            && row_has(s, "Type the key's name to confirm:")
            && s.contains("Enter delete")
    });
}

#[test]
fn d_deletes_the_pair_after_the_name_is_typed_and_nothing_else_and_no_host_is_changed() {
    let home = home_with_bystanders();
    let (_store_dir, config) = store_where_db_has("~/.ssh/id_ed25519");
    let hosts_before = fs::read(config.join(HOSTS_FILE)).unwrap();
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let mut session = start_with_config(&fake, &home, &config);
    open_keys(&mut session, |s| {
        s.contains("id_ed25519") && s.contains("D delete")
    });

    session.send(b"D");
    wait_for_the_delete_question(&mut session, "id_ed25519");
    // What the question must say, before anything is typed.
    let screen = session.screen();
    assert!(row_has(&screen, "Used by: db."), "{}", screen.text());
    assert!(
        row_has(
            &screen,
            "Bifrost cannot know which servers have this key in"
        ),
        "{}",
        screen.text()
    );
    assert!(
        row_has(&screen, "authorized_keys. Deleting it means losing"),
        "{}",
        screen.text()
    );
    assert!(
        row_has(&screen, "access to those servers until another key is"),
        "{}",
        screen.text()
    );
    assert!(
        row_has(&screen, "The agent holds this key"),
        "it is loaded in the agent: {}",
        screen.text()
    );
    assert!(home.file("id_ed25519").exists(), "asking deleted nothing");

    // A wrong name deletes nothing and says so.
    session.send(b"nope\r");
    session.wait_until("the complaint", |s| {
        row_has(s, "That is not the key's name.")
    });
    assert!(home.file("id_ed25519").exists() && home.file("id_ed25519.pub").exists());
    // Erase it, and type the name.
    session.send(&[0x7f; 4]);
    session.send(b"id_ed25519\r");
    session.wait_until("the result", |s| {
        let text = said(s);
        text.contains("Deleted the key 'id_ed25519': removed")
            && text.contains("These saved hosts still name it as their key file: db.")
            && !s.contains("Delete key")
    });
    session.wait_until("the keys read again", |s| {
        row_has(s, "> old") && !row_has(s, "id_ed25519  ")
    });

    // On disk: the pair is gone, and every other file is exactly as it was.
    assert!(!home.file("id_ed25519").exists(), "the private key is gone");
    assert!(!home.file("id_ed25519.pub").exists(), "and its .pub");
    assert_bystanders_untouched(&home);
    // The saved hosts were not touched: db still names the key it no longer has.
    assert_eq!(fs::read(config.join(HOSTS_FILE)).unwrap(), hosts_before);
    assert_eq!(
        identity_files(&config)[0],
        ("db".to_string(), Some("~/.ssh/id_ed25519".to_string()))
    );
    quit(session);
}

#[test]
fn nothing_is_deleted_by_a_lowercase_d_esc_a_wrong_name_or_ctrl_c() {
    let home = home_with_bystanders();
    let fake = fakes(KEYGEN, AGENT_WITH_KEY);
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("id_ed25519") && s.contains("D delete")
    });
    let untouched = |home: &Home| {
        assert!(home.file("id_ed25519").exists() && home.file("id_ed25519.pub").exists());
        assert_bystanders_untouched(home);
    };

    // A plain d does nothing: the help that comes after it is what opens.
    session.send(b"d?");
    session.wait_until("the help, and no question", |s| {
        s.contains("These keys work in Bifrost:") && !s.contains("Delete key")
    });
    session.send(b"\x1b");
    session.wait_until("the keys again", |s| {
        s.contains("Keys in ") && !s.contains("These keys work")
    });
    untouched(&home);

    // Esc gives up.
    session.send(b"D");
    wait_for_the_delete_question(&mut session, "id_ed25519");
    session.send(b"id_ed25519");
    session.send(b"\x1b");
    session.wait_until("given up", |s| {
        said(s).contains("Nothing was deleted.") && !s.contains("Delete key")
    });
    untouched(&home);

    // Names that are nearly right are wrong: case, a space, a prefix, a suffix.
    for typed in ["ID_ED25519", "id_ed25519 ", "id_ed2551", "id_ed25519x"] {
        session.send(b"D");
        wait_for_the_delete_question(&mut session, "id_ed25519");
        session.send(typed.as_bytes());
        session.send(b"\r");
        session.wait_until("the complaint", |s| {
            row_has(s, "That is not the key's name.")
        });
        untouched(&home);
        session.send(b"\x1b");
        session.wait_until("given up", |s| !s.contains("Delete key"));
    }

    // Ctrl-C at the question quits, with everything where it was.
    session.send(b"D");
    wait_for_the_delete_question(&mut session, "id_ed25519");
    session.send(b"id_ed25519");
    session.send(CTRL_C);
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
    untouched(&home);
}

#[cfg(unix)]
#[test]
fn a_key_that_is_a_link_is_removed_as_a_link_and_the_file_it_points_to_stays() {
    let home = Home::new(&[]);
    let elsewhere = tempfile::tempdir().unwrap();
    let real = elsewhere.path().join("real_private");
    fs::write(&real, "THE REAL PRIVATE KEY\n").unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&real, home.file("linked")).unwrap();
    fs::write(home.file("linked.pub"), "a public key\n").unwrap();
    let fake = fakes(
        "echo '256 SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw c (ED25519)'",
        NO_AGENT,
    );
    let (_dir, mut session) = start(&fake, &home);
    open_keys(&mut session, |s| {
        s.contains("linked") && s.contains("D delete")
    });

    session.send(b"D");
    wait_for_the_delete_question(&mut session, "linked");
    assert!(
        row_has(
            &session.screen(),
            "It is a symbolic link: only the link is removed"
        ),
        "{}",
        session.screen().text()
    );
    session.send(b"linked\r");
    session.wait_until("deleted", |s| {
        said(s).contains("Deleted the key 'linked': removed")
    });

    assert!(
        fs::symlink_metadata(home.file("linked")).is_err(),
        "the link is gone"
    );
    assert!(!home.file("linked.pub").exists());
    assert_eq!(
        fs::read_to_string(&real).unwrap(),
        "THE REAL PRIVATE KEY\n",
        "the file the link pointed to is untouched"
    );
    quit(session);
}

// ---- the real tools ----------------------------------------------------------------------------

/// `#[ignore]`: needs the real `ssh-keygen`. Run by hand with
/// `cargo test --test pty_keys -- --ignored`. It makes a key in a temporary
/// home and answers the passphrase prompt with an empty passphrase, which is the
/// one thing the fakes cannot show: that the real prompt appears on the real
/// terminal, and that what it makes is a key.
#[test]
#[ignore = "needs the real ssh-keygen"]
fn the_real_ssh_keygen_asks_for_its_passphrase_itself_and_makes_the_key() {
    let home = Home::new(&[]);
    let (_dir, config) = healthy_store();
    let mut session = Session::start(
        &config,
        30,
        100,
        &[
            ("PATH", "/usr/bin:/bin:/usr/local/bin"),
            ("HOME", home.path()),
        ],
    );
    open_keys(&mut session, |s| s.contains("No key pairs were found"));
    open_form(&mut session);
    empty_field(&mut session);
    session.send(b"real\rme on my laptop\r");
    session.wait_until("the passphrase prompt", |s| {
        s.normal_contains("Enter passphrase")
    });
    // Empty, and again to confirm.
    session.send(b"\r");
    session.wait_until("the confirmation prompt", |s| {
        s.normal_contains("Enter same passphrase again")
    });
    session.send(b"\r");
    session.wait_until("the new key, listed and selected", |s| {
        s.alt_screen && s.contains("Made the key 'real'.") && s.contains("> real")
    });
    assert!(
        session.screen().contains("ed25519") && session.screen().contains("me on my laptop"),
        "{}",
        session.screen().text()
    );
    assert_eq!(home.mode("real"), 0o600);
    let listed = std::process::Command::new("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(home.file("real.pub"))
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.contains("(ED25519)") && listed.contains("me on my laptop"),
        "{listed}"
    );
    quit(session);
}
