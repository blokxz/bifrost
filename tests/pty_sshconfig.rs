//! The ssh config screen in the real binary, in a pseudo-terminal.
//!
//! `ssh` is a fake script found through `PATH` that answers `ssh -G <name>` from a
//! table, and `HOME` is a temporary directory with a `.ssh` that holds an ssh
//! config to import, so nothing here touches the real ssh config, the real
//! store or the real home. What is checked on disk is what the store and the
//! export file really hold afterwards.
//!
//! Unix only, like the other pseudo-terminal tests.

#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use bifrost_ssh::ssh::export::{GENERATED_HEADER, INCLUDE_LINE};
use bifrost_ssh::store::{HOSTS_FILE, Store};
use support::{FakeSsh, Session, assert_restored, contains_bytes, healthy_store};

const HOME_SCREEN: &str = "Saved hosts: 2";

/// The ssh config that is imported. `web` is already saved, `app` and `jumpy` are
/// new, `caf\u{e9}` is not a name Bifrost accepts, and `broken` is a host that ssh
/// itself refuses.
const SSH_CONFIG: &str = "Host web\n  HostName 192.0.2.1\n\
Host app\n  HostName app.example.com\n  User deploy\n  Port 2222\n  IdentityFile ~/.ssh/id_app\n\
Host jumpy\n  HostName jumpy.example.com\n  ProxyCommand nc %h %p\n\
Host caf\u{e9}\n  HostName cafe.example.com\n\
Host broken\n  HostName broken.example.com\n";

/// What the fake `ssh -G` prints for each host of [`SSH_CONFIG`], as the real one
/// does: lower case keywords, and ssh's default identity files as well.
const FAKE_SSH_G: &str = r#"if [ "$1" = "-G" ]; then
  case "$3" in
    app)
      printf 'hostname app.example.com\nuser deploy\nport 2222\n'
      printf 'identityfile %s/.ssh/id_app\nidentityfile ~/.ssh/id_ed25519\n' "$HOME"
      ;;
    jumpy)
      printf 'hostname jumpy.example.com\nuser me\nport 22\nproxycommand nc %%h %%p\n'
      ;;
    broken)
      echo 'ssh: Could not resolve hostname broken: Name or service not known' >&2
      exit 255
      ;;
    *)
      printf 'hostname %s\nuser me\nport 22\n' "$3"
      ;;
  esac
  exit 0
fi
exit 0"#;

/// A home with a `.ssh`, and what is in it before the test.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new(config: Option<&str>) -> Home {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        if let Some(config) = config {
            fs::write(ssh.join("config"), config).unwrap();
        }
        Home { dir }
    }

    fn path(&self) -> &str {
        self.dir.path().to_str().unwrap()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(".ssh").join(name)
    }

    fn read(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.file(name)).ok()
    }
}

fn start(fake: &FakeSsh, home: &Home) -> (tempfile::TempDir, PathBuf, Session) {
    let (dir, config) = healthy_store();
    let session = Session::start(
        &config,
        30,
        100,
        &[("PATH", &fake.path_env()), ("HOME", home.path())],
    );
    (dir, config, session)
}

/// What a screen says, with line breaks, borders and runs of spaces made single
/// spaces, for text that wrapped.
fn said(screen: &support::Screen) -> String {
    screen
        .text()
        .split_whitespace()
        .filter(|word| *word != "│")
        .collect::<Vec<_>>()
        .join(" ")
}

/// Waits for the list, presses s and waits for the two choices.
fn open_ssh_config(session: &mut Session) {
    session.wait_until("the list", |s| s.alt_screen && s.contains(HOME_SCREEN));
    session.send(b"s");
    session.wait_until("the ssh config screen", |s| {
        s.contains("SSH config") && s.contains("i import") && s.contains("e export")
    });
}

fn quit(mut session: Session) {
    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}

fn saved_hosts(config: &PathBuf) -> Vec<String> {
    let mut names: Vec<String> = Store::at(config)
        .load()
        .unwrap()
        .hosts
        .as_slice()
        .iter()
        .map(|host| host.name.clone())
        .collect();
    names.sort();
    names
}

// ---- import ----------------------------------------------------------------------------------

#[test]
fn i_shows_what_importing_would_do_and_saves_nothing_until_y() {
    let home = Home::new(Some(SSH_CONFIG));
    let fake = FakeSsh::new(FAKE_SSH_G);
    let (_dir, config, mut session) = start(&fake, &home);
    let before = fs::read(config.join(HOSTS_FILE)).unwrap();
    open_ssh_config(&mut session);

    session.send(b"i");
    session.wait_until("the preview", |s| {
        let text = said(s);
        text.contains("2 hosts to import, 1 already in Bifrost, 2 skipped.")
            && text
                .contains("Press y to import these 2 hosts, or n to cancel. Nothing is saved yet.")
            && text.contains("y import")
    });
    let text = said(&session.screen());
    for expected in [
        "Will be imported (2)",
        "app: deploy@app.example.com:2222",
        "jumpy: me@jumpy.example.com",
        "Already in Bifrost, left as they are (1)",
        "Skipped, and why (2)",
        "café: Name may only contain",
        "broken: ssh -G failed: ssh: Could not resolve hostname broken",
        "Warnings (2)",
        "Warning: Host 'jumpy': its ProxyCommand was dropped because Bifrost does not support",
        "Warning: Host 'app': the identity file",
    ] {
        assert!(
            text.contains(expected),
            "{expected}:\n{}",
            session.screen().text()
        );
    }
    // The end of the identity file's path, which is one long word and is cut
    // wherever the line ends.
    assert!(
        session.screen().contains_wrapped("id_app' does not exist."),
        "{}",
        session.screen().text()
    );
    // Looking saved nothing, and ssh was asked about each new host and no other.
    assert_eq!(fs::read(config.join(HOSTS_FILE)).unwrap(), before);
    assert_eq!(saved_hosts(&config), ["db", "web"]);

    // A no leaves everything as it was.
    session.send(b"n");
    session.wait_until("the two choices again", |s| {
        s.contains("i import") && !s.contains("Will be imported")
    });
    assert_eq!(fs::read(config.join(HOSTS_FILE)).unwrap(), before);
    quit(session);
}

#[test]
fn y_saves_exactly_the_hosts_shown_and_the_list_has_them() {
    let home = Home::new(Some(SSH_CONFIG));
    let fake = FakeSsh::new(FAKE_SSH_G);
    let (_dir, config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"i");
    session.wait_until("the preview", |s| {
        s.contains("Press y to import these 2 hosts")
    });

    // Only y confirms. Enter and other letters do nothing.
    session.send(b"\rjk");
    session.send(b"y");
    session.wait_until("the summary", |s| {
        let text = said(s);
        text.contains("2 hosts imported, 1 already in Bifrost, 2 skipped.")
            && text.contains("Saved. Press Enter to go back.")
            && text.contains("Imported (2)")
    });

    let saved = Store::at(&config).load().unwrap();
    assert_eq!(saved_hosts(&config), ["app", "db", "jumpy", "web"]);
    let app = saved.hosts.get("app").unwrap();
    assert_eq!(app.hostname, "app.example.com");
    assert_eq!(app.user.as_deref(), Some("deploy"));
    assert_eq!(app.port, Some(2222));
    assert!(
        app.identity_file
            .as_deref()
            .is_some_and(|f| f.ends_with("id_app"))
    );
    // ssh's default identity files are not imported, and nothing of the dropped
    // ProxyCommand is kept.
    let file = fs::read_to_string(config.join(HOSTS_FILE)).unwrap();
    assert!(!file.contains("id_ed25519"), "{file}");
    assert!(!file.contains("nc "), "{file}");
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

    // Back to the list, where the hosts are.
    session.send(b"\r");
    session.wait_until("the menu", |s| {
        s.contains("i import") && s.contains("e export")
    });
    session.send(b"\x1b");
    session.wait_until("the list with the new hosts", |s| {
        s.contains("Saved hosts: 4") && s.contains("app") && s.contains("jumpy")
    });
    // Nothing of the ssh config itself changed.
    assert_eq!(home.read("config").unwrap(), SSH_CONFIG);
    quit(session);
}

#[test]
fn a_missing_ssh_config_is_said_plainly_and_nothing_can_be_imported() {
    let home = Home::new(None);
    let fake = FakeSsh::new(FAKE_SSH_G);
    let (_dir, config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"i");
    session.wait_until("the explanation", |s| {
        let text = said(s);
        text.contains("There is no ssh config at")
            // Starts inside the path, which is cut wherever the line ends.
            && s.contains_wrapped(".ssh/config, so there is nothing to import.")
    });
    assert!(!session.screen().contains("Press y"));
    session.send(b"y");
    assert_eq!(saved_hosts(&config), ["db", "web"]);
    quit(session);
}

#[test]
fn without_ssh_the_import_says_what_to_install_and_the_screen_still_works() {
    let home = Home::new(Some(SSH_CONFIG));
    // No ssh in the PATH at all.
    let fake = FakeSsh::absent();
    let (dir, config) = healthy_store();
    let mut session = Session::start(
        &config,
        30,
        100,
        &[
            ("PATH", &fake.path_env_without_tools()),
            ("HOME", home.path()),
        ],
    );
    open_ssh_config(&mut session);
    session.send(b"i");
    session.wait_until("the explanation", |s| {
        said(s).contains("Error: Could not find the 'ssh' program")
    });
    assert!(
        session.screen().contains("i import"),
        "still on the two choices"
    );
    drop(dir);
    quit(session);
}

#[test]
fn what_ssh_says_about_a_host_never_reaches_the_terminal_as_it_was_written() {
    let home = Home::new(Some("Host evil\n  HostName e.example.com\n"));
    let fake = FakeSsh::new(
        r#"printf 'ssh: \033]0;pwned\007 \342\200\256bad \033[31mred\n' >&2
exit 255"#,
    );
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"i");
    session.wait_until("the skipped host", |s| {
        s.contains("Skipped, and why (1)") && s.contains("evil: ssh -G failed")
    });
    session.send(b"q");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
    assert!(!contains_bytes(&output, b"\x1b]0;pwned"), "a title was set");
    assert!(!contains_bytes(&output, "\u{202e}".as_bytes()));
    assert!(!contains_bytes(&output, b"\x1b[31mred"));
}

#[test]
fn a_host_whose_ssh_hangs_is_skipped_after_the_timeout_and_the_rest_is_imported() {
    // The fake starts a command for `hangs` and waits for it, as a Match exec
    // that never finishes would. The default deadline is 5 seconds.
    let home = Home::new(Some(
        "Host web\n  HostName 192.0.2.1\n\
         Host hangs\n  HostName hangs.example.com\n\
         Host app\n  HostName app.example.com\n",
    ));
    let fake = FakeSsh::new(
        r#"if [ "$1" = "-G" ]; then
  case "$3" in
    hangs)
      sleep 60 &
      echo $! > "$HOME/hang-pid"
      wait
      ;;
    *)
      printf 'hostname %s.example.com\nuser me\nport 22\n' "$3"
      ;;
  esac
  exit 0
fi
exit 0"#,
    );
    let (_dir, config, mut session) = start(&fake, &home);
    let before = fs::read(config.join(HOSTS_FILE)).unwrap();
    open_ssh_config(&mut session);

    session.send(b"i");
    // Nothing is drawn while ssh is being waited for, and then the preview comes.
    session.wait_until("the preview, after the timeout", |s| {
        let text = said(s);
        text.contains("1 host to import, 1 already in Bifrost, 1 skipped.")
            && text
                .contains("hangs: ssh did not answer within 5 seconds, so this host was skipped.")
            && text.contains("Press y to import this host")
    });
    let text = said(&session.screen());
    assert!(
        text.contains("Will be imported (1)") && text.contains("app: me@app.example.com"),
        "{text}"
    );
    assert!(text.contains("Skipped, and why (1)"), "{text}");
    assert!(text.contains("Match"), "the usual cause is named: {text}");
    assert_eq!(
        fs::read(config.join(HOSTS_FILE)).unwrap(),
        before,
        "looking saved nothing"
    );

    // What the hanging command started did not outlive the timeout.
    let pid =
        fs::read_to_string(home.dir.path().join("hang-pid")).expect("the fake started its command");
    let pid = pid.trim().to_string();
    let gone = (0..100).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(20));
        !std::process::Command::new("kill")
            .args(["-0", &pid])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    });
    assert!(
        gone,
        "the command started for the hanging host (pid {pid}) is still running"
    );

    // And the screen is alive: the host that could be read imports.
    session.send(b"y");
    session.wait_until("the summary", |s| {
        said(s).contains("1 host imported, 1 already in Bifrost, 1 skipped.")
            && said(s).contains("Saved. Press Enter to go back.")
    });
    assert_eq!(saved_hosts(&config), ["app", "db", "web"]);
    quit(session);
}

// ---- export ----------------------------------------------------------------------------------

#[test]
fn e_asks_first_and_then_writes_the_file_private_and_never_touches_the_ssh_config() {
    let config_text = "# mine\nHost home\n  User me\n";
    let home = Home::new(Some(config_text));
    let fake = FakeSsh::new("exit 0");
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);

    session.send(b"e");
    session.wait_until("the plan", |s| {
        let text = said(s);
        // The path is one long word, cut wherever the line ends.
        text.contains("Write 2 hosts to")
            && s.contains_wrapped(".ssh/bifrost_config.")
            && text.contains("The file does not exist yet, so it will be created.")
            && text.contains("Press y to write it, or n to cancel.")
    });
    assert!(
        home.read("bifrost_config").is_none(),
        "asking writes nothing"
    );

    // Enter and n write nothing.
    session.send(b"\r");
    session.send(b"n");
    session.wait_until("the choices", |s| {
        s.contains("i import") && !s.contains("Press y")
    });
    assert!(home.read("bifrost_config").is_none());

    session.send(b"e");
    session.wait_until("the plan again", |s| s.contains("Press y to write it"));
    session.send(b"y");
    // Everything asserted is waited for, the line on a line of its own
    // included: the frame arrives in pieces, and until the last of it is here
    // the tail of the previous page is still beside this one.
    session.wait_until("the include line, alone on its line", |s| {
        let text = said(s);
        text.contains("Wrote 2 hosts to")
            && text.contains("add this line at the very top of")
            && text.contains("named config, not in bifrost_config")
            && s.lines().iter().any(|line| {
                line.trim_matches(|c: char| c == '│' || c.is_whitespace()) == INCLUDE_LINE
            })
    });

    let exported = home.read("bifrost_config").unwrap();
    assert!(exported.starts_with(GENERATED_HEADER), "{exported}");
    assert!(
        exported.contains("Host web") && exported.contains("Host db"),
        "{exported}"
    );
    assert_eq!(
        fs::metadata(home.file("bifrost_config"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        home.read("config").unwrap(),
        config_text,
        "the user's ssh config is exactly as it was: no Include added"
    );
    quit(session);
}

#[test]
fn an_ssh_config_that_already_includes_the_file_is_not_asked_to_add_it() {
    let home = Home::new(Some(&format!("{INCLUDE_LINE}\nHost home\n  User me\n")));
    let fake = FakeSsh::new("exit 0");
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"e");
    session.wait_until("the plan", |s| s.contains("Press y to write it"));
    session.send(b"y");
    session.wait_until("the result", |s| {
        said(s).contains("already includes it, so ssh uses these hosts. Nothing more to do.")
    });
    assert!(!said(&session.screen()).contains("add this line"));
    quit(session);
}

#[test]
fn an_include_after_a_host_line_is_a_warning() {
    let home = Home::new(Some(&format!("Host home\n  User me\n{INCLUDE_LINE}\n")));
    let fake = FakeSsh::new("exit 0");
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"e");
    session.wait_until("the plan", |s| s.contains("Press y to write it"));
    session.send(b"y");
    session.wait_until("the warning", |s| {
        said(s).contains("but after a Host or Match line")
            && said(s).contains("Move this line to the very top")
    });
    quit(session);
}

#[test]
fn a_config_whose_includes_loop_is_a_warning_and_not_a_clean_bill_of_health() {
    // A file of the user's own that includes itself: ssh refuses to start with
    // "Too many recursive configuration includes", however right the rest of
    // the config is. The include of bifrost_config is found, which on its own
    // used to be reported as "nothing more to do".
    //
    // (The same line inside bifrost_config heals itself: the export rewrites
    // that file before this check runs.)
    let home = Home::new(Some(&format!(
        "{INCLUDE_LINE}\nInclude extra.conf\nHost home\n  User me\n"
    )));
    fs::write(home.file("extra.conf"), "Include extra.conf\nHost extra\n").unwrap();
    let fake = FakeSsh::new("exit 0");
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"e");
    session.wait_until("the plan", |s| s.contains("Press y to write it"));
    session.send(b"y");
    session.wait_until("the loop warning", |s| {
        said(s).contains("includes itself")
            && said(s).contains("Too many recursive configuration includes")
    });
    quit(session);
}

#[test]
fn with_no_ssh_config_it_says_to_create_one_and_creates_nothing_itself() {
    let home = Home::new(None);
    let fake = FakeSsh::new("exit 0");
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"e");
    session.wait_until("the plan", |s| s.contains("Press y to write it"));
    session.send(b"y");
    session.wait_until("the advice", |s| {
        said(s).contains("You have no ssh config yet.") && said(s).contains(INCLUDE_LINE)
    });
    assert!(
        home.read("config").is_none(),
        "Bifrost created no ssh config"
    );
    quit(session);
}

#[test]
fn a_file_bifrost_did_not_make_is_never_replaced_and_y_does_nothing() {
    let home = Home::new(Some("Host home\n"));
    fs::write(home.file("bifrost_config"), "Host precious\n  User me\n").unwrap();
    let fake = FakeSsh::new("exit 0");
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"e");
    session.wait_until("the stop", |s| {
        said(s).contains("Stop: That file exists and Bifrost did not make it")
    });
    assert!(!said(&session.screen()).contains("Press y to write it"));
    session.send(b"y");
    session.send(b"\r");
    // Still the same screen, and the file untouched.
    session.send(b"\x1b");
    session.wait_until("the choices", |s| {
        s.contains("i import") && !s.contains("Stop:")
    });
    assert_eq!(
        home.read("bifrost_config").unwrap(),
        "Host precious\n  User me\n"
    );
    quit(session);
}

#[test]
fn a_file_bifrost_made_is_replaced_and_the_plan_says_so() {
    let home = Home::new(Some(&format!("{INCLUDE_LINE}\n")));
    fs::write(
        home.file("bifrost_config"),
        format!("{GENERATED_HEADER}\nHost stale\n  HostName old.example.com\n"),
    )
    .unwrap();
    let fake = FakeSsh::new("exit 0");
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"e");
    session.wait_until("the plan", |s| {
        said(s).contains("The file was made by Bifrost, so it will be replaced.")
    });
    session.send(b"y");
    session.wait_until("the result", |s| said(s).contains("Wrote 2 hosts to"));
    let exported = home.read("bifrost_config").unwrap();
    assert!(
        !exported.contains("stale") && exported.contains("Host web"),
        "{exported}"
    );
    quit(session);
}

#[test]
fn the_screen_scrolls_helps_and_leaves_cleanly() {
    let home = Home::new(Some(SSH_CONFIG));
    let fake = FakeSsh::new(FAKE_SSH_G);
    let (_dir, _config, mut session) = start(&fake, &home);
    open_ssh_config(&mut session);
    session.send(b"?");
    session.wait_until("the help", |s| s.contains("These keys work in Bifrost:"));
    session.send(b"\x1b");
    session.wait_until("the choices again", |s| {
        s.contains("i import") && s.contains("SSH config")
    });
    session.send(b"\x1b");
    session.wait_until("the list", |s| {
        s.contains(HOME_SCREEN) && !s.contains("SSH config")
    });
    // Ctrl-C from the screen quits and restores the terminal.
    session.send(b"s");
    session.wait_until("the screen", |s| s.contains("i import"));
    session.send(support::CTRL_C);
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}");
    assert_restored(&output);
}
