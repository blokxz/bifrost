//! What the ssh agent is doing, from `ssh-add -l`.
//!
//! The agent not running is an ordinary state, not an error: a terminal without
//! an agent is common, and the keys screen explains what it means. So the answer
//! is a value, [`AgentState`], and only a program that cannot be started at all
//! is reported as unavailable.
//!
//! What `ssh-add -l` prints (OpenSSH 9.6):
//!
//! | situation                    | exit | output                                              |
//! |------------------------------|------|-----------------------------------------------------|
//! | agent with keys              | 0    | one line per key, as `ssh-keygen -l` prints it      |
//! | agent with no keys           | 1    | `The agent has no identities.`                      |
//! | no agent variable            | 2    | `Could not open a connection to your authentication agent.` |
//! | variable set, agent is gone  | 2    | `Error connecting to agent: No such file or directory` |
//!
//! Only lines that are exactly what ssh-add says are believed, and a line with a
//! control or bidirectional character never is: what the agent's keys are named
//! is chosen by whoever added them. Keys are recognized by their fingerprints,
//! never by their comments.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::keys::parse_fingerprint;
use crate::sanitize::is_unsafe_char;

/// How long to wait for `ssh-add -l`. An agent that is forwarded over a dead
/// connection can leave it waiting for good, and the interface must not.
pub const AGENT_TIMEOUT: Duration = Duration::from_secs(3);

/// How much of ssh-add's output is read. Far more than any agent holds.
const MAX_OUTPUT: u64 = 256 * 1024;

/// How often to look at whether ssh-add has finished.
const POLL: Duration = Duration::from_millis(10);

/// Whether there is an agent, and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// An agent answered. `hashes` are the fingerprints (`SHA256:...`) of the
    /// keys it holds, none if it holds none.
    Running { hashes: Vec<String> },
    /// This session has no agent: `SSH_AUTH_SOCK` is not set.
    NotStarted,
    /// `SSH_AUTH_SOCK` is set but nothing answers there: the agent has ended, or
    /// the socket is left over.
    Unreachable,
    /// `ssh-add` could not be run or did not answer in time. Holds why, in
    /// plain English.
    Unavailable(String),
    /// `ssh-add` said something that is not one of the above. Holds its first
    /// line, raw: it must be sanitized before it is shown.
    Unknown(String),
}

impl AgentState {
    /// The fingerprints of the loaded keys, when an agent answered.
    pub fn hashes(&self) -> Option<&[String]> {
        match self {
            AgentState::Running { hashes } => Some(hashes),
            _ => None,
        }
    }
}

/// Reads what `ssh-add -l` printed. `exit` is its exit status when it had one.
pub fn interpret(exit: Option<i32>, stdout: &str, stderr: &str) -> AgentState {
    // Lines that are ssh-add's own words: not the ones with control characters.
    let words: Vec<&str> = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.chars().any(is_unsafe_char))
        .collect();

    if words
        .iter()
        .any(|line| line.starts_with("Could not open a connection to your authentication agent"))
    {
        return AgentState::NotStarted;
    }
    if words
        .iter()
        .any(|line| line.starts_with("Error connecting to agent"))
    {
        return AgentState::Unreachable;
    }
    if words.contains(&"The agent has no identities.") {
        return AgentState::Running { hashes: Vec::new() };
    }
    if exit == Some(0) {
        let hashes: Vec<String> = stdout
            .lines()
            .filter_map(parse_fingerprint)
            .map(|key| key.hash)
            .collect();
        if !hashes.is_empty() {
            return AgentState::Running { hashes };
        }
    }
    let first = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string);
    AgentState::Unknown(first.unwrap_or_else(|| match exit {
        Some(code) => format!("ssh-add exited with status {code} and printed nothing"),
        None => "ssh-add ended without printing anything".to_string(),
    }))
}

/// Asks the agent what it holds, by running `ssh-add -l`.
///
/// It has no terminal and no input, so it can never prompt. If it has not
/// finished within `timeout` it is killed and the answer is
/// [`AgentState::Unavailable`].
pub fn list(ssh_add: &Path, timeout: Duration) -> AgentState {
    let mut child = match Command::new(ssh_add)
        .arg("-l")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => return AgentState::Unavailable(format!("Could not run ssh-add: {err}")),
    };

    let (sender, receiver) = mpsc::channel::<(bool, Vec<u8>)>();
    if let Some(pipe) = child.stdout.take() {
        read_in_background(pipe, true, sender.clone());
    }
    if let Some(pipe) = child.stderr.take() {
        read_in_background(pipe, false, sender);
    } else {
        drop(sender);
    }

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return AgentState::Unavailable(format!(
                    "ssh-add did not answer within {} seconds, so Bifrost cannot tell what the \
                     agent holds.",
                    timeout.as_secs()
                ));
            }
            Err(err) => {
                let _ = child.kill();
                return AgentState::Unavailable(format!("Could not wait for ssh-add: {err}"));
            }
        }
    };

    // The pipes close with the process; a moment is enough to collect them.
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    while let Ok((is_stdout, bytes)) = receiver.recv_timeout(Duration::from_millis(300)) {
        if is_stdout {
            stdout = bytes;
        } else {
            stderr = bytes;
        }
    }
    interpret(
        status.code(),
        &String::from_utf8_lossy(&stdout),
        &String::from_utf8_lossy(&stderr),
    )
}

fn read_in_background(
    pipe: impl Read + Send + 'static,
    is_stdout: bool,
    sender: mpsc::Sender<(bool, Vec<u8>)>,
) {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.take(MAX_OUTPUT).read_to_end(&mut bytes);
        let _ = sender.send((is_stdout, bytes));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "SHA256:Gch6wPWbVBGcUR0XuYOLVqoZ+L5m7d4yzsUg0dxJVTw";
    const B: &str = "SHA256:Crv2UD7RjSr55ym7z5Nso5T9YwtVbduZ6xUVvnj9VtE";

    // What OpenSSH 9.6 printed.
    fn key_line(bits: u32, hash: &str, comment: &str, kind: &str) -> String {
        format!("{bits} {hash} {comment} ({kind})\n")
    }

    #[test]
    fn an_agent_with_keys_is_running_and_its_fingerprints_are_read() {
        let out = key_line(256, A, "dev laptop (work) <me@x>", "ED25519")
            + &key_line(2048, B, "no comment", "RSA");
        assert_eq!(
            interpret(Some(0), &out, ""),
            AgentState::Running {
                hashes: vec![A.to_string(), B.to_string()]
            }
        );
    }

    #[test]
    fn an_agent_with_no_keys_is_running_and_empty() {
        assert_eq!(
            interpret(Some(1), "The agent has no identities.\n", ""),
            AgentState::Running { hashes: vec![] }
        );
    }

    #[test]
    fn no_agent_in_this_session_is_a_normal_state() {
        assert_eq!(
            interpret(
                Some(2),
                "",
                "Could not open a connection to your authentication agent.\n"
            ),
            AgentState::NotStarted
        );
    }

    #[test]
    fn an_agent_that_is_gone_is_told_apart_from_one_never_started() {
        assert_eq!(
            interpret(
                Some(2),
                "",
                "Error connecting to agent: No such file or directory\n"
            ),
            AgentState::Unreachable
        );
        assert_eq!(
            interpret(
                Some(2),
                "",
                "Error connecting to agent: Connection refused\r\n"
            ),
            AgentState::Unreachable
        );
    }

    #[test]
    fn anything_else_is_unknown_and_keeps_the_first_line() {
        assert_eq!(
            interpret(Some(2), "", "something new happened\nand more\n"),
            AgentState::Unknown("something new happened".to_string())
        );
        assert_eq!(
            interpret(Some(3), "", ""),
            AgentState::Unknown("ssh-add exited with status 3 and printed nothing".to_string())
        );
        assert_eq!(
            interpret(None, "", ""),
            AgentState::Unknown("ssh-add ended without printing anything".to_string())
        );
        // Exit 0 but nothing that is a key.
        assert_eq!(
            interpret(Some(0), "hello\n", ""),
            AgentState::Unknown("hello".to_string())
        );
    }

    #[test]
    fn a_line_with_control_or_bidi_characters_is_never_taken_for_ssh_add_s_words() {
        for line in [
            "The agent has no identities.\x1b[0m",
            "\u{202e}The agent has no identities.",
            "Could not open a connection to your authentication agent.\x07",
            "Error connecting to agent: \u{2066}x",
        ] {
            let state = interpret(Some(2), "", &format!("{line}\n"));
            assert!(
                matches!(state, AgentState::Unknown(_)),
                "{line:?}: {state:?}"
            );
        }
    }

    #[test]
    fn hostile_key_comments_do_not_change_what_is_loaded() {
        // The comment is whatever the person who added the key chose.
        let out = key_line(256, A, "evil\x1b]0;pwned\x07 \u{202e}text", "ED25519");
        assert_eq!(
            interpret(Some(0), &out, ""),
            AgentState::Running {
                hashes: vec![A.to_string()]
            }
        );
        // A comment cannot pass for a fingerprint or for a message.
        let sneaky = key_line(
            256,
            A,
            "The agent has no identities. SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ED25519",
        );
        assert_eq!(
            interpret(Some(0), &sneaky, "").hashes(),
            Some(&[A.to_string()][..])
        );
    }

    #[test]
    fn lines_that_are_not_keys_are_skipped_among_keys() {
        let out = format!(
            "garbage\n{}another garbage\n",
            key_line(256, A, "c", "ED25519")
        );
        assert_eq!(
            interpret(Some(0), &out, ""),
            AgentState::Running {
                hashes: vec![A.to_string()]
            }
        );
    }

    #[test]
    fn hashes_are_only_there_when_an_agent_answered() {
        assert_eq!(AgentState::NotStarted.hashes(), None);
        assert_eq!(AgentState::Unreachable.hashes(), None);
        assert_eq!(AgentState::Unknown("x".to_string()).hashes(), None);
        assert_eq!(
            AgentState::Running { hashes: vec![] }.hashes(),
            Some(&[][..])
        );
    }

    #[test]
    fn a_program_that_cannot_be_started_is_unavailable_not_a_panic() {
        let state = list(Path::new("/nonexistent/ssh-add"), AGENT_TIMEOUT);
        let AgentState::Unavailable(why) = state else {
            panic!("{state:?}");
        };
        assert!(why.starts_with("Could not run ssh-add:"), "{why}");
    }
}
