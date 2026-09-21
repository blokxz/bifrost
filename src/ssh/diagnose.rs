//! Explaining how a connection ended.
//!
//! [`classify`] turns what [`connect::run`](super::connect::run) reported (an
//! exit status and the end of ssh's stderr) into a [`Verdict`], and
//! [`FailureKind`] carries the plain-English explanation and the suggested next
//! steps for each failure Bifrost recognizes.
//!
//! ssh's stderr is not trustworthy text. A server can print a banner before
//! login, and that banner arrives on the same stream as ssh's own messages. So:
//!
//! - **Only exit status 255 is an ssh failure.** Any other status is what the
//!   remote session or command returned (a shell whose last command failed
//!   exits 1) and is never explained as a connection problem.
//! - **The decision rests on the last meaningful line.** ssh says why it gave up
//!   last, after anything a server printed. The one exception is the epilogue
//!   that ssh adds when a jump host fails, which is skipped.
//! - **A line with control or bidirectional characters is never taken for
//!   ssh's own.** ssh's messages have none; a hostile banner might. Such a line
//!   is not matched, so the result is "unrecognized" and the raw output is
//!   there to read.
//! - **Nothing from ssh's output is put into an explanation.** The text is
//!   chosen from fixed messages and names only the saved host. Output can
//!   change which message is shown, never what it says.
//!
//! The wording that is matched was captured from OpenSSH 9.6 where a failure
//! could be produced without a server (refused, unresolvable, timed out,
//! handshake failures, jump host failures). The login and host key messages
//! follow OpenSSH's documented text; they are the ones to confirm against a real
//! server (see the ignored tests).

use std::path::Path;

use super::command::KnownHostsTarget;
use super::connect::{Exit, Outcome};
use crate::pathtext::{Rules, same_path};
use crate::sanitize::{PLACEHOLDER, is_unsafe_char};

/// How a connection ended, as far as the user needs to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// ssh exited with status 0: the session ended normally.
    Ended,
    /// The remote session or command exited with this status. Not a connection
    /// problem.
    RemoteStatus(i32),
    /// The user pressed Ctrl-C.
    Cancelled,
    /// The user closed the connection (`~.`).
    ClosedByYou,
    /// ssh was ended by this signal.
    Signalled(i32),
    /// ssh could not connect, or the connection failed. Needs an explanation.
    Failed(FailureKind),
}

/// Why a connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The server refused the login.
    PermissionDenied,
    /// The server's key is not the one saved for it, and ssh said so.
    HostKeyChanged,
    /// ssh could not verify the server's identity for another reason, for
    /// example the user declined to trust a new server.
    HostKeyRejected,
    ConnectionRefused,
    TimedOut,
    CouldNotResolve,
    NetworkUnreachable,
    /// The server ended a session that was running.
    ClosedByServer,
    /// The connection broke: while connecting, or in the middle of a session.
    ConnectionLost,
    /// ssh failed with a message Bifrost does not know.
    Unrecognized,
}

impl FailureKind {
    /// A short title for the error screen.
    pub fn title(self) -> &'static str {
        match self {
            FailureKind::PermissionDenied => "The server refused the login",
            FailureKind::HostKeyChanged => "The server's identity changed",
            FailureKind::HostKeyRejected => "The server's identity was not accepted",
            FailureKind::ConnectionRefused => "Connection refused",
            FailureKind::TimedOut => "The server did not answer",
            FailureKind::CouldNotResolve => "The host name was not found",
            FailureKind::NetworkUnreachable => "The network is unreachable",
            FailureKind::ClosedByServer => "The server closed the connection",
            FailureKind::ConnectionLost => "The connection was interrupted",
            FailureKind::Unrecognized => "The connection failed",
        }
    }

    /// What happened, in plain English. `name` is the saved host's name; it is
    /// the only thing that is not fixed text.
    pub fn explanation(self, name: &str) -> String {
        match self {
            FailureKind::PermissionDenied => format!(
                "'{name}' answered, but it did not accept the way you tried to log in \
                 (permission denied)."
            ),
            FailureKind::HostKeyChanged => format!(
                "The key that '{name}' presented is not the one saved the first time you \
                 connected. This happens when a server is reinstalled or its keys are \
                 replaced. It can also mean someone is intercepting the connection."
            ),
            FailureKind::HostKeyRejected => format!(
                "ssh could not confirm that '{name}' is the server it says it is, so it \
                 stopped before logging in."
            ),
            FailureKind::ConnectionRefused => format!(
                "'{name}' was reached, but nothing is accepting SSH connections at that \
                 address and port."
            ),
            FailureKind::TimedOut => {
                format!("'{name}' did not answer in time.")
            }
            FailureKind::CouldNotResolve => {
                format!("The host name of '{name}' could not be turned into an address.")
            }
            FailureKind::NetworkUnreachable => {
                format!("There is no route from this computer to '{name}'.")
            }
            FailureKind::ClosedByServer => {
                format!("'{name}' ended the session. This is normal after an idle timeout.")
            }
            FailureKind::ConnectionLost => {
                format!("The connection to '{name}' broke.")
            }
            FailureKind::Unrecognized => format!(
                "ssh could not connect to '{name}', and Bifrost does not recognize the \
                 reason."
            ),
        }
    }

    /// What to try next, most likely first.
    pub fn next_steps(self) -> &'static [&'static str] {
        match self {
            FailureKind::PermissionDenied => &[
                "Check the user name saved for this host (press e on the list to edit it).",
                "If you log in with a key, check the key file saved for the host, and that \
                 the matching public key is installed on the server.",
                "If you use a password, connect again and retype it.",
            ],
            FailureKind::HostKeyChanged => &[
                "Do not continue unless you know why the key changed.",
                "Ask the server's administrator to confirm its fingerprint.",
            ],
            FailureKind::HostKeyRejected => &[
                "If ssh asked whether to trust a new server and you answered no, connect \
                 again and answer yes only if you recognize the fingerprint.",
                "If ssh warned that the host identification changed, read its output (press \
                 o) before doing anything else.",
            ],
            FailureKind::ConnectionRefused => &[
                "Check the port saved for this host. SSH servers usually listen on 22.",
                "Check that the SSH server is running on the machine.",
                "A firewall may be blocking the port.",
            ],
            FailureKind::TimedOut => &[
                "Check that the machine is on and that you are on the right network or VPN.",
                "Check the host name or address and the port saved for this host.",
                "A firewall may be dropping the connection instead of refusing it.",
            ],
            FailureKind::CouldNotResolve => &[
                "Check the spelling of the host name (press e on the list to edit it).",
                "Check your internet connection and DNS, or try the IP address instead.",
            ],
            FailureKind::NetworkUnreachable => &[
                "Check your network connection, and your VPN if the server needs one.",
                "Check the address saved for this host.",
            ],
            FailureKind::ClosedByServer => &["Connect again if you were not finished."],
            FailureKind::ConnectionLost => &[
                "Check your network connection.",
                "Connect again. If it keeps happening, the server may be limiting \
                 connections or restarting.",
            ],
            FailureKind::Unrecognized => &[
                "Read ssh's own output (press o) for the reason.",
                "Try the same connection with `ssh -v` in a shell for more detail.",
            ],
        }
    }
}

/// Decides how a connection ended.
pub fn classify(outcome: &Outcome) -> Verdict {
    if outcome.was_interrupted() {
        return Verdict::Cancelled;
    }
    match outcome.exit {
        Exit::Code(0) => Verdict::Ended,
        Exit::Code(255) => classify_ssh_failure(&outcome.stderr),
        Exit::Code(status) => Verdict::RemoteStatus(status),
        Exit::Signal(signal) => Verdict::Signalled(signal),
    }
}

/// One line of ssh's output, with whether it can be trusted as ssh's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The text with every unsafe character replaced, and trimmed.
    pub text: String,
    /// The line had control or bidirectional characters. ssh's own messages
    /// never do.
    pub hostile: bool,
}

/// The non-empty lines of ssh's output, safe to show.
///
/// `\r` counts as a line break as well as `\n`: ssh ends its log lines with
/// `\r\n`, and a lone `\r` in text from a server would otherwise let it
/// overwrite what came before it when shown.
pub fn lines(stderr: &[u8]) -> Vec<Line> {
    String::from_utf8_lossy(stderr)
        .split(['\n', '\r'])
        .filter_map(|raw| {
            let hostile = raw.chars().any(is_unsafe_char);
            let text: String = raw
                .chars()
                .map(|c| if is_unsafe_char(c) { PLACEHOLDER } else { c })
                .collect();
            let text = text.trim().to_string();
            (!text.is_empty()).then_some(Line { text, hostile })
        })
        .collect()
}

/// Every line of ssh's output exactly as written, blank lines included, for
/// showing the output in full.
///
/// **Not safe to show**: the lines can hold control characters. They are
/// separate from [`lines`] so that the screen can clean each one itself and
/// tell the user when something was hidden.
pub fn raw_lines(stderr: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(stderr).replace("\r\n", "\n");
    let mut lines: Vec<String> = text.split(['\n', '\r']).map(str::to_string).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

/// What ssh prints last when a jump host fails: its own line about the
/// connection through the jump host closing. The reason is the line before it.
fn is_jump_epilogue(line: &str) -> bool {
    line == "Connection closed by UNKNOWN port 65535" || line == "stdio forwarding failed"
}

fn classify_ssh_failure(stderr: &[u8]) -> Verdict {
    let lines = lines(stderr);
    let Some(anchor) = lines.iter().rposition(|line| !is_jump_epilogue(&line.text)) else {
        return Verdict::Failed(FailureKind::Unrecognized);
    };
    let line = &lines[anchor];
    if line.hostile {
        return Verdict::Failed(FailureKind::Unrecognized);
    }
    let text = line.text.as_str();

    if text == "Host key verification failed." {
        let changed = lines[..anchor].iter().any(|earlier| {
            !earlier.hostile
                && earlier
                    .text
                    .contains("REMOTE HOST IDENTIFICATION HAS CHANGED!")
        });
        return Verdict::Failed(if changed {
            FailureKind::HostKeyChanged
        } else {
            FailureKind::HostKeyRejected
        });
    }
    if text.starts_with("Connection to ") && text.ends_with(" closed.") {
        return Verdict::ClosedByYou;
    }
    Verdict::Failed(kind_of(text))
}

/// Matches the message ssh ended with. Most specific first.
fn kind_of(text: &str) -> FailureKind {
    let has = |needles: &[&str]| needles.iter().any(|needle| text.contains(needle));
    if has(&["Permission denied", "Too many authentication failures"]) {
        FailureKind::PermissionDenied
    } else if has(&["Connection refused"]) {
        FailureKind::ConnectionRefused
    } else if has(&["timed out"]) {
        FailureKind::TimedOut
    } else if has(&[
        "Could not resolve hostname",
        "Name or service not known",
        "Temporary failure in name resolution",
        "nodename nor servname provided",
    ]) {
        FailureKind::CouldNotResolve
    } else if has(&["Network is unreachable", "No route to host"]) {
        FailureKind::NetworkUnreachable
    } else if text.starts_with("Connection to ") && text.ends_with("closed by remote host.") {
        FailureKind::ClosedByServer
    } else if has(&[
        "Broken pipe",
        "Connection reset by",
        "Connection closed by",
        "not responding",
    ]) {
        FailureKind::ConnectionLost
    } else {
        FailureKind::Unrecognized
    }
}

/// What ssh said about a changed host key, read from its output.
///
/// Every field is optional and checked: a missing or odd one is `None`, never a
/// guess. None of it is trusted until [`HostKeyChange::removal_target`] has
/// matched it against what Bifrost itself asked ssh to connect to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostKeyChange {
    /// The kind of key the server sent, such as `ED25519`.
    pub key_type: Option<String>,
    /// The fingerprint of the key the server sent: `SHA256:` and 43 characters.
    pub fingerprint: Option<String>,
    /// The host ssh says the saved key belongs to, as it named it.
    pub host: Option<String>,
    /// The `known_hosts` file that holds the old key, as ssh printed it.
    pub file: Option<String>,
    /// The line of that file.
    pub line: Option<u32>,
}

/// Whether `text` is a SHA-256 fingerprint as ssh prints it.
pub(crate) fn is_sha256_fingerprint(text: &str) -> bool {
    text.strip_prefix("SHA256:").is_some_and(|hash| {
        hash.len() == 43
            && hash
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/'))
    })
}

/// A key type as ssh names it: `ED25519`, `ECDSA`, `RSA`, `ED25519-SK`.
pub(crate) fn is_key_type(text: &str) -> bool {
    (2..=24).contains(&text.len())
        && text
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
}

/// Reads the details of a changed host key out of ssh's output.
///
/// Only lines without control or bidirectional characters are read, and where a
/// detail appears more than once the one closest to the end wins, as with the
/// classification.
pub fn host_key_change(stderr: &[u8]) -> HostKeyChange {
    let lines = lines(stderr);
    let mut change = HostKeyChange::default();
    for (index, line) in lines.iter().enumerate().filter(|(_, l)| !l.hostile) {
        let text = line.text.as_str();

        if let Some(rest) = text.strip_prefix("The fingerprint for the ")
            && let Some(kind) = rest.strip_suffix(" key sent by the remote host is")
            && is_key_type(kind)
        {
            change.key_type = Some(kind.to_string());
            change.fingerprint = None;
            if let Some(next) = lines.get(index + 1).filter(|next| !next.hostile) {
                let hash = next.text.trim_end_matches('.');
                if is_sha256_fingerprint(hash) {
                    change.fingerprint = Some(hash.to_string());
                }
            }
        } else if let Some(before) =
            text.strip_suffix(" has changed and you have requested strict checking.")
            && let Some((_, host)) = before.rsplit_once("ost key for ")
            && !host.is_empty()
            && !host.contains(' ')
        {
            change.host = Some(host.to_string());
        } else if let Some(rest) = text.strip_prefix("Offending ")
            && let Some((kind, place)) = rest.split_once(" key in ")
            && is_key_type(kind)
            && let Some((file, number)) = place.rsplit_once(':')
            && let Ok(number) = number.parse::<u32>()
            && !file.is_empty()
        {
            change.file = Some(file.to_string());
            change.line = Some(number);
        }
    }
    change
}

impl HostKeyChange {
    /// The saved host whose old key may be removed, if what ssh said can be
    /// tied to hosts Bifrost asked ssh to connect through.
    ///
    /// Both must hold: the host ssh named is one of `known` (the connection's
    /// host and its jump hosts), and the old key is in `default_file`, the
    /// `known_hosts` that `ssh-keygen -R` edits without being told which file.
    /// Anything else, including anything missing, is `None`: text that a server
    /// could have printed must never choose what gets removed, or from where.
    ///
    /// The file is the same one only by [`same_path`]: the same words up to the
    /// way the system writes a path, and never when either has a `..` in it, which
    /// the words cannot resolve (`a/../b` is not `b` when `a` is a link).
    pub fn removal_target<'a>(
        &self,
        known: &'a [KnownHostsTarget],
        default_file: Option<&Path>,
    ) -> Option<&'a KnownHostsTarget> {
        let default_file = default_file.map(Path::to_string_lossy);
        self.removal_target_by(known, default_file.as_deref(), Rules::native())
    }

    /// [`Self::removal_target`] with the rules for writing a path given, so that the
    /// rules of Windows and of the others are both tested on every system.
    fn removal_target_by<'a>(
        &self,
        known: &'a [KnownHostsTarget],
        default_file: Option<&str>,
        rules: Rules,
    ) -> Option<&'a KnownHostsTarget> {
        let host = self.host.as_deref()?;
        let file = self.file.as_deref()?;
        if !same_path(file, default_file?, rules) {
            return None;
        }
        known
            .iter()
            .find(|target| target.entry.eq_ignore_ascii_case(host))
    }
}

/// The last `count` non-blank lines of ssh's output, for showing next to an
/// explanation of a failure Bifrost does not recognize.
///
/// **Not safe to show**, like [`raw_lines`]: the screen cleans each line.
pub fn excerpt(stderr: &[u8], count: usize) -> Vec<String> {
    let mut all: Vec<String> = raw_lines(stderr)
        .into_iter()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let skip = all.len().saturating_sub(count);
    all.drain(..skip);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(exit: Exit, stderr: &str) -> Outcome {
        Outcome {
            exit,
            stderr: stderr.as_bytes().to_vec(),
            interrupted: false,
        }
    }

    fn ssh_failure(stderr: &str) -> Verdict {
        classify(&outcome(Exit::Code(255), stderr))
    }

    fn failed(kind: FailureKind) -> Verdict {
        Verdict::Failed(kind)
    }

    // ---- what ssh really printed (OpenSSH 9.6) ---------------------------

    #[test]
    fn connection_refused() {
        assert_eq!(
            ssh_failure("ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n"),
            failed(FailureKind::ConnectionRefused)
        );
    }

    #[test]
    fn could_not_resolve() {
        assert_eq!(
            ssh_failure(
                "ssh: Could not resolve hostname nonexistent.invalid: Name or service not known\r\n"
            ),
            failed(FailureKind::CouldNotResolve)
        );
    }

    #[test]
    fn timed_out() {
        assert_eq!(
            ssh_failure("ssh: connect to host 203.0.113.9 port 22: Connection timed out\r\n"),
            failed(FailureKind::TimedOut)
        );
    }

    #[test]
    fn a_server_that_never_sends_its_banner_is_a_timeout() {
        assert_eq!(
            ssh_failure(
                "Connection timed out during banner exchange\r\n\
                 Connection to 127.0.0.1 port 2299 timed out\r\n"
            ),
            failed(FailureKind::TimedOut)
        );
    }

    #[test]
    fn a_server_that_closes_or_resets_during_the_handshake_is_a_lost_connection() {
        for stderr in [
            "Connection closed by 127.0.0.1 port 2299\r\n",
            "Connection reset by 127.0.0.1 port 2299\r\n",
            "kex_exchange_identification: read: Connection reset by peer\r\n\
             Connection reset by 127.0.0.1 port 2299\r\n",
        ] {
            assert_eq!(
                ssh_failure(stderr),
                failed(FailureKind::ConnectionLost),
                "{stderr:?}"
            );
        }
    }

    // ---- through a jump host (real output) -------------------------------

    #[test]
    fn a_jump_host_failure_is_explained_by_its_own_line_not_by_the_epilogue() {
        // Without skipping ssh's closing line, all of these would read as a
        // connection that was merely closed.
        assert_eq!(
            ssh_failure(
                "ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n\
                 Connection closed by UNKNOWN port 65535\r\n"
            ),
            failed(FailureKind::ConnectionRefused)
        );
        assert_eq!(
            ssh_failure(
                "ssh: Could not resolve hostname nonexistent.invalid: Name or service not known\r\n\
                 Connection closed by UNKNOWN port 65535\r\n"
            ),
            failed(FailureKind::CouldNotResolve)
        );
    }

    #[test]
    fn a_target_refusing_the_jump_host_s_forward_is_a_refusal() {
        assert_eq!(
            ssh_failure(
                "channel 0: open failed: connect failed: Connection refused\r\n\
                 stdio forwarding failed\r\n\
                 Connection closed by UNKNOWN port 65535\r\n"
            ),
            failed(FailureKind::ConnectionRefused)
        );
    }

    #[test]
    fn only_the_epilogue_is_unrecognized() {
        assert_eq!(
            ssh_failure("Connection closed by UNKNOWN port 65535\r\n"),
            failed(FailureKind::Unrecognized)
        );
    }

    // ---- login and host keys (OpenSSH's documented wording) --------------

    #[test]
    fn permission_denied_in_its_usual_forms() {
        for stderr in [
            "deploy@192.0.2.1: Permission denied (publickey).\r\n",
            "deploy@192.0.2.1: Permission denied (publickey,password).\r\n",
            "deploy@192.0.2.1: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).\r\n",
            "Received disconnect from 192.0.2.1 port 22:2: Too many authentication failures\r\n\
             Disconnected from 192.0.2.1 port 22\r\n\
             Too many authentication failures\r\n",
        ] {
            assert_eq!(
                ssh_failure(stderr),
                failed(FailureKind::PermissionDenied),
                "{stderr:?}"
            );
        }
    }

    const CHANGED: &str = "\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n\
Someone could be eavesdropping on you right now (man-in-the-middle attack)!\r\n\
It is also possible that a host key has just been changed.\r\n\
The fingerprint for the ED25519 key sent by the remote host is\r\n\
SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA.\r\n\
Please contact your system administrator.\r\n\
Add correct host key in /home/dev/.ssh/known_hosts to get rid of this message.\r\n\
Offending ED25519 key in /home/dev/.ssh/known_hosts:12\r\n\
Host key for 192.0.2.1 has changed and you have requested strict checking.\r\n\
Host key verification failed.\r\n";

    #[test]
    fn a_changed_host_key_is_recognized_by_ssh_s_warning_and_its_last_line() {
        assert_eq!(ssh_failure(CHANGED), failed(FailureKind::HostKeyChanged));
    }

    #[test]
    fn a_changed_key_of_a_jump_host_is_still_a_changed_key() {
        let through_jump = format!("{CHANGED}Connection closed by UNKNOWN port 65535\r\n");
        assert_eq!(
            ssh_failure(&through_jump),
            failed(FailureKind::HostKeyChanged)
        );
    }

    #[test]
    fn declining_a_new_host_is_a_rejection_not_a_changed_key() {
        assert_eq!(
            ssh_failure("Host key verification failed.\r\n"),
            failed(FailureKind::HostKeyRejected)
        );
        assert_eq!(
            ssh_failure(
                "No ED25519 host key is known for 192.0.2.1 and you have requested strict \
                 checking.\r\nHost key verification failed.\r\n"
            ),
            failed(FailureKind::HostKeyRejected)
        );
    }

    #[test]
    fn a_changed_key_warning_that_was_not_followed_by_the_failure_is_not_a_changed_key() {
        // ssh's own last line decides. A warning earlier in the output, with a
        // different ending, must not turn an unrelated failure into this one.
        let stderr = format!(
            "{}ssh: connect to host 192.0.2.1 port 22: Connection refused\r\n",
            CHANGED.trim_end_matches("Host key verification failed.\r\n")
        );
        assert_eq!(ssh_failure(&stderr), failed(FailureKind::ConnectionRefused));
    }

    // ---- sessions that ended ---------------------------------------------

    #[test]
    fn closing_with_tilde_dot_is_not_an_error() {
        assert_eq!(
            ssh_failure("Connection to 192.0.2.1 closed.\r\n"),
            Verdict::ClosedByYou
        );
    }

    #[test]
    fn a_server_that_ends_a_session_is_told_apart_from_a_broken_connection() {
        assert_eq!(
            ssh_failure("Connection to 192.0.2.1 closed by remote host.\r\n"),
            failed(FailureKind::ClosedByServer)
        );
        for stderr in [
            "client_loop: send disconnect: Broken pipe\r\n",
            "Timeout, server 192.0.2.1 not responding.\r\n",
            "kex_exchange_identification: Connection closed by remote host\r\n",
        ] {
            assert_eq!(
                ssh_failure(stderr),
                failed(FailureKind::ConnectionLost),
                "{stderr:?}"
            );
        }
    }

    #[test]
    fn no_route_and_no_network_are_the_same_advice() {
        for stderr in [
            "ssh: connect to host 192.0.2.1 port 22: Network is unreachable\r\n",
            "ssh: connect to host 192.0.2.1 port 22: No route to host\r\n",
        ] {
            assert_eq!(
                ssh_failure(stderr),
                failed(FailureKind::NetworkUnreachable),
                "{stderr:?}"
            );
        }
    }

    #[test]
    fn other_resolver_wording_is_recognized() {
        for stderr in [
            "ssh: Could not resolve hostname x: Temporary failure in name resolution\r\n",
            "ssh: Could not resolve hostname x: nodename nor servname provided, or not known\r\n",
        ] {
            assert_eq!(
                ssh_failure(stderr),
                failed(FailureKind::CouldNotResolve),
                "{stderr:?}"
            );
        }
        // macOS says "Operation timed out".
        assert_eq!(
            ssh_failure("ssh: connect to host 192.0.2.1 port 22: Operation timed out\r\n"),
            failed(FailureKind::TimedOut)
        );
    }

    // ---- what is not an ssh failure ---------------------------------------

    #[test]
    fn only_status_255_is_an_ssh_failure() {
        let refused = "ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n";
        assert_eq!(classify(&outcome(Exit::Code(0), "")), Verdict::Ended);
        // Whatever is on stderr, a remote status is the remote's own.
        for code in [1, 2, 127, 130, 254] {
            assert_eq!(
                classify(&outcome(Exit::Code(code), refused)),
                Verdict::RemoteStatus(code)
            );
        }
        assert_eq!(classify(&outcome(Exit::Code(0), refused)), Verdict::Ended);
    }

    #[test]
    fn ctrl_c_is_a_cancellation_whatever_ssh_printed() {
        let mut cancelled = outcome(
            Exit::Code(255),
            "deploy@192.0.2.1: Permission denied (publickey).\r\n",
        );
        cancelled.interrupted = true;
        assert_eq!(classify(&cancelled), Verdict::Cancelled);
        assert_eq!(classify(&outcome(Exit::Signal(2), "")), Verdict::Cancelled);
    }

    #[test]
    fn a_signal_other_than_interrupt_is_reported_as_such() {
        assert_eq!(
            classify(&outcome(Exit::Signal(9), "")),
            Verdict::Signalled(9)
        );
    }

    #[test]
    fn a_failure_with_no_output_or_an_unknown_message_is_unrecognized() {
        assert_eq!(ssh_failure(""), failed(FailureKind::Unrecognized));
        assert_eq!(ssh_failure("\r\n  \r\n"), failed(FailureKind::Unrecognized));
        assert_eq!(
            ssh_failure("something entirely new\r\n"),
            failed(FailureKind::Unrecognized)
        );
    }

    // ---- hostile output --------------------------------------------------

    #[test]
    fn a_banner_printed_before_the_failure_cannot_change_it() {
        // A server can print any text before login; ssh's own message comes last.
        let stderr = "Welcome. Permission denied (publickey).\r\n\
                      REMOTE HOST IDENTIFICATION HAS CHANGED!\r\n\
                      ssh: connect to host 192.0.2.1 port 22: Connection refused\r\n";
        assert_eq!(ssh_failure(stderr), failed(FailureKind::ConnectionRefused));
    }

    #[test]
    fn a_banner_that_is_the_last_line_with_control_characters_is_not_believed() {
        for line in [
            "Permission denied\x1b[0m (publickey).",
            "\x1b]0;Permission denied\x07",
            "Permission denied (publickey).\x00",
            "\u{202e}Permission denied (publickey).",
            "Permission\u{2066} denied (publickey).",
            "Permission denied\u{85}(publickey).",
        ] {
            assert_eq!(
                ssh_failure(&format!("{line}\r\n")),
                failed(FailureKind::Unrecognized),
                "{line:?}"
            );
        }
    }

    #[test]
    fn a_carriage_return_cannot_hide_a_line_from_the_classifier() {
        // On a terminal this would show only "Connection refused"; here it is
        // two lines, and the last one decides.
        assert_eq!(
            ssh_failure("Permission denied (publickey).\rConnection refused"),
            failed(FailureKind::ConnectionRefused)
        );
        assert_eq!(
            ssh_failure("Connection refused\rPermission denied (publickey)."),
            failed(FailureKind::PermissionDenied)
        );
    }

    #[test]
    fn a_forged_host_key_warning_needs_ssh_s_own_last_line_to_count() {
        // Hostile warning line: not trusted even with the right last line.
        let stderr = "\u{202e}REMOTE HOST IDENTIFICATION HAS CHANGED!\r\n\
                      Host key verification failed.\r\n";
        assert_eq!(ssh_failure(stderr), failed(FailureKind::HostKeyRejected));
        // A clean forged warning is indistinguishable from the real one, which
        // is why the removal step (Block 5, step 3) checks the host as well.
        let forged = "REMOTE HOST IDENTIFICATION HAS CHANGED!\r\nHost key verification failed.\r\n";
        assert_eq!(ssh_failure(forged), failed(FailureKind::HostKeyChanged));
    }

    #[test]
    fn invalid_utf8_and_a_cut_first_line_do_not_break_classification() {
        let mut stderr = b"\xff\xfe\xfd garbage\r\n".to_vec();
        stderr.extend_from_slice(b"ssh: connect to host 192.0.2.1 port 22: Connection refused\r\n");
        assert_eq!(
            classify(&Outcome {
                exit: Exit::Code(255),
                stderr,
                interrupted: false
            }),
            failed(FailureKind::ConnectionRefused)
        );
        // The retained tail can start in the middle of a line.
        assert_eq!(
            ssh_failure("lf that was cut\r\nHost key verification failed.\r\n"),
            failed(FailureKind::HostKeyRejected)
        );
    }

    #[test]
    fn a_huge_line_of_noise_is_handled() {
        let noise = "x".repeat(200_000);
        assert_eq!(
            ssh_failure(&format!("{noise}\r\n")),
            failed(FailureKind::Unrecognized)
        );
    }

    #[test]
    fn explanations_hold_only_fixed_text_and_the_saved_name() {
        let kinds = [
            FailureKind::PermissionDenied,
            FailureKind::HostKeyChanged,
            FailureKind::HostKeyRejected,
            FailureKind::ConnectionRefused,
            FailureKind::TimedOut,
            FailureKind::CouldNotResolve,
            FailureKind::NetworkUnreachable,
            FailureKind::ClosedByServer,
            FailureKind::ConnectionLost,
            FailureKind::Unrecognized,
        ];
        for kind in kinds {
            // The text depends on the kind and the name and nothing else, so no
            // output from ssh can reach it.
            let plain = kind.explanation("web");
            assert_eq!(plain.replace("'web'", "'db'"), kind.explanation("db"));
            assert!(!plain.is_empty() && !kind.title().is_empty());
            assert!(!kind.next_steps().is_empty(), "{kind:?} needs a next step");
            for text in std::iter::once(plain.as_str())
                .chain(std::iter::once(kind.title()))
                .chain(kind.next_steps().iter().copied())
            {
                assert!(!text.chars().any(is_unsafe_char), "{text:?}");
            }
        }
    }

    // ---- the excerpt -----------------------------------------------------

    #[test]
    fn the_excerpt_is_the_last_non_blank_lines_as_written() {
        let stderr = b"one\r\n\r\ntwo\r\nthree \x1b[31mred\x1b[0m\r\nfour\r\n";
        assert_eq!(
            excerpt(stderr, 3),
            ["two", "three \x1b[31mred\x1b[0m", "four"]
        );
        assert_eq!(excerpt(stderr, 100).len(), 4);
        assert!(excerpt(b"", 5).is_empty());
    }

    #[test]
    fn raw_lines_keep_blank_lines_and_the_text_as_written() {
        assert_eq!(raw_lines(b"a\r\n\r\nb\rc\nd\r\n"), ["a", "", "b", "c", "d"]);
        assert_eq!(raw_lines(b"\x1b[31mred"), ["\x1b[31mred"]);
        assert!(raw_lines(b"").is_empty());
        assert_eq!(raw_lines(b"\xff"), ["\u{fffd}"]);
    }

    #[test]
    fn lines_split_on_both_kinds_of_line_break_and_drop_blanks() {
        let all: Vec<_> = lines(b"a\r\n\r\nb\rc\nd")
            .into_iter()
            .map(|l| l.text)
            .collect();
        assert_eq!(all, ["a", "b", "c", "d"]);
    }

    #[test]
    fn lines_mark_the_ones_with_unsafe_characters() {
        let all = lines("ok\r\nbad \u{202e}text\r\n".as_bytes());
        assert!(!all[0].hostile);
        assert!(all[1].hostile);
        assert_eq!(all[1].text, "bad ?text");
    }

    // ---- the details of a changed host key ---------------------------------

    fn change(stderr: &str) -> HostKeyChange {
        host_key_change(stderr.as_bytes())
    }

    #[test]
    fn the_details_are_read_from_ssh_s_warning() {
        let read = change(CHANGED);
        assert_eq!(read.key_type.as_deref(), Some("ED25519"));
        assert_eq!(
            read.fingerprint.as_deref(),
            Some("SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(read.host.as_deref(), Some("192.0.2.1"));
        assert_eq!(read.file.as_deref(), Some("/home/dev/.ssh/known_hosts"));
        assert_eq!(read.line, Some(12));
    }

    #[test]
    fn older_wording_and_a_port_are_read_too() {
        let read = change(
            "The fingerprint for the ECDSA key sent by the remote host is\r\n\
             SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA.\r\n\
             Offending ECDSA key in /home/dev/.ssh/known_hosts:3\r\n\
             ECDSA host key for [192.0.2.1]:2222 has changed and you have requested strict checking.\r\n",
        );
        assert_eq!(read.key_type.as_deref(), Some("ECDSA"));
        assert_eq!(read.host.as_deref(), Some("[192.0.2.1]:2222"));
        assert_eq!(read.line, Some(3));
    }

    #[test]
    fn a_path_with_spaces_and_colons_keeps_its_line_number() {
        let read = change("Offending RSA key in C:/Users/Ana Diaz/.ssh/known_hosts:7\r\n");
        assert_eq!(
            read.file.as_deref(),
            Some("C:/Users/Ana Diaz/.ssh/known_hosts")
        );
        assert_eq!(read.line, Some(7));
    }

    #[test]
    fn odd_or_missing_details_are_none_and_never_guessed() {
        assert_eq!(change(""), HostKeyChange::default());
        assert_eq!(
            change("Host key verification failed.\r\n"),
            HostKeyChange::default()
        );
        for fingerprint in [
            "SHA256:tooshort",
            "MD5:aa:bb:cc",
            "SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAA!",
            "sha256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let read = change(&format!(
                "The fingerprint for the ED25519 key sent by the remote host is\r\n{fingerprint}.\r\n"
            ));
            assert_eq!(read.fingerprint, None, "{fingerprint}");
            assert_eq!(read.key_type.as_deref(), Some("ED25519"));
        }
        // A key type that is not one, a host with spaces, a line that is no number.
        assert_eq!(
            change("The fingerprint for the ed25519; rm key sent by the remote host is\r\n")
                .key_type,
            None
        );
        assert_eq!(
            change("Host key for a b has changed and you have requested strict checking.\r\n").host,
            None
        );
        assert_eq!(
            change("Offending ED25519 key in /x/known_hosts:twelve\r\n").file,
            None
        );
    }

    #[test]
    fn lines_with_control_or_bidi_characters_are_not_read() {
        let read = change(
            "The fingerprint for the ED25519 key sent by the remote host is\r\n\
             SHA256:pZ90vMeWq3ZkYc4TsAAAAAAAAAAAAAAAAAAAAAAAAAA.\x1b[0m\r\n\
             Offending ED25519 key in /home/dev/.ssh/known_hosts:12\x07\r\n\
             \u{202e}Host key for 192.0.2.1 has changed and you have requested strict checking.\r\n",
        );
        assert_eq!(read.fingerprint, None);
        assert_eq!(read.file, None);
        assert_eq!(read.host, None);
        assert_eq!(read.key_type.as_deref(), Some("ED25519"));
    }

    #[test]
    fn the_latest_mention_wins() {
        let read = change(
            "Host key for a.example has changed and you have requested strict checking.\r\n\
             Host key for b.example has changed and you have requested strict checking.\r\n",
        );
        assert_eq!(read.host.as_deref(), Some("b.example"));
    }

    // ---- tying it to the connection ----------------------------------------

    fn target(entry: &str, name: &str) -> KnownHostsTarget {
        KnownHostsTarget {
            entry: entry.to_string(),
            saved_name: name.to_string(),
        }
    }

    fn known() -> Vec<KnownHostsTarget> {
        vec![
            target("192.0.2.1", "web"),
            target("[10.0.0.5]:2200", "bastion"),
        ]
    }

    const DEFAULT_FILE: &str = "/home/dev/.ssh/known_hosts";

    fn removal(read: &HostKeyChange, file: Option<&str>) -> Option<String> {
        let known = known();
        read.removal_target(&known, file.map(Path::new))
            .map(|t| t.saved_name.clone())
    }

    #[test]
    fn the_target_is_the_saved_host_ssh_named_when_the_file_is_the_default() {
        assert_eq!(
            removal(&change(CHANGED), Some(DEFAULT_FILE)).as_deref(),
            Some("web")
        );
    }

    #[test]
    fn a_jump_host_s_changed_key_targets_the_jump_host() {
        let read = HostKeyChange {
            host: Some("[10.0.0.5]:2200".to_string()),
            file: Some(DEFAULT_FILE.to_string()),
            ..HostKeyChange::default()
        };
        assert_eq!(
            removal(&read, Some(DEFAULT_FILE)).as_deref(),
            Some("bastion")
        );
    }

    #[test]
    fn the_host_is_compared_ignoring_case() {
        let read = HostKeyChange {
            host: Some("192.0.2.1".to_uppercase()),
            file: Some(DEFAULT_FILE.to_string()),
            ..HostKeyChange::default()
        };
        assert!(removal(&read, Some(DEFAULT_FILE)).is_some());
        let named = HostKeyChange {
            host: Some("WEB.EXAMPLE".to_string()),
            ..read
        };
        let known = vec![target("web.example", "web")];
        assert!(
            named
                .removal_target(&known, Some(Path::new(DEFAULT_FILE)))
                .is_some()
        );
    }

    #[test]
    fn a_host_bifrost_did_not_connect_through_is_never_a_target() {
        // What a server could print: a different host's name.
        for host in [
            "other.example",
            "192.0.2.2",
            "192.0.2.1:22",
            "[192.0.2.1]:22",
            "*",
            "",
        ] {
            let read = HostKeyChange {
                host: Some(host.to_string()),
                file: Some(DEFAULT_FILE.to_string()),
                ..HostKeyChange::default()
            };
            assert_eq!(removal(&read, Some(DEFAULT_FILE)), None, "{host:?}");
        }
    }

    #[test]
    fn a_key_in_any_other_file_is_never_removed_by_bifrost() {
        for file in [
            "/home/dev/.ssh/authorized_keys",
            "/etc/ssh/ssh_known_hosts",
            "/home/dev/.ssh/known_hosts2",
            "/home/other/.ssh/known_hosts",
            "known_hosts",
        ] {
            let read = HostKeyChange {
                host: Some("192.0.2.1".to_string()),
                file: Some(file.to_string()),
                ..HostKeyChange::default()
            };
            assert_eq!(removal(&read, Some(DEFAULT_FILE)), None, "{file}");
        }
    }

    #[test]
    fn nothing_is_removed_when_anything_is_unknown() {
        let both = HostKeyChange {
            host: Some("192.0.2.1".to_string()),
            file: Some(DEFAULT_FILE.to_string()),
            ..HostKeyChange::default()
        };
        assert!(removal(&both, Some(DEFAULT_FILE)).is_some());
        assert_eq!(removal(&both, None), None, "the default file is not known");
        let no_host = HostKeyChange {
            host: None,
            ..both.clone()
        };
        assert_eq!(removal(&no_host, Some(DEFAULT_FILE)), None);
        let no_file = HostKeyChange { file: None, ..both };
        assert_eq!(removal(&no_file, Some(DEFAULT_FILE)), None);
    }

    // ---- which file: both ways of writing a path, on every system --------------

    /// The target for `printed` (as ssh printed the file) when the default file is
    /// `default`, by the given rules. `None` when it is not one to remove from.
    fn removal_by(printed: &str, default: &str, rules: Rules) -> Option<String> {
        let read = HostKeyChange {
            host: Some("192.0.2.1".to_string()),
            file: Some(printed.to_string()),
            ..HostKeyChange::default()
        };
        let known = known();
        read.removal_target_by(&known, Some(default), rules)
            .map(|t| t.saved_name.clone())
    }

    const WINDOWS_DEFAULT: &str = r"C:\Users\Dev\.ssh\known_hosts";

    #[test]
    fn under_the_rules_of_windows_the_slashes_the_case_and_the_prefix_do_not_matter() {
        for printed in [
            WINDOWS_DEFAULT,
            "C:/Users/Dev/.ssh/known_hosts",
            r"C:\Users/Dev\.ssh/known_hosts",
            r"c:\users\dev\.ssh\known_hosts",
            r"C:\USERS\DEV\.SSH\KNOWN_HOSTS",
            r"C:\Users\Dev\.ssh\\known_hosts",
            r"C:\Users\Dev\.\.ssh\known_hosts",
            r"\\?\C:\Users\Dev\.ssh\known_hosts",
        ] {
            assert_eq!(
                removal_by(printed, WINDOWS_DEFAULT, Rules::Windows).as_deref(),
                Some("web"),
                "{printed}"
            );
        }
        // The default file may as well come written the other way.
        assert!(
            removal_by(
                WINDOWS_DEFAULT,
                "c:/users/dev/.ssh/known_hosts",
                Rules::Windows
            )
            .is_some()
        );
    }

    #[test]
    fn under_the_rules_of_windows_another_file_is_still_another_file() {
        for printed in [
            r"D:\Users\Dev\.ssh\known_hosts",
            r"C:\Users\Other\.ssh\known_hosts",
            r"C:\Users\Dev\.ssh\known_hosts2",
            r"C:\Users\Dev\.ssh\authorized_keys",
            r"C:\Users\Dev\known_hosts",
            r"C:\Users\Dev\.ssh",
            // Not the same start: the root of the current drive, the folder of a
            // drive, a relative path, a network path.
            r"\Users\Dev\.ssh\known_hosts",
            r"C:Users\Dev\.ssh\known_hosts",
            r"Users\Dev\.ssh\known_hosts",
            r"\\Users\Dev\.ssh\known_hosts",
            "known_hosts",
            "~/.ssh/known_hosts",
            " ",
        ] {
            assert_eq!(
                removal_by(printed, WINDOWS_DEFAULT, Rules::Windows),
                None,
                "{printed:?}"
            );
        }
    }

    #[test]
    fn under_the_rules_of_the_others_case_and_backslashes_count() {
        let default = "/home/dev/.ssh/known_hosts";
        for printed in [
            default,
            "/home/dev//.ssh/known_hosts",
            "/home/dev/./.ssh/known_hosts",
            "//home/dev/.ssh/known_hosts",
        ] {
            assert_eq!(
                removal_by(printed, default, Rules::Unix).as_deref(),
                Some("web"),
                "{printed}"
            );
        }
        for printed in [
            "/home/dev/.ssh/Known_Hosts",
            "/Home/dev/.ssh/known_hosts",
            r"/home/dev/.ssh\known_hosts",
            r"\home\dev\.ssh\known_hosts",
            "home/dev/.ssh/known_hosts",
            "known_hosts",
            "~/.ssh/known_hosts",
            "/home/dev/.ssh/known_hosts2",
            "",
        ] {
            assert_eq!(
                removal_by(printed, default, Rules::Unix),
                None,
                "{printed:?}"
            );
        }
        // The same words are two files under the other rules and one under these.
        assert!(removal_by("/home/dev/.ssh/Known_Hosts", default, Rules::Windows).is_some());
        assert!(removal_by(r"/home/dev/.ssh\known_hosts", default, Rules::Windows).is_some());
    }

    #[test]
    fn a_path_with_dot_dot_is_never_the_file_even_when_it_leads_there() {
        // These all reach the default file if no name on the way is a link, and
        // the words cannot say. What is removed is chosen by the answer here.
        let unix_default = "/home/dev/.ssh/known_hosts";
        for printed in [
            "/home/dev/.ssh/../.ssh/known_hosts",
            "/home/dev/x/../.ssh/known_hosts",
            "/home/dev/.ssh/known_hosts/../known_hosts",
            "/../home/dev/.ssh/known_hosts",
            "/home/dev/.ssh/known_hosts/..",
        ] {
            assert_eq!(
                removal_by(printed, unix_default, Rules::Unix),
                None,
                "{printed}"
            );
        }
        for printed in [
            r"C:\Users\Dev\.ssh\..\.ssh\known_hosts",
            r"C:\Users\Dev\x\..\.ssh\known_hosts",
            r"C:\..\Users\Dev\.ssh\known_hosts",
            "C:/Users/Dev/.ssh/../.ssh/known_hosts",
        ] {
            assert_eq!(
                removal_by(printed, WINDOWS_DEFAULT, Rules::Windows),
                None,
                "{printed}"
            );
        }
        // Nor when the default file is the one written with it: a wrong yes on
        // either side picks the wrong file, and identical words do not change that.
        for (printed, default) in [
            ("/a/../known_hosts", "/a/../known_hosts"),
            ("/known_hosts", "/a/../known_hosts"),
            ("/a/../known_hosts", "/known_hosts"),
        ] {
            for rules in [Rules::Unix, Rules::Windows] {
                assert_eq!(
                    removal_by(printed, default, rules),
                    None,
                    "{printed} {default}"
                );
            }
        }
        // A name that only has dots in it is a name.
        assert!(
            removal_by(
                "/home/dev/..ssh/known_hosts",
                "/home/dev/..ssh/known_hosts",
                Rules::Unix
            )
            .is_some()
        );
        assert!(
            removal_by(
                "/home/dev/.ssh/known_hosts.",
                "/home/dev/.ssh/known_hosts.",
                Rules::Unix
            )
            .is_some()
        );
    }

    #[test]
    fn the_public_entry_uses_the_rules_of_the_system_that_is_running() {
        // Case is the difference: the same file under Windows, another one elsewhere.
        let read = HostKeyChange {
            host: Some("192.0.2.1".to_string()),
            file: Some("/home/dev/.ssh/Known_Hosts".to_string()),
            ..HostKeyChange::default()
        };
        let known = known();
        let target = read.removal_target(&known, Some(Path::new(DEFAULT_FILE)));
        assert_eq!(target.is_some(), cfg!(windows));
    }

    #[test]
    fn the_host_is_still_needed_whatever_the_rules_say_of_the_file() {
        // The file is the default one under both, and the host is not a known one.
        let read = HostKeyChange {
            host: Some("other.example".to_string()),
            file: Some(WINDOWS_DEFAULT.to_string()),
            ..HostKeyChange::default()
        };
        let known = known();
        for rules in [Rules::Unix, Rules::Windows] {
            assert!(
                read.removal_target_by(&known, Some(WINDOWS_DEFAULT), rules)
                    .is_none()
            );
            assert!(read.removal_target_by(&known, None, rules).is_none());
        }
    }
}
