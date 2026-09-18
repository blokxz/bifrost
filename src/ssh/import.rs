//! Import hosts from the user's ssh config.
//!
//! The config is not parsed here. [`scan`](super::scan) only finds the host
//! names; each one is then resolved with `ssh -G <name>`, so OpenSSH itself
//! decides what the configuration means (patterns, `Match`, defaults).
//!
//! Rules:
//! - Existing Bifrost hosts are never overwritten; name clashes are reported
//!   as conflicts.
//! - Every imported value goes through the normal validators. A host with an
//!   invalid field is skipped whole, with the reason.
//! - `ProxyCommand` is dropped with a warning (Bifrost only supports
//!   `ProxyJump`). Forwards that Bifrost cannot represent (non-localhost bind,
//!   Unix sockets, dynamic forwards) are dropped with a warning.
//! - ssh's built-in default identity files are ignored; only explicit ones are
//!   imported, and only the first if several are configured. An identity file
//!   that ends in `.pub` is dropped with a warning (the host is still
//!   imported); it is only rejected for hosts entered by hand.
//! - The user that ssh reports is always stored explicitly, even when it is
//!   just the local login name. Port 22 is stored as unset.
//! - A `ProxyJump` is kept only when it names another host that is in the
//!   Bifrost store after the import (one hop; multi-hop lists are dropped).
//!
//! Note that `ssh -G` evaluates `Match exec` commands, so this must only be
//! pointed at the user's own configuration.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::scan::scan_host_names;
use crate::domain::validate;
use crate::domain::{Forward, Host, Hosts, Warning};
use crate::sysenv::{self, Env, Platform};
use crate::text::escape_control;

/// ssh's default identity files, which `ssh -G` prints even when the config
/// does not mention them.
const DEFAULT_IDENTITY_FILES: [&str; 7] = [
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_xmss",
    "id_dsa",
];

/// Why resolving one host with ssh failed.
#[derive(Debug)]
pub enum ResolveError {
    /// ssh could not be run at all; the whole import stops.
    Unavailable(String),
    /// ssh rejected this one host; it is skipped.
    Failed(String),
}

/// Something that can run `ssh -G <name>` and return its output.
pub trait SshResolver {
    fn resolve(&self, name: &str) -> Result<String, ResolveError>;
}

/// Runs the real `ssh -G`. The binary must be an absolute path (see
/// [`super::binary`]); it is spawned directly, never through a shell, and the
/// host name is passed after `--`.
#[derive(Debug, Clone)]
pub struct SystemSshResolver {
    ssh: PathBuf,
    config_file: Option<PathBuf>,
}

impl SystemSshResolver {
    pub fn new(ssh: PathBuf) -> Self {
        SystemSshResolver {
            ssh,
            config_file: None,
        }
    }

    /// Use an explicit config file (`ssh -F`) instead of ssh's default lookup.
    pub fn with_config_file(mut self, config_file: PathBuf) -> Self {
        self.config_file = Some(config_file);
        self
    }
}

impl SshResolver for SystemSshResolver {
    fn resolve(&self, name: &str) -> Result<String, ResolveError> {
        if !self.ssh.is_absolute() {
            return Err(ResolveError::Unavailable(format!(
                "the ssh path '{}' is not absolute",
                self.ssh.display()
            )));
        }
        let mut command = Command::new(&self.ssh);
        command.arg("-G");
        if let Some(config) = &self.config_file {
            command.arg("-F").arg(config);
        }
        command
            .arg("--")
            .arg(name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = command.output().map_err(|err| {
            ResolveError::Unavailable(format!("could not run {}: {err}", self.ssh.display()))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first_line = stderr.lines().next().unwrap_or("").trim();
            return Err(ResolveError::Failed(format!(
                "ssh -G failed: {}",
                escape_control(first_line)
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| ResolveError::Failed("ssh -G printed text that is not UTF-8".into()))
    }
}

/// Where to read the ssh config from.
#[derive(Debug, Clone)]
pub struct ImportSource {
    /// The config file to scan.
    pub config: PathBuf,
    /// The directory relative `Include`s resolve against (`~/.ssh`).
    pub ssh_dir: PathBuf,
    pub home: Option<PathBuf>,
}

impl ImportSource {
    /// The user's own config: `~/.ssh/config`, or `%USERPROFILE%\.ssh\config`
    /// on Windows.
    pub fn for_user(platform: Platform, env: Env<'_>) -> Result<Self, ImportError> {
        let home = sysenv::home_dir(platform, env).ok_or(ImportError::NoHome)?;
        let ssh_dir = home.join(".ssh");
        Ok(ImportSource {
            config: ssh_dir.join("config"),
            ssh_dir,
            home: Some(home),
        })
    }
}

/// A host that was found but not imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedHost {
    /// The name, with control characters escaped.
    pub name: String,
    pub reason: String,
}

/// The outcome of an import. Nothing has been saved: the caller decides
/// whether to store `hosts`.
#[derive(Debug)]
pub struct ImportReport {
    /// The existing hosts plus the imported ones.
    pub hosts: Hosts,
    /// Names of the hosts that were added.
    pub imported: Vec<String>,
    /// Names that already exist in Bifrost and were left untouched.
    pub conflicts: Vec<String>,
    pub skipped: Vec<SkippedHost>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug)]
pub enum ImportError {
    NoHome,
    ReadConfig {
        path: PathBuf,
        source: io::Error,
    },
    /// ssh could not be run.
    Ssh(String),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::NoHome => f.write_str(
                "Could not find your home directory, so the ssh config cannot be located.",
            ),
            ImportError::ReadConfig { path, source } => {
                write!(
                    f,
                    "Could not read the ssh config {}: {source}",
                    path.display()
                )
            }
            ImportError::Ssh(message) => write!(f, "Could not run ssh: {message}"),
        }
    }
}

impl std::error::Error for ImportError {}

/// Imports the hosts of `source` that are not yet in `existing`.
pub fn import_hosts(
    existing: &Hosts,
    source: &ImportSource,
    resolver: &dyn SshResolver,
) -> Result<ImportReport, ImportError> {
    let scan = scan_host_names(&source.config, &source.ssh_dir, source.home.as_deref()).map_err(
        |err| ImportError::ReadConfig {
            path: source.config.clone(),
            source: err,
        },
    )?;

    let mut report = ImportReport {
        hosts: existing.clone(),
        imported: Vec::new(),
        conflicts: Vec::new(),
        skipped: Vec::new(),
        warnings: scan.warnings,
    };

    let mut candidates: Vec<Candidate> = Vec::new();
    for name in scan.names {
        if let Err(err) = validate::validate_name(&name) {
            report.skip(&name, err.to_string());
            continue;
        }
        if existing.get(&name).is_some() {
            report.conflicts.push(name);
            continue;
        }
        let output = match resolver.resolve(&name) {
            Ok(output) => output,
            Err(ResolveError::Unavailable(message)) => return Err(ImportError::Ssh(message)),
            Err(ResolveError::Failed(message)) => {
                report.skip(&name, message);
                continue;
            }
        };
        match build_candidate(&name, parse_resolved(&output), source, &mut report.warnings) {
            Ok(candidate) => candidates.push(candidate),
            Err(reason) => report.skip(&name, reason),
        }
    }

    // First add every host without its jump host, so that jump hosts can be
    // matched regardless of the order they appear in the config.
    let mut jumps: Vec<(String, String)> = Vec::new();
    for candidate in candidates {
        let name = candidate.host.name.clone();
        let missing_key = validate::identity_file_warning(&candidate.host, source.home.as_deref());
        match report.hosts.add(candidate.host) {
            Ok(()) => {
                report.warnings.extend(missing_key);
                report.imported.push(name.clone());
                if let Some(alias) = candidate.jump_alias {
                    jumps.push((name, alias));
                }
            }
            Err(err) => report.skip(&name, err.to_string()),
        }
    }
    for (name, alias) in jumps {
        apply_jump(&mut report, &name, &alias);
    }
    Ok(report)
}

impl ImportReport {
    fn skip(&mut self, name: &str, reason: String) {
        self.skipped.push(SkippedHost {
            name: escape_control(name),
            reason,
        });
    }
}

fn apply_jump(report: &mut ImportReport, name: &str, alias: &str) {
    let shown = escape_control(alias);
    if alias.contains(',') {
        report.warnings.push(Warning::new(format!(
            "Host '{name}': ProxyJump '{shown}' lists several hops. Bifrost keeps one jump \
             host per host, so it was dropped. Give each jump host its own jump host to \
             build a chain."
        )));
        return;
    }
    let Some(target) = report.hosts.get(alias).map(|host| host.name.clone()) else {
        report.warnings.push(Warning::new(format!(
            "Host '{name}': its jump host '{shown}' is not a host in Bifrost, so the jump \
             host was dropped."
        )));
        return;
    };
    let Some(mut updated) = report.hosts.get(name).cloned() else {
        return;
    };
    updated.proxy_jump = Some(target);
    if let Err(err) = report.hosts.update(name, updated) {
        report.warnings.push(Warning::new(format!(
            "Host '{name}': the jump host '{shown}' was dropped: {err}"
        )));
    }
}

struct Candidate {
    host: Host,
    jump_alias: Option<String>,
}

/// The interesting lines of `ssh -G` output.
#[derive(Debug, Default)]
struct Resolved {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<String>,
    identity_files: Vec<String>,
    proxy_jump: Option<String>,
    proxy_command: Option<String>,
    local_forwards: Vec<String>,
    remote_forwards: Vec<String>,
    dynamic_forwards: Vec<String>,
    forward_agent: Option<String>,
}

/// Reads `ssh -G` output: one `keyword value` pair per line, lowercase keywords.
fn parse_resolved(output: &str) -> Resolved {
    let mut resolved = Resolved::default();
    for line in output.lines() {
        let Some((key, value)) = line.trim().split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim().to_string();
        match key.to_ascii_lowercase().as_str() {
            "hostname" => resolved.hostname = Some(value),
            "user" => resolved.user = Some(value),
            "port" => resolved.port = Some(value),
            "identityfile" => resolved.identity_files.push(unquote(&value)),
            "proxyjump" if !value.eq_ignore_ascii_case("none") => {
                resolved.proxy_jump = Some(value);
            }
            "proxycommand" if !value.eq_ignore_ascii_case("none") => {
                resolved.proxy_command = Some(value);
            }
            "localforward" => resolved.local_forwards.push(value),
            "remoteforward" => resolved.remote_forwards.push(value),
            "dynamicforward" => resolved.dynamic_forwards.push(value),
            "forwardagent" => resolved.forward_agent = Some(value),
            _ => {}
        }
    }
    resolved
}

fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

/// Quotes external text for use inside a message.
fn shown(text: &str) -> String {
    format!("'{}'", escape_control(text))
}

fn build_candidate(
    name: &str,
    resolved: Resolved,
    source: &ImportSource,
    warnings: &mut Vec<Warning>,
) -> Result<Candidate, String> {
    let hostname = resolved
        .hostname
        .ok_or_else(|| "ssh did not report a host name for it".to_string())?;
    let mut host = Host::new(name, hostname);

    if let Some(port) = &resolved.port {
        let port: u16 = port.parse().map_err(|_| {
            format!(
                "ssh reported the port {}, which is not a number",
                shown(port)
            )
        })?;
        // 22 is ssh's default; leave it unset.
        host.port = (port != 22).then_some(port);
    }

    host.user = resolved.user;

    let explicit: Vec<&String> = resolved
        .identity_files
        .iter()
        .filter(|file| !is_default_identity(file, source))
        .collect();
    host.identity_file = explicit.first().map(|file| (*file).clone());
    if explicit.len() > 1 {
        warnings.push(Warning::new(format!(
            "Host '{name}': {} identity files are configured; only the first ({}) was imported.",
            explicit.len(),
            shown(explicit[0])
        )));
    }
    let public_key = host
        .identity_file
        .take_if(|file| file.to_ascii_lowercase().ends_with(".pub"));
    if let Some(file) = public_key {
        warnings.push(Warning::new(format!(
            "Host '{name}': its identity file {} is a public key (it ends in .pub), so no \
             identity file was imported. If the host needs a specific key, set the private \
             key file on it.",
            shown(&file)
        )));
    }

    if resolved.proxy_command.is_some() {
        warnings.push(Warning::new(format!(
            "Host '{name}': its ProxyCommand was dropped because Bifrost does not support \
             ProxyCommand. Use ProxyJump instead; the host may not be reachable until you do."
        )));
    }

    host.forward_agent = match resolved.forward_agent.as_deref() {
        None | Some("no") => false,
        Some("yes") => true,
        Some(other) => {
            warnings.push(Warning::new(format!(
                "Host '{name}': ForwardAgent {} is not supported and was treated as 'no'.",
                shown(other)
            )));
            false
        }
    };

    for (label, specs, target) in [
        (
            "LocalForward",
            &resolved.local_forwards,
            &mut host.local_forwards,
        ),
        (
            "RemoteForward",
            &resolved.remote_forwards,
            &mut host.remote_forwards,
        ),
    ] {
        for spec in specs {
            match parse_forward(spec) {
                Ok(Parsed::Forward(forward)) => target.push(forward),
                Ok(Parsed::Unsupported(why)) => warnings.push(Warning::new(format!(
                    "Host '{name}': the {label} {} was dropped: {why}.",
                    shown(spec)
                ))),
                Err(why) => {
                    return Err(format!(
                        "its {label} {} is not understood: {why}",
                        shown(spec)
                    ));
                }
            }
        }
    }
    for spec in &resolved.dynamic_forwards {
        warnings.push(Warning::new(format!(
            "Host '{name}': the DynamicForward {} was dropped because Bifrost does not \
             support dynamic (SOCKS) forwards.",
            shown(spec)
        )));
    }

    validate::validate_host_fields(&host).map_err(|err| err.to_string())?;
    Ok(Candidate {
        host,
        jump_alias: resolved.proxy_jump,
    })
}

/// True for `~/.ssh/id_*` (and the same path spelled out) that ssh tries by
/// default.
fn is_default_identity(value: &str, source: &ImportSource) -> bool {
    let normalize = |text: &str| {
        let text = text.replace('\\', "/");
        if cfg!(windows) {
            text.to_ascii_lowercase()
        } else {
            text
        }
    };
    let value = normalize(value);
    DEFAULT_IDENTITY_FILES.iter().any(|default| {
        value == normalize(&format!("~/.ssh/{default}"))
            || value == normalize(&source.ssh_dir.join(default).to_string_lossy())
    })
}

enum Parsed {
    Forward(Forward),
    /// Valid ssh, but not something Bifrost can represent.
    Unsupported(String),
}

/// Parses `[bind:]port host:port` as printed by `ssh -G`.
fn parse_forward(spec: &str) -> Result<Parsed, String> {
    let mut parts = spec.split_whitespace();
    let (Some(listen), Some(dest), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err("expected a listen port and a destination".to_string());
    };
    if listen.starts_with('/') || dest.starts_with('/') {
        return Ok(Parsed::Unsupported(
            "Unix socket forwards are not supported".to_string(),
        ));
    }

    let (bind, listen_port) = split_endpoint(listen);
    if let Some(bind) = bind
        && !is_local_bind(bind)
    {
        return Ok(Parsed::Unsupported(format!(
            "it binds to {} but Bifrost only forwards on localhost",
            shown(bind)
        )));
    }
    let listen_port: u16 = listen_port
        .parse()
        .map_err(|_| format!("{} is not a valid listen port", shown(listen_port)))?;

    let (dest_host, dest_port) = split_destination(dest)
        .ok_or_else(|| format!("the destination {} has no port", shown(dest)))?;
    let dest_port: u16 = dest_port
        .parse()
        .map_err(|_| format!("{} is not a valid destination port", shown(dest_port)))?;

    Ok(Parsed::Forward(Forward {
        listen_port,
        dest_host: dest_host.to_string(),
        dest_port,
    }))
}

/// Splits `host:port`, `[v6]:port` or a bare `port` into (host, port).
fn split_endpoint(text: &str) -> (Option<&str>, &str) {
    if let Some(rest) = text.strip_prefix('[')
        && let Some((host, port)) = rest.split_once("]:")
    {
        return (Some(host), port);
    }
    match text.rsplit_once(':') {
        Some((host, port)) => (Some(host), port),
        None => (None, text),
    }
}

/// Splits a destination in `host:port`, `[v6]:port` or `host/port` form.
fn split_destination(text: &str) -> Option<(&str, &str)> {
    if let Some((host, port)) = text.rsplit_once('/')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return Some((host, port));
    }
    match split_endpoint(text) {
        (Some(host), port) => Some((host, port)),
        (None, _) => None,
    }
}

fn is_local_bind(bind: &str) -> bool {
    matches!(
        bind.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn source() -> ImportSource {
        ImportSource {
            config: PathBuf::from("unused"),
            ssh_dir: crate::sysenv::testing::abs("home/me/.ssh"),
            home: Some(crate::sysenv::testing::abs("home/me")),
        }
    }

    fn forward(spec: &str) -> Result<Parsed, String> {
        parse_forward(spec)
    }

    fn expect_forward(spec: &str) -> Forward {
        match forward(spec) {
            Ok(Parsed::Forward(f)) => f,
            Ok(Parsed::Unsupported(why)) => panic!("{spec}: unsupported: {why}"),
            Err(why) => panic!("{spec}: error: {why}"),
        }
    }

    #[test]
    fn parses_ssh_g_lines_and_ignores_the_rest() {
        let resolved = parse_resolved(
            "user deploy\nhostname web.example.com\nport 2222\n\
             identityfile ~/.ssh/id_rsa\nidentityfile \"~/keys/my key\"\n\
             proxyjump bastion\nproxycommand none\nforwardagent yes\n\
             localforward 8080 db:80\nremoteforward 9000 localhost:3000\n\
             dynamicforward 1080\nstricthostkeychecking ask\nbatchmode no\nnovalue\n",
        );
        assert_eq!(resolved.user.as_deref(), Some("deploy"));
        assert_eq!(resolved.hostname.as_deref(), Some("web.example.com"));
        assert_eq!(resolved.port.as_deref(), Some("2222"));
        assert_eq!(resolved.identity_files, ["~/.ssh/id_rsa", "~/keys/my key"]);
        assert_eq!(resolved.proxy_jump.as_deref(), Some("bastion"));
        assert_eq!(resolved.proxy_command, None, "`none` means unset");
        assert_eq!(resolved.forward_agent.as_deref(), Some("yes"));
        assert_eq!(resolved.local_forwards, ["8080 db:80"]);
        assert_eq!(resolved.remote_forwards, ["9000 localhost:3000"]);
        assert_eq!(resolved.dynamic_forwards, ["1080"]);
    }

    #[test]
    fn default_identity_files_are_recognized() {
        let src = source();
        for default in [
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/id_ecdsa_sk",
            "~/.ssh/id_dsa",
        ] {
            assert!(is_default_identity(default, &src), "{default}");
        }
        let spelled_out = src
            .ssh_dir
            .join("id_ed25519")
            .to_string_lossy()
            .into_owned();
        assert!(is_default_identity(&spelled_out, &src));
        for explicit in [
            "~/keys/work",
            "~/.ssh/work_ed25519",
            "~/.ssh/id_rsa.old",
            "/other/id_rsa",
        ] {
            assert!(!is_default_identity(explicit, &src), "{explicit}");
        }
    }

    #[test]
    fn parses_local_forward_forms() {
        assert_eq!(
            expect_forward("8080 db.internal:5432"),
            Forward {
                listen_port: 8080,
                dest_host: "db.internal".into(),
                dest_port: 5432
            }
        );
        for bind in ["127.0.0.1", "localhost", "LOCALHOST", "[::1]"] {
            let f = expect_forward(&format!("{bind}:8080 db:80"));
            assert_eq!((f.listen_port, f.dest_port), (8080, 80), "{bind}");
        }
        assert_eq!(expect_forward("8080 [::1]:80").dest_host, "::1");
        assert_eq!(expect_forward("8080 ::1/80").dest_host, "::1");
        assert_eq!(expect_forward("8080 db/5432").dest_port, 5432);
    }

    #[test]
    fn unrepresentable_forwards_are_unsupported_not_errors() {
        for spec in [
            "0.0.0.0:8080 db:80",
            "*:8080 db:80",
            ":8080 db:80",
            "192.168.1.5:8080 db:80",
            "/tmp/local.sock db:80",
            "8080 /var/run/remote.sock",
        ] {
            assert!(
                matches!(forward(spec), Ok(Parsed::Unsupported(_))),
                "{spec}"
            );
        }
    }

    #[test]
    fn malformed_forwards_are_errors() {
        for spec in [
            "",
            "8080",
            "8080 db",
            "abc db:80",
            "8080 db:abc",
            "1 2 3",
            "8080 db:99999",
        ] {
            assert!(forward(spec).is_err(), "{spec:?}");
        }
    }

    struct FakeResolver {
        outputs: HashMap<String, Result<String, String>>,
        unavailable: bool,
    }

    impl SshResolver for FakeResolver {
        fn resolve(&self, name: &str) -> Result<String, ResolveError> {
            if self.unavailable {
                return Err(ResolveError::Unavailable("no ssh".into()));
            }
            match self.outputs.get(name) {
                Some(Ok(out)) => Ok(out.clone()),
                Some(Err(msg)) => Err(ResolveError::Failed(msg.clone())),
                None => Err(ResolveError::Failed(format!("unknown host {name}"))),
            }
        }
    }

    fn import_with(config: &str, outputs: &[(&str, &str)], existing: &Hosts) -> ImportReport {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(&config_path, config).unwrap();
        let source = ImportSource {
            config: config_path,
            ssh_dir: dir.path().to_path_buf(),
            home: None,
        };
        let resolver = FakeResolver {
            outputs: outputs
                .iter()
                .map(|(k, v)| ((*k).to_string(), Ok((*v).to_string())))
                .collect(),
            unavailable: false,
        };
        import_hosts(existing, &source, &resolver).unwrap()
    }

    #[test]
    fn imports_a_simple_host_and_drops_default_values() {
        let report = import_with(
            "Host web\n",
            &[(
                "web",
                "user deploy\nhostname web.example.com\nport 22\nidentityfile ~/.ssh/id_rsa\n",
            )],
            &Hosts::new(),
        );
        assert_eq!(report.imported, ["web"]);
        let web = report.hosts.get("web").unwrap();
        assert_eq!(web.hostname, "web.example.com");
        assert_eq!(web.user.as_deref(), Some("deploy"));
        assert_eq!(web.port, None);
        assert_eq!(web.identity_file, None);
        assert!(report.skipped.is_empty() && report.conflicts.is_empty());
    }

    #[test]
    fn the_resolved_user_is_always_stored_even_if_it_is_the_local_login() {
        // ssh reports the local login name as `user` when the config sets none.
        // The store may be used elsewhere, so it is kept explicitly.
        let report = import_with(
            "Host a\nHost b\n",
            &[
                ("a", "user tester\nhostname a.example.com\n"),
                ("b", "user admin\nhostname b.example.com\n"),
            ],
            &Hosts::new(),
        );
        assert_eq!(
            report.hosts.get("a").unwrap().user.as_deref(),
            Some("tester")
        );
        assert_eq!(
            report.hosts.get("b").unwrap().user.as_deref(),
            Some("admin")
        );
    }

    #[test]
    fn existing_hosts_are_never_overwritten() {
        let mut existing = Hosts::new();
        let mut mine = Host::new("Web", "mine.example.com");
        mine.favorite = true;
        existing.add(mine.clone()).unwrap();

        let report = import_with(
            "Host web\nHost other\n",
            &[
                ("web", "hostname theirs.example.com\n"),
                ("other", "hostname other.example.com\n"),
            ],
            &existing,
        );
        assert_eq!(report.conflicts, ["web"]);
        assert_eq!(report.imported, ["other"]);
        assert_eq!(report.hosts.get("web"), Some(&mine));
        assert_eq!(report.hosts.len(), 2);
    }

    #[test]
    fn invalid_hosts_are_skipped_with_a_reason() {
        let report = import_with(
            "Host bad:name\nHost \"-oProxyCommand=id\"\nHost badhost\nHost fine\n",
            &[
                ("badhost", "hostname under_score.example.com\n"),
                ("fine", "hostname fine.example.com\n"),
            ],
            &Hosts::new(),
        );
        assert_eq!(report.imported, ["fine"]);
        assert_eq!(report.skipped.len(), 3);
        assert_eq!(report.skipped[0].name, "bad:name");
        assert!(report.skipped[0].reason.contains("Name may only contain"));
        assert!(report.skipped[1].reason.contains("must not start with '-'"));
        assert!(
            report.skipped[2]
                .reason
                .contains("Hostname may only contain")
        );
    }

    #[test]
    fn skipped_names_have_control_characters_escaped() {
        let report = import_with("Host bad\u{1b}name\n", &[], &Hosts::new());
        assert_eq!(report.skipped[0].name, "bad\\u{1b}name");
    }

    #[test]
    fn ssh_failures_skip_the_host_but_missing_ssh_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Host a\n").unwrap();
        let source = ImportSource {
            config,
            ssh_dir: dir.path().to_path_buf(),
            home: None,
        };

        let failing = FakeResolver {
            outputs: [(
                "a".to_string(),
                Err("ssh -G failed: bad config".to_string()),
            )]
            .into_iter()
            .collect(),
            unavailable: false,
        };
        let report = import_hosts(&Hosts::new(), &source, &failing).unwrap();
        assert_eq!(report.skipped[0].reason, "ssh -G failed: bad config");

        let missing = FakeResolver {
            outputs: HashMap::new(),
            unavailable: true,
        };
        let err = import_hosts(&Hosts::new(), &source, &missing).unwrap_err();
        assert!(matches!(err, ImportError::Ssh(_)));
    }

    #[test]
    fn jump_hosts_match_by_alias_regardless_of_order() {
        let report = import_with(
            "Host web\nHost bastion\nHost lost\nHost multi\n",
            &[
                ("web", "hostname web.example.com\nproxyjump bastion\n"),
                ("bastion", "hostname bastion.example.com\n"),
                ("lost", "hostname lost.example.com\nproxyjump ghost\n"),
                (
                    "multi",
                    "hostname multi.example.com\nproxyjump bastion,web\n",
                ),
            ],
            &Hosts::new(),
        );
        assert_eq!(
            report.hosts.get("web").unwrap().proxy_jump.as_deref(),
            Some("bastion")
        );
        assert_eq!(report.hosts.get("lost").unwrap().proxy_jump, None);
        assert_eq!(report.hosts.get("multi").unwrap().proxy_jump, None);
        let messages: Vec<&str> = report.warnings.iter().map(Warning::message).collect();
        assert!(
            messages
                .iter()
                .any(|m| m.contains("'ghost'") && m.contains("not a host in Bifrost"))
        );
        assert!(messages.iter().any(|m| m.contains("lists several hops")));
    }

    #[test]
    fn jump_hosts_can_point_at_existing_bifrost_hosts() {
        let mut existing = Hosts::new();
        existing.add(Host::new("bastion", "203.0.113.1")).unwrap();
        let report = import_with(
            "Host web\n",
            &[("web", "hostname web.example.com\nproxyjump BASTION\n")],
            &existing,
        );
        assert_eq!(
            report.hosts.get("web").unwrap().proxy_jump.as_deref(),
            Some("bastion")
        );
    }

    #[test]
    fn imported_jump_loops_are_broken_with_a_warning() {
        let report = import_with(
            "Host a\nHost b\n",
            &[
                ("a", "hostname a.example.com\nproxyjump b\n"),
                ("b", "hostname b.example.com\nproxyjump a\n"),
            ],
            &Hosts::new(),
        );
        assert_eq!(report.imported, ["a", "b"]);
        let a = report.hosts.get("a").unwrap().proxy_jump.clone();
        let b = report.hosts.get("b").unwrap().proxy_jump.clone();
        assert!(
            a.is_some() != b.is_some(),
            "exactly one jump survives: {a:?} {b:?}"
        );
        assert!(report.warnings.iter().any(|w| w.message().contains("loop")));
    }

    #[test]
    fn proxy_command_is_dropped_with_a_warning() {
        let report = import_with(
            "Host legacy\n",
            &[(
                "legacy",
                "hostname legacy.example.com\nproxycommand nc -X 5 %h %p\n",
            )],
            &Hosts::new(),
        );
        assert_eq!(report.imported, ["legacy"]);
        assert!(report.warnings.iter().any(|w| {
            w.message().contains("ProxyCommand was dropped") && w.message().contains("'legacy'")
        }));
    }

    #[test]
    fn several_explicit_identity_files_keep_the_first_and_warn() {
        let report = import_with(
            "Host multi\n",
            &[(
                "multi",
                "hostname multi.example.com\nidentityfile ~/keys/first\n\
                 identityfile ~/keys/second\nidentityfile ~/.ssh/id_rsa\n",
            )],
            &Hosts::new(),
        );
        assert_eq!(
            report.hosts.get("multi").unwrap().identity_file.as_deref(),
            Some("~/keys/first")
        );
        assert!(report.warnings.iter().any(|w| {
            w.message().contains("2 identity files") && w.message().contains("~/keys/first")
        }));
    }

    #[test]
    fn a_public_key_identity_is_dropped_with_a_warning_but_the_host_is_kept() {
        let report = import_with(
            "Host agentkey\nHost mixed\n",
            &[
                (
                    "agentkey",
                    "hostname a.example.com\nidentityfile ~/keys/id.PUB\n",
                ),
                (
                    "mixed",
                    "hostname m.example.com\nidentityfile ~/keys/id.pub\nidentityfile ~/keys/other\n",
                ),
            ],
            &Hosts::new(),
        );
        assert_eq!(report.imported, ["agentkey", "mixed"]);
        assert!(report.skipped.is_empty());
        assert_eq!(report.hosts.get("agentkey").unwrap().identity_file, None);
        // Only the first identity file is considered, as for any other host.
        assert_eq!(report.hosts.get("mixed").unwrap().identity_file, None);
        let public_key_warnings: Vec<&str> = report
            .warnings
            .iter()
            .map(Warning::message)
            .filter(|m| m.contains("is a public key"))
            .collect();
        assert_eq!(public_key_warnings.len(), 2, "{:?}", report.warnings);
        assert!(public_key_warnings[0].contains("'agentkey'"));
        assert!(public_key_warnings[0].contains("~/keys/id.PUB"));
    }

    #[test]
    fn public_keys_are_still_rejected_for_hosts_entered_by_hand() {
        let mut hosts = Hosts::new();
        let mut manual = Host::new("manual", "m.example.com");
        manual.identity_file = Some("~/keys/id.pub".into());
        assert!(hosts.add(manual).is_err());
    }

    #[test]
    fn missing_identity_files_are_checked_against_the_source_home() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("present_key"), "x").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Host present\nHost absent\n").unwrap();
        let source = ImportSource {
            config,
            ssh_dir: dir.path().to_path_buf(),
            home: Some(home.path().to_path_buf()),
        };
        let resolver = FakeResolver {
            outputs: [
                (
                    "present".to_string(),
                    Ok("hostname p.example.com\nidentityfile ~/present_key\n".to_string()),
                ),
                (
                    "absent".to_string(),
                    Ok("hostname a.example.com\nidentityfile ~/absent_key\n".to_string()),
                ),
            ]
            .into_iter()
            .collect(),
            unavailable: false,
        };
        let report = import_hosts(&Hosts::new(), &source, &resolver).unwrap();
        assert_eq!(report.imported, ["present", "absent"]);
        let warnings: Vec<&str> = report.warnings.iter().map(Warning::message).collect();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("Host 'absent'") && warnings[0].contains("does not exist"));
    }

    #[test]
    fn unsupported_forwards_warn_and_valid_ones_are_kept() {
        let report = import_with(
            "Host db\n",
            &[(
                "db",
                "hostname db.example.com\nlocalforward 5433 localhost:5432\n\
                 localforward 0.0.0.0:8080 localhost:80\nremoteforward 9000 localhost:3000\n\
                 dynamicforward 1080\n",
            )],
            &Hosts::new(),
        );
        let db = report.hosts.get("db").unwrap();
        assert_eq!(db.local_forwards.len(), 1);
        assert_eq!(db.remote_forwards.len(), 1);
        let messages: Vec<&str> = report.warnings.iter().map(Warning::message).collect();
        assert!(
            messages
                .iter()
                .any(|m| m.contains("0.0.0.0:8080") && m.contains("only forwards on localhost"))
        );
        assert!(messages.iter().any(|m| m.contains("DynamicForward")));
    }

    #[test]
    fn a_malformed_forward_skips_the_host() {
        let report = import_with(
            "Host db\n",
            &[("db", "hostname db.example.com\nlocalforward garbage\n")],
            &Hosts::new(),
        );
        assert!(report.imported.is_empty());
        assert!(report.skipped[0].reason.contains("LocalForward"));
    }

    #[test]
    fn forward_agent_values() {
        let report = import_with(
            "Host a\nHost b\nHost c\n",
            &[
                ("a", "hostname a.example.com\nforwardagent yes\n"),
                ("b", "hostname b.example.com\nforwardagent no\n"),
                ("c", "hostname c.example.com\nforwardagent $SSH_AUTH_SOCK\n"),
            ],
            &Hosts::new(),
        );
        assert!(report.hosts.get("a").unwrap().forward_agent);
        assert!(!report.hosts.get("b").unwrap().forward_agent);
        assert!(!report.hosts.get("c").unwrap().forward_agent);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.message().contains("ForwardAgent"))
        );
    }

    #[test]
    fn hostile_ssh_output_cannot_smuggle_values_past_validation() {
        let report = import_with(
            "Host evil\n",
            &[("evil", "hostname -oProxyCommand=id\n")],
            &Hosts::new(),
        );
        assert!(report.imported.is_empty());
        assert!(report.hosts.is_empty());

        let report = import_with(
            "Host evil\n",
            &[("evil", "hostname ok.example.com\nuser -oProxyCommand=id\n")],
            &Hosts::new(),
        );
        assert!(report.imported.is_empty());
    }

    #[test]
    fn for_user_points_at_the_ssh_directory() {
        let env = crate::sysenv::testing::fake_env(&[(
            "HOME",
            crate::sysenv::testing::abs("home/me").into_os_string(),
        )]);
        let src = ImportSource::for_user(Platform::Linux, &env).unwrap();
        assert_eq!(
            src.config,
            crate::sysenv::testing::abs("home/me")
                .join(".ssh")
                .join("config")
        );
        assert!(matches!(
            ImportSource::for_user(Platform::Linux, &crate::sysenv::testing::fake_env(&[])),
            Err(ImportError::NoHome)
        ));

        // Windows keeps the config in %USERPROFILE%\.ssh\config.
        let win = crate::sysenv::testing::fake_env(&[(
            "USERPROFILE",
            crate::sysenv::testing::abs("Users/me").into_os_string(),
        )]);
        let src = ImportSource::for_user(Platform::Windows, &win).unwrap();
        assert_eq!(
            src.config,
            crate::sysenv::testing::abs("Users/me")
                .join(".ssh")
                .join("config")
        );
    }

    #[test]
    fn system_resolver_refuses_a_relative_ssh_path() {
        let resolver = SystemSshResolver::new(PathBuf::from("ssh"));
        assert!(matches!(
            resolver.resolve("web"),
            Err(ResolveError::Unavailable(_))
        ));
    }
}
