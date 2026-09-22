//! Import tests against the fixture ssh configs in `tests/fixtures/ssh_configs`.
//!
//! `ssh -G` is replaced by canned output captured from a real `ssh -G -F` run
//! (`g/<name>.txt`), so no ssh binary or network is needed. One `#[ignore]`d
//! test runs the real thing; run it with `cargo test -- --ignored`.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use bifrost_ssh::domain::{Forward, Host, Hosts};
use bifrost_ssh::ssh::binary::resolve_ssh;
use bifrost_ssh::ssh::export;
use bifrost_ssh::ssh::import::{
    ImportReport, ImportSource, ResolveError, SshResolver, SystemSshResolver, import_hosts,
};
use bifrost_ssh::ssh::scan::scan_host_names;
use bifrost_ssh::store::Store;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssh_configs")
}

/// Serves `g/<name>.txt` and records which names were resolved.
struct CannedResolver {
    resolved: RefCell<Vec<String>>,
}

impl CannedResolver {
    fn new() -> Self {
        CannedResolver {
            resolved: RefCell::new(Vec::new()),
        }
    }
}

impl SshResolver for CannedResolver {
    fn resolve(&self, name: &str) -> Result<String, ResolveError> {
        self.resolved.borrow_mut().push(name.to_string());
        fs::read_to_string(fixtures().join("g").join(format!("{name}.txt")))
            .map_err(|_| ResolveError::Failed(format!("no canned ssh -G output for {name}")))
    }
}

fn source() -> ImportSource {
    ImportSource {
        config: fixtures().join("import_main.conf"),
        ssh_dir: fixtures(),
        home: None,
    }
}

fn has_warning(report: &ImportReport, needle: &[&str]) -> bool {
    report
        .warnings
        .iter()
        .any(|w| needle.iter().all(|n| w.message().contains(n)))
}

// ---- scanner ---------------------------------------------------------------

#[test]
fn scanner_finds_concrete_host_names_in_a_fixture() {
    let report = scan_host_names(&fixtures().join("basic.conf"), &fixtures(), None).unwrap();
    assert_eq!(
        report.names,
        ["web", "lower", "db1", "db2", "quoted name", "after-match"]
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn scanner_follows_includes_and_survives_include_loops() {
    let report = scan_host_names(&fixtures().join("includes.conf"), &fixtures(), None).unwrap();
    assert_eq!(
        report.names,
        [
            "first",
            "from-web-conf",
            "from-db-conf",
            "from-extra",
            "last"
        ]
    );
    // The fixture includes itself, which the scan survives and reports: ssh
    // itself refuses such a file with "Too many recursive configuration
    // includes", so it is not something to pass over in silence.
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(
        report.warnings[0].message().contains("includes itself"),
        "{:?}",
        report.warnings
    );
}

// ---- import ----------------------------------------------------------------

#[test]
fn imports_the_fixture_config() {
    let resolver = CannedResolver::new();
    let report = import_hosts(&Hosts::new(), &source(), &resolver).unwrap();

    assert_eq!(
        report.imported,
        [
            "bastion", "web", "db", "legacy", "multikey", "chain", "plain"
        ]
    );
    assert!(report.conflicts.is_empty());

    // Patterns were never resolved, and neither was a name that fails validation.
    let resolved = resolver.resolved.borrow();
    assert!(!resolved.iter().any(|n| n.contains('*') || n == "host:2222"));

    let skipped: Vec<(&str, &str)> = report
        .skipped
        .iter()
        .map(|s| (s.name.as_str(), s.reason.as_str()))
        .collect();
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert_eq!(skipped[0].0, "bad_host");
    assert!(
        skipped[0].1.contains("Hostname may only contain"),
        "{skipped:?}"
    );
    assert_eq!(skipped[1].0, "host:2222");
    assert!(
        skipped[1].1.contains("Name may only contain"),
        "{skipped:?}"
    );

    let hosts = &report.hosts;

    let bastion = hosts.get("bastion").unwrap();
    assert_eq!(bastion.hostname, "bastion.example.com");
    assert_eq!(bastion.user.as_deref(), Some("admin"));
    assert_eq!(bastion.port, Some(2222));
    assert_eq!(
        bastion.identity_file.as_deref(),
        Some("~/keys/bastion_ed25519")
    );
    assert_eq!(bastion.proxy_jump, None);

    let web = hosts.get("web").unwrap();
    assert_eq!(web.hostname, "web.example.com");
    assert_eq!(web.user.as_deref(), Some("deploy"));
    assert_eq!(web.port, None, "the default port is left unset");
    assert_eq!(
        web.identity_file, None,
        "ssh's default keys are not imported"
    );
    assert_eq!(web.proxy_jump.as_deref(), Some("bastion"));
    assert!(web.forward_agent);
    assert_eq!(
        web.remote_forwards,
        [Forward {
            listen_port: 9090,
            dest_host: "localhost".into(),
            dest_port: 3000
        }]
    );

    let db = hosts.get("db").unwrap();
    assert_eq!(
        db.user.as_deref(),
        Some("tester"),
        "the resolved user is stored explicitly, even when it is the login name"
    );
    assert_eq!(db.proxy_jump.as_deref(), Some("bastion"));
    assert_eq!(
        db.local_forwards,
        [Forward {
            listen_port: 5433,
            dest_host: "localhost".into(),
            dest_port: 5432
        }]
    );

    let multikey = hosts.get("multikey").unwrap();
    assert_eq!(multikey.identity_file.as_deref(), Some("~/keys/first"));

    let chain = hosts.get("chain").unwrap();
    assert_eq!(chain.proxy_jump, None);

    assert_eq!(hosts.get("plain").unwrap().user.as_deref(), Some("tester"));
    assert_eq!(hosts.get("plain").unwrap().hostname, "plain.example.com");

    // Warnings for everything that was dropped.
    assert!(has_warning(
        &report,
        &["ProxyCommand was dropped", "'legacy'"]
    ));
    assert!(has_warning(
        &report,
        &["2 identity files", "'multikey'", "~/keys/first"]
    ));
    assert!(has_warning(
        &report,
        &["0.0.0.0", "only forwards on localhost", "'db'"]
    ));
    assert!(has_warning(&report, &["DynamicForward", "'db'"]));
    assert!(has_warning(&report, &["lists several hops", "'chain'"]));
}

#[test]
fn drops_proxy_command_but_keeps_the_host() {
    let report = import_hosts(&Hosts::new(), &source(), &CannedResolver::new()).unwrap();
    let legacy = report.hosts.get("legacy").unwrap();
    assert_eq!(legacy.hostname, "legacy.example.com");
    assert_eq!(legacy.proxy_jump, None);
    // Nothing that looks like a ProxyCommand survives anywhere in the store.
    let rendered = export::render(&report.hosts).unwrap();
    assert!(!rendered.to_ascii_lowercase().contains("proxycommand"));
    assert!(!rendered.contains("nc -X"));
}

#[test]
fn existing_hosts_are_kept_and_reported_as_conflicts() {
    let mut existing = Hosts::new();
    let mut mine = Host::new("WEB", "my-own.example.com");
    mine.favorite = true;
    mine.notes = Some("do not lose me".into());
    existing.add(mine.clone()).unwrap();

    let resolver = CannedResolver::new();
    let report = import_hosts(&existing, &source(), &resolver).unwrap();

    assert_eq!(report.conflicts, ["web"]);
    assert!(!report.imported.contains(&"web".to_string()));
    assert!(!resolver.resolved.borrow().contains(&"web".to_string()));
    assert_eq!(report.hosts.get("web"), Some(&mine));
    // The imported `db` still finds its jump host among the imported hosts.
    assert_eq!(
        report.hosts.get("db").unwrap().proxy_jump.as_deref(),
        Some("bastion")
    );
}

#[test]
fn importing_twice_only_reports_conflicts() {
    let first = import_hosts(&Hosts::new(), &source(), &CannedResolver::new()).unwrap();
    let second = import_hosts(&first.hosts, &source(), &CannedResolver::new()).unwrap();
    assert!(second.imported.is_empty());
    assert_eq!(second.conflicts.len(), first.imported.len());
    assert_eq!(second.hosts, first.hosts);
}

#[test]
fn import_then_store_then_export_end_to_end() {
    let report = import_hosts(&Hosts::new(), &source(), &CannedResolver::new()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path().join("bifrost"));
    store.save(&report.hosts).unwrap();
    let loaded = store.load().unwrap().hosts;
    assert_eq!(loaded, report.hosts);

    let target = dir.path().join(".ssh").join("bifrost_config");
    export::export_to(&loaded, &target).unwrap();
    let text = fs::read_to_string(&target).unwrap();
    assert!(
        text.contains(
            "Host web\n    HostName web.example.com\n    User deploy\n    \
         ProxyJump admin@bastion.example.com:2222\n"
        ),
        "{text}"
    );
    assert!(text.contains("    RemoteForward 127.0.0.1:9090 localhost:3000\n"));
    assert!(text.contains("    ForwardAgent yes\n"));
    assert!(text.contains("    IdentityFile \"~/keys/bastion_ed25519\"\n    IdentitiesOnly yes\n"));
}

#[test]
fn a_missing_config_imports_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let source = ImportSource {
        config: dir.path().join("no-such-config"),
        ssh_dir: dir.path().to_path_buf(),
        home: None,
    };
    let report = import_hosts(&Hosts::new(), &source, &CannedResolver::new()).unwrap();
    assert!(report.hosts.is_empty());
    assert!(report.imported.is_empty() && report.skipped.is_empty());
}

// ---- hostile input ---------------------------------------------------------

/// A resolver that answers every name with the same output.
struct Fixed(&'static str);

impl SshResolver for Fixed {
    fn resolve(&self, _name: &str) -> Result<String, ResolveError> {
        Ok(self.0.to_string())
    }
}

fn import_one(config: &str, output: &'static str) -> ImportReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    fs::write(&path, config).unwrap();
    let source = ImportSource {
        config: path,
        ssh_dir: dir.path().to_path_buf(),
        home: None,
    };
    import_hosts(&Hosts::new(), &source, &Fixed(output)).unwrap()
}

#[test]
fn hostile_config_values_never_reach_the_store() {
    for (label, output) in [
        ("option as hostname", "hostname -oProxyCommand=id\n"),
        (
            "option as user",
            "hostname ok.example.com\nuser -oProxyCommand=id\n",
        ),
        (
            "option as identity",
            "hostname ok.example.com\nidentityfile -oProxyCommand=id\n",
        ),
        ("shell in hostname", "hostname $(id).example.com\n"),
        ("semicolon in hostname", "hostname ok.example.com;id\n"),
        (
            "control char in user",
            "hostname ok.example.com\nuser a\u{1b}[31mb\n",
        ),
        (
            "option as forward host",
            "hostname ok.example.com\nlocalforward 1 -oProxyCommand=id:2\n",
        ),
    ] {
        let report = import_one("Host evil\n", output);
        assert!(report.imported.is_empty(), "{label}: {:?}", report.imported);
        assert!(report.hosts.is_empty(), "{label}");
        assert_eq!(report.skipped.len(), 1, "{label}");
    }
}

#[test]
fn hostile_host_names_are_skipped_without_running_ssh() {
    struct Panics;
    impl SshResolver for Panics {
        fn resolve(&self, name: &str) -> Result<String, ResolveError> {
            panic!("ssh must not be asked about {name:?}");
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    fs::write(
        &path,
        "Host \"-oProxyCommand=id\"\nHost \"a;b\"\nHost \"$(id)\"\nHost `id`\nHost \"a\u{1b}b\"\n",
    )
    .unwrap();
    let source = ImportSource {
        config: path,
        ssh_dir: dir.path().to_path_buf(),
        home: None,
    };
    let report = import_hosts(&Hosts::new(), &source, &Panics).unwrap();
    assert!(report.hosts.is_empty());
    assert_eq!(report.skipped.len(), 5);
    for skipped in &report.skipped {
        assert!(!skipped.name.contains('\u{1b}'), "{skipped:?}");
    }
}

#[test]
fn awkward_but_valid_values_are_exported_without_injection() {
    // Valid values that need quoting: an identity path with quotes and a
    // fake directive inside it.
    let report = import_one(
        "Host tricky\n",
        "hostname ok.example.com\nidentityfile /tmp/k\" ProxyCommand evil \"z\n",
    );
    assert_eq!(report.imported, ["tricky"]);
    let text = export::render(&report.hosts).unwrap();
    let directive_lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(str::trim)
        .collect();
    assert!(
        directive_lines.iter().all(|l| {
            ["Host ", "HostName ", "IdentityFile ", "IdentitiesOnly "]
                .iter()
                .any(|k| l.starts_with(k))
        }),
        "{directive_lines:?}"
    );
    assert!(
        text.contains("IdentityFile \"/tmp/k\\\" ProxyCommand evil \\\"z\""),
        "{text}"
    );
}

#[test]
fn a_public_key_identity_is_dropped_with_a_warning_and_the_host_is_imported() {
    let report = import_one(
        "Host agentkey\n",
        "hostname a.example.com\nuser me\nidentityfile ~/keys/id_ed25519.pub\n",
    );
    assert_eq!(report.imported, ["agentkey"]);
    assert!(report.skipped.is_empty());
    let host = report.hosts.get("agentkey").unwrap();
    assert_eq!(host.identity_file, None);
    assert_eq!(host.user.as_deref(), Some("me"));
    assert!(has_warning(&report, &["'agentkey'", "public key", ".pub"]));
    // Nothing about the key is exported.
    assert!(
        !export::render(&report.hosts)
            .unwrap()
            .contains("id_ed25519")
    );
}

// ---- the real ssh (manual) -------------------------------------------------

/// Runs the real `ssh -G` on the fixture config. Needs OpenSSH installed and no
/// network. Run with: `cargo test -- --ignored`.
#[test]
#[ignore = "needs a real ssh binary"]
fn real_ssh_imports_the_fixture_config() {
    let ssh = resolve_ssh().expect("ssh should be installed");
    let resolver =
        SystemSshResolver::new(ssh).with_config_file(fixtures().join("import_main.conf"));

    let report = import_hosts(&Hosts::new(), &source(), &resolver).unwrap();

    assert_eq!(
        report.imported,
        [
            "bastion", "web", "db", "legacy", "multikey", "chain", "plain"
        ],
        "skipped: {:?}",
        report.skipped
    );
    let web = report.hosts.get("web").unwrap();
    assert_eq!(web.user.as_deref(), Some("deploy"));
    assert_eq!(web.proxy_jump.as_deref(), Some("bastion"));
    assert!(web.forward_agent);
    assert_eq!(web.identity_file, None);
    assert!(report.hosts.get("db").unwrap().user.is_some());
    let bastion = report.hosts.get("bastion").unwrap();
    assert_eq!(bastion.port, Some(2222));
    assert_eq!(
        bastion.identity_file.as_deref(),
        Some("~/keys/bastion_ed25519")
    );
    assert_eq!(report.hosts.get("db").unwrap().local_forwards.len(), 1);
    assert!(has_warning(&report, &["ProxyCommand was dropped"]));
    assert!(has_warning(&report, &["lists several hops"]));
}
