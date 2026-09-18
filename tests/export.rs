//! Export tests through the public API only: what ends up in the exported
//! file, and that hostile values cannot add directives to it.

use std::fs;

use bifrost_ssh::domain::{Forward, Host, Hosts};
use bifrost_ssh::ssh::export::{self, ExportError, GENERATED_HEADER};

type Mutation = Box<dyn Fn(&mut Host)>;

fn host(name: &str, hostname: &str) -> Host {
    Host::new(name, hostname)
}

/// The lines that are directives (not blank, not comments), trimmed.
fn directives(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn keyword(line: &str) -> &str {
    line.split_whitespace().next().unwrap()
}

#[test]
fn exports_a_realistic_store() {
    let mut bastion = host("bastion", "bastion.example.com");
    bastion.user = Some("admin".into());
    bastion.port = Some(2222);
    bastion.notes = Some("hardware token required".into());

    let mut web = host("web", "10.0.0.5");
    web.user = Some("deploy".into());
    web.identity_file = Some("~/.ssh/web_ed25519".into());
    web.proxy_jump = Some("bastion".into());
    web.forward_agent = true;
    web.favorite = true;
    web.tags = vec!["prod".into()];
    web.local_forwards = vec![Forward {
        listen_port: 8443,
        dest_host: "localhost".into(),
        dest_port: 443,
    }];

    let mut hosts = Hosts::new();
    hosts.add(bastion).unwrap();
    hosts.add(web).unwrap();

    let text = export::render(&hosts).unwrap();
    assert!(text.starts_with(GENERATED_HEADER));
    assert_eq!(
        directives(&text),
        [
            "Host bastion",
            "HostName bastion.example.com",
            "User admin",
            "Port 2222",
            "Host web",
            "HostName 10.0.0.5",
            "User deploy",
            "IdentityFile \"~/.ssh/web_ed25519\"",
            "IdentitiesOnly yes",
            "ProxyJump admin@bastion.example.com:2222",
            "LocalForward 127.0.0.1:8443 localhost:443",
            "ForwardAgent yes",
        ]
    );
    for private in ["hardware token", "prod", "favorite"] {
        assert!(!text.contains(private), "{private} leaked into the export");
    }
}

#[test]
fn hosts_with_hostile_values_cannot_be_created_so_they_cannot_be_exported() {
    let attempts: Vec<(&str, Mutation)> = vec![
        (
            "newline in hostname",
            Box::new(|h| h.hostname = "a.example.com\nProxyCommand id".into()),
        ),
        (
            "carriage return in user",
            Box::new(|h| h.user = Some("u\rProxyCommand id".into())),
        ),
        (
            "newline in identity file",
            Box::new(|h| h.identity_file = Some("k\nProxyCommand id".into())),
        ),
        (
            "option as hostname",
            Box::new(|h| h.hostname = "-oProxyCommand=id".into()),
        ),
        (
            "option as user",
            Box::new(|h| h.user = Some("-oLocalCommand=id".into())),
        ),
        (
            "option as identity file",
            Box::new(|h| h.identity_file = Some("-oProxyCommand=id".into())),
        ),
        (
            "option as jump host",
            Box::new(|h| h.proxy_jump = Some("-oProxyCommand=id".into())),
        ),
        (
            "space in name",
            Box::new(|h| h.name = "a ProxyCommand=id".into()),
        ),
        ("pattern as name", Box::new(|h| h.name = "*".into())),
        (
            "option as forward destination",
            Box::new(|h| {
                h.local_forwards.push(Forward {
                    listen_port: 1,
                    dest_host: "-oProxyCommand=id".into(),
                    dest_port: 2,
                })
            }),
        ),
    ];

    let mut hosts = Hosts::new();
    hosts.add(host("safe", "safe.example.com")).unwrap();
    for (label, mutate) in attempts {
        let mut evil = host("evil", "evil.example.com");
        mutate(&mut evil);
        assert!(hosts.add(evil).is_err(), "{label} should be rejected");
    }

    let text = export::render(&hosts).unwrap();
    assert_eq!(
        directives(&text),
        ["Host safe", "HostName safe.example.com"]
    );
}

#[test]
fn awkward_but_valid_values_stay_inside_their_directive() {
    let mut h = host("tricky", "tricky.example.com");
    h.identity_file = Some("/tmp/k\" ProxyCommand evil \"z".into());
    h.user = Some("CORP\\svc".into());
    let mut hosts = Hosts::new();
    hosts.add(h).unwrap();

    let text = export::render(&hosts).unwrap();
    let lines = directives(&text);
    assert_eq!(
        lines.iter().map(|l| keyword(l)).collect::<Vec<_>>(),
        ["Host", "HostName", "User", "IdentityFile", "IdentitiesOnly"]
    );
    assert_eq!(lines[2], "User \"CORP\\\\svc\"");
    assert_eq!(
        lines[3],
        "IdentityFile \"/tmp/k\\\" ProxyCommand evil \\\"z\""
    );
}

#[test]
fn a_five_hop_chain_exports_in_connection_order_and_six_cannot_exist() {
    let mut hosts = Hosts::new();
    // h5 is the outermost jump host; h0 is the destination.
    hosts.add(host("h5", "h5.example.com")).unwrap();
    for i in (0..5).rev() {
        let mut h = host(&format!("h{i}"), &format!("h{i}.example.com"));
        h.proxy_jump = Some(format!("h{}", i + 1));
        hosts.add(h).unwrap();
    }
    let text = export::render(&hosts).unwrap();
    assert!(
        text.contains(
            "ProxyJump h5.example.com:22,h4.example.com:22,h3.example.com:22,\
         h2.example.com:22,h1.example.com:22\n"
        ),
        "{text}"
    );

    // A sixth hop is refused: h6 can exist, but h5 cannot hop through it.
    hosts.add(host("h6", "h6.example.com")).unwrap();
    let mut h5 = hosts.get("h5").unwrap().clone();
    h5.proxy_jump = Some("h6".into());
    let err = hosts.update("h5", h5).unwrap_err();
    assert!(err.to_string().contains("at most 5 hops"), "{err}");
    assert_eq!(hosts.get("h5").unwrap().proxy_jump, None);
}

#[test]
fn export_file_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join(".ssh");
    let user_config = ssh_dir.join("config");
    let target = ssh_dir.join("bifrost_config");

    fs::create_dir(&ssh_dir).unwrap();
    fs::write(&user_config, "Include bifrost_config\nHost mine\n").unwrap();

    let mut hosts = Hosts::new();
    hosts.add(host("web", "web.example.com")).unwrap();
    export::export_to(&hosts, &target).unwrap();
    assert!(fs::read_to_string(&target).unwrap().contains("Host web\n"));

    // Re-exporting replaces the generated file.
    hosts.add(host("db", "db.example.com")).unwrap();
    export::export_to(&hosts, &target).unwrap();
    assert!(fs::read_to_string(&target).unwrap().contains("Host db\n"));

    // The user's own config is never touched, nor can it be targeted.
    assert_eq!(
        fs::read_to_string(&user_config).unwrap(),
        "Include bifrost_config\nHost mine\n"
    );
    assert!(matches!(
        export::export_to(&hosts, &user_config),
        Err(ExportError::ProtectedTarget(_))
    ));

    // A file that Bifrost did not write is not replaced.
    let other = ssh_dir.join("handwritten");
    fs::write(&other, "Host precious\n").unwrap();
    assert!(matches!(
        export::export_to(&hosts, &other),
        Err(ExportError::NotGenerated(_))
    ));
    assert_eq!(fs::read_to_string(&other).unwrap(), "Host precious\n");
}

#[cfg(unix)]
#[test]
fn exported_file_is_user_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("fresh-ssh-dir").join("bifrost_config");
    let mut hosts = Hosts::new();
    hosts.add(host("web", "web.example.com")).unwrap();
    export::export_to(&hosts, &target).unwrap();

    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&target), 0o600);
    assert_eq!(mode(target.parent().unwrap()), 0o700);
}
