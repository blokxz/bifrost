//! The arguments Bifrost builds, checked against the real `ssh`.
//!
//! `ssh -G` prints the configuration it would use without connecting, so this
//! needs the binary but no network and no server. Like every test that needs a
//! real ssh, it is `#[ignore]`d and run by hand: `cargo test -- --ignored`.

use std::process::Command;

use bifrost_ssh::domain::{Forward, Host, Hosts};
use bifrost_ssh::ssh::binary::resolve_ssh;
use bifrost_ssh::ssh::command::build_args;

fn host(name: &str) -> Host {
    Host::new(name, format!("{name}.example.com"))
}

/// What `ssh -G` resolves for `args`, as lowercase key to values.
fn resolve(args: &[String]) -> Vec<(String, String)> {
    let ssh = resolve_ssh().expect("ssh should be installed for this test");
    let output = Command::new(ssh)
        .arg("-G")
        .args(args)
        .output()
        .expect("ssh should run");
    assert!(
        output.status.success(),
        "ssh refused the arguments {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn values<'a>(resolved: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    resolved
        .iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[test]
#[ignore = "needs the real ssh binary"]
fn ssh_reads_every_setting_back_as_it_was_meant() {
    let mut jump = host("bastion");
    jump.user = Some("ops".to_string());
    jump.port = Some(2200);
    let mut web = host("web");
    web.user = Some("deploy".to_string());
    web.port = Some(2222);
    web.identity_file = Some("~/.ssh/id_ed25519".to_string());
    web.proxy_jump = Some("bastion".to_string());
    web.forward_agent = true;
    web.local_forwards = vec![Forward {
        listen_port: 8080,
        dest_host: "localhost".to_string(),
        dest_port: 80,
    }];
    web.remote_forwards = vec![Forward {
        listen_port: 9000,
        dest_host: "::1".to_string(),
        dest_port: 3000,
    }];
    let hosts = Hosts::from_vec(vec![jump, web.clone()]).unwrap();

    let args = build_args(&web, &hosts).unwrap();
    let resolved = resolve(args.as_slice());

    assert_eq!(values(&resolved, "user"), ["deploy"]);
    assert_eq!(values(&resolved, "hostname"), ["web.example.com"]);
    assert_eq!(values(&resolved, "port"), ["2222"]);
    assert_eq!(values(&resolved, "identitiesonly"), ["yes"]);
    assert_eq!(values(&resolved, "forwardagent"), ["yes"]);
    assert_eq!(
        values(&resolved, "proxyjump"),
        ["ops@bastion.example.com:2200"]
    );
    assert_eq!(
        values(&resolved, "localforward"),
        ["[127.0.0.1]:8080 [localhost]:80"]
    );
    assert_eq!(
        values(&resolved, "remoteforward"),
        ["[127.0.0.1]:9000 [::1]:3000"]
    );
    assert!(
        values(&resolved, "proxycommand").is_empty(),
        "nothing Bifrost builds can set a ProxyCommand"
    );
}

#[test]
#[ignore = "needs the real ssh binary"]
fn a_hostile_identity_file_stays_one_argument_and_sets_nothing_else() {
    let mut h = host("web");
    h.identity_file = Some("/keys/a b; touch pwned -oProxyCommand=evil".to_string());
    let hosts = Hosts::from_vec(vec![h.clone()]).unwrap();

    let args = build_args(&h, &hosts).unwrap();
    let resolved = resolve(args.as_slice());

    assert_eq!(values(&resolved, "hostname"), ["web.example.com"]);
    assert!(values(&resolved, "proxycommand").is_empty());
}
