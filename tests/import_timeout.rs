//! Importing when an `ssh -G` does not finish.
//!
//! `ssh -G` runs the `Match exec` commands of the user's config, and one of them
//! can hang. Each host is given a deadline: one that misses it is skipped with the
//! reason, like any host ssh could not resolve, and what it started is killed with
//! it. `ssh` is a fake script here that hangs for chosen hosts, the way such a
//! command would: it starts a `sleep` and waits for it.
//!
//! Unix only: the script is a shell script.

#![cfg(unix)]

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bifrost_ssh::domain::Hosts;
use bifrost_ssh::ssh::import::{
    IMPORT_BUDGET, ImportReport, ImportSource, RESOLVE_TIMEOUT, SystemSshResolver, import_hosts,
};

/// What is said of every host that was not read because the budget ran out.
const OUT_OF_TIME: &str = "the import was taking too long, so the remaining hosts were not read; \
check for a Match exec command in your ssh config that does not finish, then try again.";

/// A scratch `~/.ssh` with a config of these host names, and a fake `ssh` that
/// answers `ssh -G -- <name>` and hangs for the names in `hang`.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new(hosts: &[&str], hang: &[&str], answer_after_seconds: Option<&str>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        fs::create_dir(&ssh_dir).unwrap();
        let config: String = hosts
            .iter()
            .map(|host| format!("Host {host}\n  HostName {host}.example.com\n"))
            .collect();
        fs::write(ssh_dir.join("config"), config).unwrap();

        let hangs = hang.join("|");
        let pids = dir.path().join("pids");
        fs::create_dir(&pids).unwrap();
        let delay = answer_after_seconds
            .map(|seconds| format!("sleep {seconds}\n"))
            .unwrap_or_default();
        let script = format!(
            r#"#!/bin/sh
# ssh -G -- NAME
name="$3"
case "$name" in
  {hangs})
    # A Match exec that never finishes: a command is started, and waited for.
    sleep 60 &
    echo $! > "{pids}/$name"
    wait
    ;;
esac
{delay}printf 'hostname %s.example.com\nuser me\nport 22\n' "$name"
"#,
            hangs = if hang.is_empty() {
                "__nothing__".to_string()
            } else {
                hangs
            },
            pids = pids.display(),
        );
        support::write_script(&dir.path().join("ssh"), &script, 0o755);
        Fixture { dir }
    }

    fn ssh(&self) -> PathBuf {
        self.dir.path().join("ssh")
    }

    fn source(&self) -> ImportSource {
        let ssh_dir = self.dir.path().join(".ssh");
        ImportSource {
            config: ssh_dir.join("config"),
            ssh_dir,
            home: Some(self.dir.path().to_path_buf()),
        }
    }

    /// The pid of what the fake started for `name`, if it did.
    fn started_for(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.dir.path().join("pids").join(name))
            .ok()
            .map(|pid| pid.trim().to_string())
    }

    fn import(&self, timeout: Duration) -> (ImportReport, Duration) {
        self.import_within(timeout, IMPORT_BUDGET)
    }

    fn import_within(&self, timeout: Duration, budget: Duration) -> (ImportReport, Duration) {
        let resolver = SystemSshResolver::new(self.ssh())
            .with_timeout(timeout)
            .with_budget(budget);
        self.run(&resolver)
    }

    /// The report, and how long the import itself took.
    ///
    /// The clock starts once the spawn lock is held. An import holds the lock for
    /// its whole run, and the tests of this file take several seconds together, so
    /// a test that has to wait for its turn would otherwise report the others'
    /// time as its own.
    fn run(&self, resolver: &SystemSshResolver) -> (ImportReport, Duration) {
        let _serialized = support::serialize_spawns();
        let started = Instant::now();
        let report = import_hosts(&Hosts::new(), &self.source(), resolver).unwrap();
        (report, started.elapsed())
    }
}

fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn gone_soon(pid: &str) -> bool {
    (0..100).any(|_| {
        thread::sleep(Duration::from_millis(20));
        !alive(pid)
    })
}

#[test]
fn a_host_that_hangs_is_skipped_with_the_reason_and_the_others_are_imported() {
    let fixture = Fixture::new(&["fine", "slow", "also"], &["slow"], None);
    let (report, took) = fixture.import(Duration::from_millis(500));

    assert_eq!(report.imported, ["fine", "also"]);
    assert_eq!(report.skipped.len(), 1, "{:?}", report.skipped);
    assert_eq!(report.skipped[0].name, "slow");
    let reason = &report.skipped[0].reason;
    assert!(
        reason.starts_with("ssh did not answer within 500 milliseconds, so this host was skipped."),
        "{reason}"
    );
    assert!(
        reason.contains("Match exec"),
        "the usual cause is named: {reason}"
    );
    assert!(
        report.hosts.get("slow").is_none(),
        "nothing of it was imported"
    );
    assert!(
        took < Duration::from_secs(5),
        "the import waited too long: {took:?}"
    );
}

#[test]
fn what_the_hanging_command_started_is_killed_and_does_not_pile_up() {
    let fixture = Fixture::new(&["a", "b", "c"], &["a", "b", "c"], None);
    let (report, _) = fixture.import(Duration::from_millis(300));
    assert_eq!(report.skipped.len(), 3);
    for name in ["a", "b", "c"] {
        let pid = fixture
            .started_for(name)
            .expect("the fake started its command");
        assert!(
            gone_soon(&pid),
            "the command started for {name} (pid {pid}) is still running"
        );
    }
}

#[test]
fn hosts_that_all_hang_cost_the_timeout_each_and_no_more() {
    // The worst case, said in numbers: every host misses its deadline, so the
    // import takes the timeout times the number of hosts, and no longer.
    let fixture = Fixture::new(&["a", "b", "c"], &["a", "b", "c"], None);
    let (report, took) = fixture.import(Duration::from_millis(400));
    assert!(report.imported.is_empty());
    assert_eq!(report.skipped.len(), 3);
    assert!(took >= Duration::from_millis(1200), "{took:?}");
    assert!(took < Duration::from_secs(6), "{took:?}");
}

#[test]
fn a_host_that_answers_slowly_but_in_time_is_imported() {
    let fixture = Fixture::new(&["patient"], &[], Some("1"));
    let (report, took) = fixture.import(Duration::from_secs(5));
    assert_eq!(report.imported, ["patient"]);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert!(took >= Duration::from_millis(900), "{took:?}");
}

#[test]
fn a_hang_is_not_confused_with_ssh_being_unavailable() {
    // Unavailable stops the whole import; a hang skips one host.
    let fixture = Fixture::new(&["slow"], &["slow"], None);
    let (report, _) = fixture.import(Duration::from_millis(300));
    assert_eq!(report.skipped.len(), 1);
    let missing = SystemSshResolver::new(Path::new("/nonexistent/ssh").to_path_buf())
        .with_timeout(Duration::from_millis(300));
    let result = import_hosts(&Hosts::new(), &fixture.source(), &missing);
    assert!(
        result.is_err(),
        "a program that cannot start still stops the import"
    );
}

#[test]
fn when_the_budget_runs_out_the_remaining_hosts_are_skipped_without_asking_ssh() {
    // Two hosts miss their own deadline, the third is cut by the budget, and the
    // other seventeen are not asked. The budget is two and a half deadlines, so
    // that the first two end by their own with half a deadline to spare, however
    // slow starting and ending a process is.
    let timeout = Duration::from_millis(600);
    let budget = Duration::from_millis(1500);
    let names: Vec<String> = (0..20).map(|n| format!("h{n}")).collect();
    let hosts: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = Fixture::new(&hosts, &hosts, None);
    let (report, took) = fixture.import_within(timeout, budget);

    assert!(report.imported.is_empty());
    assert_eq!(
        report.skipped.len(),
        names.len(),
        "every host is listed: {:?}",
        report.skipped
    );
    // The first ones missed their own deadline.
    for skipped in &report.skipped[..2] {
        assert!(
            skipped
                .reason
                .starts_with("ssh did not answer within 600 milliseconds"),
            "{skipped:?}"
        );
    }
    // The rest were not read, and that is what they are told.
    for skipped in &report.skipped[2..] {
        assert_eq!(skipped.reason, OUT_OF_TIME, "{skipped:?}");
    }
    // And ssh was not run for those at all.
    for late in &names[3..] {
        assert!(
            fixture.started_for(late).is_none(),
            "ssh was asked about {late} after the budget was spent"
        );
    }
    // Kept: it took about the budget (1.5 s), and not a deadline for each of the
    // twenty hosts (12 s). The bound is half of that, far from both.
    assert!(took < timeout * 20 / 2, "the budget was not kept: {took:?}");
}

#[test]
fn a_host_cut_short_by_the_budget_is_told_that_and_not_that_it_did_not_answer() {
    // Its own deadline is far off, the budget is near: what ended the wait is the
    // budget, and the host may have been fine.
    let far_off = Duration::from_secs(30);
    let fixture = Fixture::new(&["slow", "fine"], &["slow"], None);
    let (report, took) = fixture.import_within(far_off, Duration::from_millis(500));
    assert!(report.imported.is_empty(), "{:?}", report.imported);
    assert_eq!(report.skipped.len(), 2);
    assert_eq!(report.skipped[0].name, "slow");
    assert_eq!(report.skipped[0].reason, OUT_OF_TIME);
    assert_eq!(
        report.skipped[1].reason, OUT_OF_TIME,
        "a healthy host after it too"
    );
    // The wait ended at the budget (half a second) and not at the host's own
    // deadline (thirty seconds). The bound is half of the deadline: about thirty
    // times what it should take, and half of what waiting for the deadline would.
    assert!(took < far_off / 2, "{took:?}");
    let pid = fixture.started_for("slow").expect("it was started");
    assert!(
        gone_soon(&pid),
        "what was cut short is killed too (pid {pid})"
    );
}

#[test]
fn healthy_hosts_are_never_held_back_by_the_budget_however_many_there_are() {
    let names: Vec<String> = (0..60).map(|n| format!("host{n:02}")).collect();
    let hosts: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = Fixture::new(&hosts, &[], None);
    let (report, took) = fixture.import(RESOLVE_TIMEOUT);
    assert_eq!(report.imported.len(), 60);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert!(
        took < IMPORT_BUDGET / 2,
        "sixty healthy hosts took {took:?}"
    );
}

#[test]
fn the_budget_is_counted_from_the_first_host_and_not_from_when_the_resolver_was_made() {
    let fixture = Fixture::new(&["fine"], &[], None);
    let resolver = SystemSshResolver::new(fixture.ssh())
        .with_timeout(Duration::from_secs(5))
        .with_budget(Duration::from_millis(600));
    thread::sleep(Duration::from_millis(900));
    let (report, _) = fixture.run(&resolver);
    assert_eq!(report.imported, ["fine"], "{:?}", report.skipped);
}

#[test]
fn the_defaults_are_five_seconds_a_host_and_sixty_for_the_whole_import() {
    assert_eq!(RESOLVE_TIMEOUT, Duration::from_secs(5));
    assert_eq!(IMPORT_BUDGET, Duration::from_secs(60));
}
