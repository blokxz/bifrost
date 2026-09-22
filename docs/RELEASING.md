# Releasing Bifrost

This file is the release checklist. The **gates** below are binding from now on;
the exact command sequence (tag, push, verify the release, publish the crate) is
added to it at the end of Block 7.

## The rule

A sentence in `README.md`, `SECURITY.md` or `docs/DECISIONS.md` that is only true
after something has been done gets a row in the table below **on the day it is
written**, and that row stays until the thing has been done and checked. Nothing is
tagged while a row is open. When a row closes, the wording of the sentence is
changed to the stronger claim in the same commit as the check.

Until a row is closed, the document says only what is true now.

## Gates before tagging 0.1.0

| # | The claim, and where it is | Only true after | How to check | Wording now, and after |
|---|---|---|---|---|
| 1 | **Windows** (README, "Platform status") | You run the Windows part of `docs/manual-tests.md` on the physical Windows machine, with the real `ssh.exe`, and each step passes or its failure is recorded as a known limitation | The results of every step in the "Windows" section, written down. Anything that failed is fixed or listed under "Known limitations" in `docs/DECISIONS.md` and in the README | Now: "Builds and passes the automated tests in CI; manual testing pending." After: "Tested by hand on Windows." (and keep a pointer to the steps not run, if any) |
| 2 | **macOS** (README, "Platform status") says "Covered by CI only" | The `macos-latest` job is green on the commit that is tagged, **with the pseudo-terminal suites (`pty`, `pty_connect`, `pty_keys`, `pty_sshconfig`) run and passing, not skipped**. They are the only test of Bifrost's terminal handling on macOS: raw mode, the alternate screen, resizes, what happens when ssh takes the terminal | The CI run of that exact commit: open the macOS job's log and read the result line of each of those four suites | Stays as it is: nobody has used Bifrost on a Mac by hand. If the pty suites are ever limited to Linux, the README row must say that terminal behaviour on macOS is not tested |
| 3 | **Linux tested by hand against a real server** (README) | The ignored real-server tests and the "Against a real server" steps of `docs/manual-tests.md` pass against the Incus container on the commit that is tagged. They were last run before Block 7 changed the path code | Run them; note the commit | Stays as it is |
| 4 | **Checksums and provenance** (README "Prebuilt binary", SECURITY.md "Releases") | The release workflow has run on a tag, for real. Do this with a `v0.1.0-rc.1` tag first: it makes a draft that is deleted afterwards | Download the draft's files and run the commands from the README: `sha256sum -c SHA256SUMS --ignore-missing` and `gh attestation verify <archive> --repo blokxz/bifrost` | Until then the sentences describe what the workflow is meant to do |
| 5 | **Archive names** (README table) | They are exactly what the workflow uploads | Compare the table with the rc draft's asset names | Fix whichever is wrong |
| 6 | **"static, any distribution"** for the Linux archive (README) | The musl binary from the rc draft runs on an old and a new distribution container with no libc of its own to depend on | `file bifrost` says "statically linked"; `ldd bifrost` says "not a dynamic executable"; run `bifrost --version` in an old Debian and a current Fedora container | If it does not hold, change the README to say what does |
| 7 | **macOS quarantine advice** (README, `xattr -d com.apple.quarantine`) | Someone has downloaded the macOS archive on a Mac and needed it | Try it on a Mac. If nobody can, keep the sentence but say it is the usual macOS remedy and has not been tried on Bifrost | Soften if untried |
| 8 | **`cargo install bifrost-ssh --locked`** (README) | The crate is published | After publishing, in a clean container with Rust 1.88: `cargo install bifrost-ssh --locked && bifrost --version` | Until published, nothing links to it |
| 9 | **CI claims** (SECURITY.md: every action pinned by full hash, `cargo deny` in CI; README: tests run on Linux, Windows and macOS) | The CI workflows on `main` really do it, and every job is green. The `Dependencies` workflow has **never been run**: it uses `EmbarkStudios/cargo-deny-action`, which needs Docker, and there is none on the development machine. Its `rust-version: stable` setting is a guess until it runs | The Actions tab on the tagged commit: `CI` (Linux, Windows, macOS, minimum Rust version, linux musl, pty x20, pty tests with long paths, actions are pinned) and `Dependencies`. Also `sh .github/scripts/check-pins.sh` and `cargo deny --locked check` locally | Keep in step with the workflows. If the action fails for a reason of its own, fix it or replace it (see DECISIONS.md, "a known weakness of the cargo-deny action") before tagging |
| 10 | **Private vulnerability reporting** (SECURITY.md) | Enabled in the repository settings (done) | Open `https://github.com/blokxz/bifrost/security/advisories/new` while logged out of the owner account: the form opens | |
| 11 | **The crate name** `bifrost-ssh` is free | Nobody registered it in the meantime | `curl -s -o /dev/null -w '%{http_code}\n' https://crates.io/api/v1/crates/bifrost-ssh` prints 404 just before publishing | |
| 12 | **The changelog date** | You fill in the `[0.1.0]` heading of `CHANGELOG.md` | The heading has a real date and not the placeholder | |

## Before every release

- `cargo fmt --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo clippy --locked --all-targets --target x86_64-pc-windows-gnu -- -D warnings`
- `cargo test --locked`, run by you in a real terminal
- CI green on the commit to be tagged, on all of its jobs
