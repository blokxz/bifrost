# Changelog

All notable changes to Bifrost are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Command line** (Block 1)
  - `bifrost` opens the TUI, `bifrost <host>` connects directly (not implemented
    yet) and `bifrost list` prints the saved hosts.
  - Host arguments that look like ssh options (for example `-oProxyCommand=...`)
    are rejected.
  - CI on Linux and Windows: formatting, clippy with warnings denied, and tests.
- **Host model and validation** (Block 2)
  - Hosts with name, hostname, user, port, identity file, jump host, agent
    forwarding, favorite flag, tags, notes and local/remote port forwards.
  - Every field is validated; a collection of hosts is always internally
    consistent (unique names, existing jump hosts, no jump loops, chains of at
    most 5 hops).
  - A host that other hosts jump through cannot be deleted, and renaming it
    updates the references.
- **Store** (Block 2)
  - A single TOML file, `hosts.toml` with `version = 1`, in the platform's
    config directory. `BIFROST_CONFIG_DIR` overrides the location.
  - Atomic writes with the previous version kept as `hosts.toml.bak`.
  - A file that is invalid, or written by a newer Bifrost, is reported with its
    location and how to recover, and is never overwritten.
  - Warnings for files or directories that other users can access (Unix) and
    for identity files that do not exist.
- **ssh integration** (Block 2)
  - Resolution of the `ssh` binary to an absolute path, ignoring empty and
    relative `PATH` entries.
  - Import from the user's ssh config: hosts are found by a minimal scan
    (following `Include`) and resolved with `ssh -G`. Invalid hosts are
    skipped and reported; existing hosts are never overwritten.
  - Export to `~/.ssh/bifrost_config`, which Bifrost owns. It never edits
    `~/.ssh/config`.
- **Terminal interface** (Block 3)
  - A synchronous, single-threaded TUI built on ratatui and crossterm.
  - Home screen with the number of saved hosts. A store that cannot be loaded
    does not stop the TUI: the home screen explains what is wrong, which line,
    and how to restore `hosts.toml.bak`.
  - Help screen, opened with `?` and closed with `?` or Esc.
  - Keys: arrows and `j`/`k` scroll, `?` help, `q` or Esc quit, Ctrl+C quits.
    A footer always lists the keys of the current screen.
  - A short message instead of a broken layout when the terminal is smaller
    than 60x15.
  - Colors from the terminal's 16 ANSI colors; `NO_COLOR` is respected. Errors
    and warnings carry a text label, so color is never the only signal.
  - The terminal is restored on every exit path, including panics, and the
    terminal guard can hand the terminal over and take it back (used by
    connecting in a later release).
  - `bifrost list` prints the saved host names to stdout, one per line. Load
    warnings and the message for an empty store go to stderr, so the output is
    safe to pipe.
  - Store errors have clear English messages and a non-zero exit code.
  - Starting the TUI without an interactive terminal fails with a message that
    points to `bifrost list`.

### Security

- Bifrost stores no secrets: only paths to key files, never passwords,
  passphrases or key material.
- Files and directories are user-only (0600 and 0700) on Unix.
- Processes are spawned with an argument vector, never through a shell.
- Exported values are quoted and escaped so they cannot inject ssh directives.
- All external text shown in the TUI or printed by the CLI (host names, file
  contents quoted in errors, ssh output) is sanitized. C0 and C1 control
  characters, DEL, ESC and Unicode bidirectional controls are replaced with `?`,
  and the footer says when characters were hidden.
- Error messages built by the library escape the same set of characters,
  including bidirectional controls, so a right-to-left override in a host name
  cannot reorder the text of a message.
