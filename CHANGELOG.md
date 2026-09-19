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
  - A store that cannot be loaded does not stop the TUI: the first screen
    explains what is wrong, which line, and how to restore `hosts.toml.bak`.
  - Help screen, opened with `?` and closed with `?` or Esc.
  - `q` or Esc quit, Ctrl+C quits. A footer always lists the keys of the
    current screen.
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

- **Host library** (Block 4)
  - The host list: favorite marker, name, `user@hostname:port` (port only when
    set) and tags. Favorites come first, then names ignoring case. Arrows and
    `j`/`k`, Home/End and PageUp/PageDown move the selection, and a position
    indicator shows when the list does not fit. An empty store explains how to
    add the first host.
  - Fuzzy search with `/`, with no new dependency: letters may be spread out
    (`dbp` finds `db-prod`), prefixes and consecutive letters rank higher, and
    name matches outrank hostname and tag matches. Results are ranked, matched
    letters are shown in bold and underlined, and "no matches" is stated in
    words. Enter keeps the filter, Esc clears it.
  - `f` marks a host as a favorite and saves.
  - `a` adds and `e` edits a host in a form: name, hostname, user, port,
    identity file, tags and notes, then a collapsed Advanced section with jump
    host, local and remote port forwards and agent forwarding. Every field shows
    what it is for and an example, and is checked when you leave it. Saving is
    blocked while anything is invalid. The jump host is chosen from a list of the
    saved hosts that would be valid. Turning on agent forwarding shows a warning.
    A missing key file is reported after saving. Esc asks before discarding
    unsaved changes.
  - `d` deletes a host after its name is typed. A host that other hosts jump
    through is refused at once, with those hosts listed.
  - `c` shows the ssh command for the selected host and asks the terminal to copy
    it (OSC 52), which works over SSH. The command is always shown on screen too,
    and the message says "copy requested", because a terminal that does not
    support the request ignores it silently.
  - Warnings found when loading stay visible as a one-line summary; `w` lists
    them.
  - A failed save never loses anything: the list is left as it was, and a form
    keeps everything that was typed.
- **ssh command** (Block 4)
  - The arguments to spawn ssh with are built separately from the quoted text a
    person pastes, and the two cannot be confused (see Security).

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
- The arguments for ssh are one element per argument with no quoting, never go
  through a shell, and put the destination after `--`, so a hostname can never be
  read as an option. Values are checked again where they become arguments, in
  release builds too.
- The command shown for pasting is quoted for the user's shell (single quotes on
  Unix, double quotes on Windows). On Windows, values that a shell would still
  expand inside quotes (`%`, `$`, `!`, the backtick, and a double quote) are not
  shown at all rather than shown unsafely.
- The clipboard request is write-only, carries the text base64-encoded so it
  cannot end the escape sequence early, and is never sent for text containing
  control characters. Bifrost never reads the clipboard.
- Deleting a host requires typing its name exactly, and a host that others jump
  through cannot be deleted.
