# Changelog

All notable changes to Bifrost are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-22

### Added

- **Command line** (Block 1)
  - `bifrost` opens the TUI, `bifrost <host>` connects directly and `bifrost list`
    prints the saved hosts.
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

- **Connecting** (Block 5)
  - Enter on a host runs `ssh` for it, with the jump chain if it has one, and
    returns to the list afterwards. The terminal is handed over completely:
    ssh runs on the normal screen, Bifrost draws nothing and reads no input while
    it does, and everything ssh prints stays in the scrollback. The result is
    shown on the list ("Disconnected from 'web'.", "The connection to 'web' was
    cancelled.").
  - The terminal comes back correctly on every way ssh can end: a clean exit, a
    failed remote command, a connection failure, Ctrl-C, being killed while in
    raw mode, and a resize during the session.
  - Ctrl-C while ssh has the terminal (a password prompt, a hanging connection)
    ends ssh and returns to the list instead of quitting Bifrost. A SIGINT sent to
    Bifrost itself quits it cleanly, like Ctrl+C in the interface.
  - A status that is not 255 is the remote session's own exit status, not a
    connection error.
  - Everything ssh writes to stderr is still shown live, and its last 64 KiB are
    kept.
  - A failed connection gets a screen of its own that says what happened in plain
    English and what to try next: login refused (permission denied), the
    server's identity changed or was not accepted, connection refused, timed out,
    host name not found, network unreachable, closed by the server, and a broken
    connection. A failure Bifrost does not recognize gets a generic message and
    quotes the end of ssh's own output. Failures through a jump host are
    explained by the jump host's own error.
  - `o` shows everything ssh printed during the last connection, cleaned of
    control characters, from the failure screen or from the list. Enter or Esc
    leave the failure screen.
  - What is not a failure is one line on the list: a normal logout, the remote
    command's exit status, Ctrl-C, closing with `~.`.
  - When a server's key is not the one saved, a blocking screen says so: this
    may be a reinstalled server or someone intercepting the connection, with the
    fingerprint of the key received, where the old key is kept and how to check
    the fingerprint on the server. Enter or Esc abort, which is the default, and
    almost no other key does anything.
  - From that screen `r` removes the old key, after the host's name is typed
    exactly. Bifrost never edits `known_hosts` itself: it runs `ssh-keygen -R`,
    which keeps the previous file as `known_hosts.old`. The next connection then
    shows the new key for the user to accept. If the changed key is a jump host's,
    the name to type is the jump host's.
  - Removal is offered only when ssh's message can be tied to a host Bifrost
    connected through and to the default `known_hosts`. Otherwise the screen says
    Bifrost will not remove a key there.
- **Command line** (Block 5)
  - `bifrost <host>` connects without opening the interface and exits with ssh's
    status, or the remote command's, unchanged. A process ended by a signal is
    `128 + signal`, and Ctrl-C is 130. A connection failure is explained on stderr
    after ssh's own messages, and for a changed key the command to remove the old
    key is printed, never run.
  - When Bifrost itself cannot connect (the host is not saved, the saved hosts
    cannot be read, ssh is not installed) it exits with 2, and says so on stderr
    with `bifrost: error:`. An unknown host lists the closest saved names. This
    is documented at the end of `--help`.
  - `ssh` and `ssh-keygen` are resolved to absolute paths, when the interface
    opens or when connecting. When ssh is missing, the list still works and
    connecting explains what to install.

- **Keys and the ssh config** (Block 6): the keys screen (`K`), making, adding and
  sending keys, choosing a host's key from a list, and the ssh config screen (`s`).
  - **Keys screen.** `K` on the host list shows the key pairs in `~/.ssh` (a private key with a
    `.pub` next to it): name, type and size, whether the agent holds it, and
    whether its permissions are ones ssh accepts. The selected key's fingerprint,
    comment and paths are shown below the list.
  - Type, size, fingerprint and comment come from `ssh-keygen -l -f` run on the
    public file. Bifrost never reads a private key.
  - The agent is asked with `ssh-add -l`, waiting at most 3 seconds. An agent that
    is not running is a normal state and is explained, not reported as an error;
    keys are then neither "loaded" nor "not loaded" but "unknown".
  - On Linux and macOS a private key that other users can read is flagged in
    words, and `f` sets it to 0600 after a yes/no question. It is not offered for
    a symbolic link. Only the private file of a key pair in `~/.ssh` can be
    changed. On Windows permissions are not checked.
  - Bifrost never overwrites a key. It deletes one only when asked to, as described
    under **Deleting a key** below.
  - `g` makes a new ed25519 key. A small form asks for the file name (one that is
    free is suggested) and an optional comment, and says beforehand that
    `ssh-keygen` will ask for a passphrase and that Bifrost never sees it. Then the
    interface steps aside and `ssh-keygen` runs on the real terminal, where it asks
    for the passphrase itself. Back on the keys screen, the new key is listed and
    selected. A name that is already a key, or a file that exists in `~/.ssh` under
    that name or `name.pub`, is refused.
  - `a` adds the selected key to the agent with `ssh-add`, the same way. It is not
    tried when it cannot work and says why instead: the key is already loaded, its
    permissions are too open (`f` fixes them), or there is no agent to add it to.
  - Ctrl-C at either passphrase prompt cancels that action and Bifrost goes on. A
    failure says what the tool said last.
  - `c` sends the selected key's public key to a saved host, without
    `ssh-copy-id`. A list of the saved hosts (in the order of the host list) is
    followed by a question that names the key, its fingerprint and the host,
    because this lets whoever has the private key log in there. Then ssh runs on
    the real terminal, where it asks for the password and for a new server's key
    itself. The key is added to `~/.ssh/authorized_keys` on the server, and not a
    second time if it is already there.
  - How it ended is judged like a connection: ssh's own failures are explained on
    the same screens, a changed host key stops on the blocking screen, and going
    back returns to the keys screen. A command that the server ran and that
    failed (any other status) is said to be that, with what the server said last.
  - **Deleting a key.** `D` (a capital, like `K`; a plain `d` does nothing) on the
    keys screen asks to delete the selected key. The question first lists the saved
    hosts that have the key as their identity file, and says plainly that Bifrost
    cannot know which servers have the key in their `authorized_keys`, and that
    deleting it means losing access to them until another key is installed. The
    key's exact name has to be typed and confirmed with Enter (case, spaces and
    prefixes all count); Esc gives up. It is still allowed when hosts use the key:
    the user sees them and decides. Only the private file and its `.pub` are
    removed, the private one first, and only for a real key pair in the ssh
    directory: never `config`, `known_hosts` or another file that ssh reads, a
    lone `.pub`, a folder, or a name that is not one plain file name. A key that is
    a symbolic link is removed as a link and the file it points to stays, which the
    question says. The saved hosts are not changed; afterwards the message names those
    that still point at the deleted key, and the keys are read again. If the agent
    holds the key, the question says it keeps holding it (`ssh-add -d` removes it).
    Nothing is overwritten or securely erased: the files are unlinked.
  - **Using a key after sending it.** Once a key was sent, Bifrost asks: use this
    key for that host from now on? `y` sets the host's identity file to
    `~/.ssh/<name>` and saves it like any other change, and the message on the keys
    screen says so; `n` or Esc changes nothing. Only plain `y` answers yes. It is
    not asked when the host already uses that key (however the path is written), when
    the send did not succeed, or when the path would not be one a host may have. If
    the host has another key file, the question says which one it replaces.
  - **Choosing the identity file.** In the add and edit form, Enter on the Identity
    file field opens a list, chosen like the jump host is: "(none)" (ssh uses its
    default keys), each key found in `~/.ssh` with its type, and "Another file"
    for a key that is elsewhere, which goes back to the box to type the path. Typing a
    path directly still works, and a path already typed is kept and shown on the
    "Another file" line. What is stored is the path, `~/.ssh/<name>`, as before. The
    list reads names and types only: it does not ask the agent, so it opens at once
    even when a forwarded agent is stuck. With no keys it says how to make one
    (`K`, then `g`).

- **SSH config screen** (Block 6)
  - `s` on the host list opens a screen with two things to do.
  - **Import** (`i`) reads `~/.ssh/config` and the files it includes, and shows what
    importing it would do before anything is saved: the hosts that would be added
    (with user, address, port, jump host and key), the ones already in Bifrost
    that are left as they are, the ones skipped and why, and every warning
    (a dropped `ProxyCommand`, dropped forwards, a dropped `.pub` identity, a key
    file that does not exist). Only `y` imports; `n` and Esc cancel. What is
    saved is exactly the set that was shown, with the previous version kept as
    `hosts.toml.bak`. If saving fails nothing changes and the preview stays. After
    saving, the page says what was imported and what was left out.
  - **Export** (`e`) says how many hosts will be written and where
    (`~/.ssh/bifrost_config`), whether the file is new or is one Bifrost made and
    will replace, and asks. A file that Bifrost did not make is never offered for
    writing. After writing it shows what is left to do: the exact line to add to
    your `~/.ssh/config` (`Include ~/.ssh/bifrost_config`) on a line of its own,
    or that it is already there, or, if the line is there but after a `Host` or
    `Match` line, where ssh would only use it for that block, that it has to move
    to the top. Bifrost never edits or creates your `~/.ssh/config`.
  - Problems are said in plain English on the screen, and everything from outside
    (host names, what ssh said about a host, warnings, paths) is cleaned before it
    is drawn.
  - **A `Match exec` that hangs cannot freeze the import for good.** Each `ssh -G`
    is given 5 seconds. A host that does not answer in time is skipped with the
    reason and listed under Skipped in the preview, like any other host ssh could not
    resolve, and the command that hung is killed with it (on Unix, its whole
    process group).
  - **The whole import has a budget of 60 seconds.** When it is spent, the hosts not
    yet read are skipped without running ssh for them, with the reason "the import
    was taking too long, so the remaining hosts were not read; check for a Match exec
    command in your ssh config that does not finish, then try again." Healthy hosts
    are never held back however many there are. In the preview, hosts skipped for the
    same reason are shown as one entry.
- **Release preparation** (Block 7)
  - Licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
  - `README.md` for beginners: install, first steps, the keys of every screen, the
    command line and its exit status, where files live, what Bifrost never does,
    the known limitations and the status of each platform.
  - `SECURITY.md`: how to report a vulnerability privately, what is in scope, and
    the security model in short.
  - Package metadata for crates.io, and the files that are published: the source,
    the lock file and the documents, and neither the integration tests, their
    fixtures nor anything from the repository's tooling.
  - The minimum supported Rust version is 1.88, checked by building and running the
    whole test suite with exactly that compiler.
  - CI: macOS joins Linux and Windows; the minimum Rust version, the static musl
    target, the pseudo-terminal repeats and the pseudo-terminal tests with long
    temporary paths (as on macOS) have jobs of their own; every `cargo test` runs
    with `--no-fail-fast`; and every workflow starts with no permissions and gives
    each job only `contents: read`.
  - `cargo deny` (`deny.toml`, `.github/workflows/deny.yml`) checks advisories,
    yanked releases, licenses, bans and sources on every push and pull request, and
    every week. Only permissive licenses are allowed.
  - Every action is pinned to a full commit hash with its version in a comment, a
    script fails CI on any that is not, and Dependabot proposes updates weekly.
  - `.github/workflows/release.yml`: pushing a version tag is checked against
    Cargo.toml's version and the changelog before anything is built, then builds
    a binary for each of the four released platforms (Linux musl, macOS on both
    architectures, Windows msvc; `x86_64-apple-darwin` cross-built, since GitHub
    retired its Intel macOS runners), smoke-tests each with `--version`, packages
    it with the README and both licenses, checksums every archive together into
    `SHA256SUMS` and verifies the file against them, attests where each archive
    was built from, and opens a draft release with all of it attached. Nothing is
    published automatically; the draft is reviewed and published by hand.

### Changed

- **Every decision Bifrost takes from the words of a path goes through one module
  (`pathtext`), on text, with the rules of Windows and of the others as an argument,
  and both sets are tested on every system.** It replaces four separate
  comparisons: which saved key is a key on disk, which file ssh named as holding the
  old host key, which `Include` reaches the exported file, and which identity files
  ssh adds by default. What changes for the user:
  - A path with `..` in it is never taken for the default `known_hosts`, so removing
    a changed host key is never offered for a file that only might be that one. On
    Unix, `//` and `/./` in the path ssh printed no longer make it a different file.
  - `~\` is the home directory only on Windows; on Unix it is an ordinary name.

### Fixed

- **A connection that Windows' ssh drops during the handshake is explained as an
  interrupted connection, not as an unknown failure.** Windows OpenSSH prints
  "Unknown error" where Linux and macOS name the reset or the close, so three
  real failures reached the generic screen. The stage ssh names
  (`kex_exchange_identification`, `banner exchange`, `ssh_dispatch_run_fatal`)
  now decides, never the words after it; the lines Windows really printed are
  test fixtures.
- **The exported file no longer invites the user to break their ssh setup.** Its
  header showed the `Include` line commented out; uncommenting it there makes
  `bifrost_config` include itself, and ssh then refuses to start with "Too many
  recursive configuration includes". The comment now says plainly that the line
  belongs in `~/.ssh/config` and must never be uncommented in that file.
- **The export screen says which file the `Include` line goes in.** Both files
  live in `~/.ssh` and are easy to mix up, so it now names `config` and says it
  is not `bifrost_config`. On Windows it also offers a PowerShell command that
  adds the line without replacing an existing config and writes ASCII, because
  PowerShell's own `>` and `echo` write UTF-16, which ssh cannot read.
- **A config whose `Include`s loop is reported instead of passing as healthy.**
  Bifrost's scan survives a loop, so a config that ssh itself refuses could be
  reported as "already includes it, nothing more to do". A file that includes
  itself, directly or through other files, is now a warning on the export
  screen whatever the include status is, and on the import preview too.
- **Input typed during a handover (a connection, sending a key, generating a
  key, adding a key) that ssh or the tool never read is discarded reliably,
  including on macOS.** Taking the terminal back only drained whatever
  crossterm's own `poll`/`read` found ready; a key typed without a following
  newline can sit in the terminal's canonical-mode queue in a way POSIX leaves
  undefined across the switch back to raw mode, so it could still surface
  afterwards and run as a Bifrost command (for example quitting). The terminal's
  input queue is now flushed directly (`tcflush`) as part of taking it back.
- **A host's key file is recognized on Windows.** The identity file list, the
  "use this key?" question after sending a key, and the list of hosts shown before
  a key is deleted compared paths as text, so `/` and `\` made one key look like
  two. They now compare the parts of the path, in one place, and on Windows ignore
  the kind of slash and the case.

### Security

- The commands that Bifrost waits for without being able to interrupt them have a
  deadline and are killed with what they started when they miss it: `ssh-add -l`
  (3 seconds), each `ssh -G` of an import (5 seconds, which runs the user's
  `Match exec` commands) and the import as a whole (60 seconds). A hung command
  cannot pile up or hold the output open, and the interface cannot be kept waiting
  for more than a minute by one.
- Deleting a key is the one way Bifrost removes a key, and it is guarded three ways:
  a capital `D`, the key's exact name typed, and a check, made again where the files
  are removed and not only on the screen, that the name is one plain file name of
  a key pair (both files present, not reserved, not a `.pub`) in the ssh directory.
  The request carries a name, never a path. Links are unlinked, never followed.
  Nothing else in the folder is touched.
- Choosing a key for a host never offers a path that the form would refuse (one
  that ends in `.pub`, has control characters and so on), and the question after
  sending a key changes nothing until a plain `y`. Names from the ssh directory
  are cleaned before they are drawn, and the footer says when something was hidden.
- The ssh config screen writes nothing until a plain `y`, and never touches the
  user's own `~/.ssh/config`: the check for the `Include` line is read-only and
  reuses the scan that import already trusts. Importing shows exactly what it
  will save and saves that set, through the same atomic, backed-up write as every
  other change. Exporting refuses a file that Bifrost did not generate, and says
  so before asking.
- Removing a host key is an explicit action confirmed by typing the host's name,
  runs `ssh-keygen -R` with an argument vector and no shell, and only for a name
  that Bifrost itself asked ssh to connect through and only in the default
  `known_hosts`. What ssh prints (a host name, a file) can decide which message is
  shown but never what is removed or from where: a path taken from ssh's output
  is never passed to `ssh-keygen`. The entry is checked again before it is run.
- ssh's output is treated as untrusted. A server can print text before login, on
  the same stream as ssh's own messages, so only exit status 255 is explained as a
  connection failure, the decision rests on the last line ssh printed, and a
  line with control or bidirectional characters is never taken for ssh's own.
  The explanations are fixed text that names only the saved host, so nothing from
  ssh's output can reach them.
- While ssh runs, Ctrl-C reaching Bifrost is caught rather than fatal, but ssh
  keeps its default behavior for it. Terminal modes are saved before ssh runs and
  restored after it, so an ssh that is killed in raw mode cannot leave the shell
  raw. Input typed during a connection that ssh did not read is discarded, so it
  cannot run as commands afterwards. ssh is killed if Bifrost fails while it
  runs.
- Making a key and adding one to the agent never put a passphrase in a command
  line, an environment variable or Bifrost's memory: `ssh-keygen` and `ssh-add`
  ask for it on the terminal themselves. `ssh-keygen` is never given `-N`.
  What they are given is checked again just before they run: a file name of one
  plain path component that cannot be read as an option, a comment without
  control characters, and the key's absolute path.
- Sending a public key never puts the key on a command line. It is written to
  ssh's stdin, and what runs on the server is one fixed command that holds no
  user data (the key is read by its script from stdin into a quoted variable).
  Before that the file is checked to be exactly one line that starts with a real
  key type, with no control characters: a private key, several keys, or a line
  with `command="..."` options in front of the key are never sent. The check is
  repeated where the bytes are made, and the arguments are checked to be the ones
  for sending a key before the key is attached to ssh, because with any others
  ssh could start a shell on the server and read the key as commands. Port
  forwards and agent forwarding are not requested for it, even if the host has
  them or the user's ssh config asks for them.
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
