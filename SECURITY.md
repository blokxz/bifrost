# Security policy

## Reporting a vulnerability

Please report security problems **privately**, using GitHub's private vulnerability
reporting:

**<https://github.com/blokxz/bifrost/security/advisories/new>**

Do not open a public issue, pull request or discussion for a vulnerability, and do
not post details anywhere public before a fix is out.

Please include what you can of:

- the version (`bifrost --version`) and your system, and the OpenSSH version
  (`ssh -V`);
- what you did, what you expected and what happened, with the smallest example that
  shows it (a host definition, an ssh config, the output of a fake ssh);
- what an attacker gains: which file, command or screen is affected.

Bifrost is maintained by one person, in their own time. What you can expect is
**best effort, with an acknowledgement within 14 days**. I will tell you whether I
consider it a vulnerability, work on a fix with you, agree a date for publishing
the advisory, and credit you in it unless you prefer not to be named. There is no
bug bounty.

## Supported versions

Only the latest release receives security fixes. While Bifrost is at 0.1.x, that
means the latest 0.1.x.

## What is in scope

Anything where Bifrost lets data it did not mean to trust cause harm, or weakens
what it promises. For example:

- **Command or argument injection** into `ssh`, `ssh-keygen`, `ssh-add`, or the
  command sent to a server when a public key is added: a host name, user, key path,
  imported value or ssh output that ends up interpreted as an option or a command.
- **Injection into the exported file** (`~/.ssh/bifrost_config`): a value that
  escapes its quotes and adds an ssh directive such as `ProxyCommand`.
- **Terminal escape injection**: host names, notes, imported data, key comments or
  ssh output that reach the screen without control and bidirectional characters
  being cleaned.
- **Writing or deleting the wrong file**: editing your `~/.ssh/config` or
  `known_hosts` on its own, replacing a file that Bifrost did not make, following a
  symbolic link when changing or deleting a key, overwriting a key.
- **A wrong yes about which file or host to change**: offering to remove a
  `known_hosts` entry for a file or host that is not the one ssh reported.
- **Leaking or storing secrets**: a password, passphrase or private key material in
  a file Bifrost writes, in a command line, in an error message or on screen.
- **Files that are too open**: Bifrost's own files or a key it creates being
  readable by other users on Linux or macOS.
- **Anything that turns host key checking off** or makes it easier to bypass.
- **Supply chain**: a way to make a release artifact, or the published crate,
  differ from what the release workflow builds from the tagged commit.

## What is not in scope

- Vulnerabilities in OpenSSH, in your ssh server, or in your terminal emulator. Please
  report those to their projects. If Bifrost makes one easier to trigger, that part
  is in scope.
- Problems that need an attacker who already controls your account or can already
  change your files (for example, editing your own `hosts.toml` or `~/.ssh/config`).
  Data that Bifrost *reads* from those files is still in scope, as above.
- What the [known limitations](docs/DECISIONS.md) already say: for example that
  Bifrost does not verify Windows file permissions, that a jump host's key is not
  passed to ssh for its hop, or that OSC 52 copying depends on your terminal. A way
  to make one of these worse than documented is in scope.
- Vulnerabilities in a dependency that Bifrost does not reach. The dependencies are
  checked in CI (`cargo deny`, including RustSec advisories); if you found one that
  Bifrost does reach, that is in scope.
- Denial of service that only slows or crashes your own Bifrost, such as a very large
  `hosts.toml` that you wrote.
- Unsigned macOS binaries triggering Gatekeeper: this is documented in the README.

## The security model in short

- **No secrets.** Bifrost stores paths to key files, never key material, passwords or
  passphrases. ssh asks for those itself, on the terminal.
- **Local programs are started directly**, with an argument vector, never through a
  shell. The destination comes after `--`, and the remote user is passed with `-l`.
- **Every field is validated** before it can reach ssh or a file: no leading `-`, no
  control characters, limited lengths and character sets, and ports in range. There
  is no free-form ssh options field and no `ProxyCommand` or `LocalCommand`.
- **Exported values are quoted and escaped**, and the escaping keeps its own runtime
  check in release builds, not only in tests.
- **Your files are yours.** Bifrost never edits `~/.ssh/config` or `known_hosts` on
  its own. Removing a changed host key is a separate action that you confirm by
  typing the host name. A key file is changed only by `chmod 0600` after you confirm,
  never through a symbolic link, and a key is never overwritten.
- **Host key checking is never turned off.**
- **Bifrost's own files** are private to your user (`0600` files, `0700` folder) on
  Linux and macOS, written atomically with a backup of the previous version.
- **Everything from outside is cleaned** (control and bidirectional characters)
  before it is drawn.
- **Releases** are built by a GitHub Actions workflow from a version tag, with every
  action pinned to a full commit hash. Each archive has a SHA-256 checksum and a
  build provenance attestation, and CI checks dependencies with `cargo deny`.

The reasoning behind each of these, and the limits Bifrost has today, are in
[docs/DECISIONS.md](docs/DECISIONS.md).
