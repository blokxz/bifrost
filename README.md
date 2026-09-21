# Bifrost

A friendly terminal interface for `ssh`. Bifrost keeps your connections, keys,
jump hosts and port forwards in one place, so that you do not have to remember
long commands or hunt through `~/.ssh` to reach a server.

It does not replace ssh and it does not reimplement it. Every connection is the
real `ssh` from your system, started with exactly the arguments Bifrost shows you.
What Bifrost adds is a list you can search, forms that check what you type, and
screens for the parts of ssh that beginners find hard: keys, the agent, and host
key warnings.

**Who it is for:** people who use ssh but do not want to memorize its options:
students, home-lab owners, developers who reach a handful of servers. If you have
a huge fleet and a finely tuned `~/.ssh/config`, plain ssh is already what you want.

```
┌ Bifrost 0.1.0 ───────────────────────────────────────────────────────────────┐
│ Saved hosts: 5                                                               │
│     Name       Target                       Tags                             │
│ > * web-prod   deploy@web.example.com:2222  #prod #web                       │
│     bastion    jump@bastion.example.com                                      │
│     db-prod    admin@10.0.0.5               #prod                            │
│     raspberry  pi@192.168.1.50                                               │
│     staging    staging.example.com                                           │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
Up/Down j/k move  Enter connect  / search  a add  e edit  d delete  f favorite
c copy  K keys  s ssh config  ? help  q/Esc quit
```

`>` is the selection and `*` marks a favorite. Enter connects; the terminal is
handed to ssh, and when you log out you are back in the list. (The screen above is
shortened; it is what Bifrost draws.)

## Install

Bifrost needs the OpenSSH client programs `ssh`, `ssh-keygen` and `ssh-add`. Most
Linux and macOS systems have them. On Windows 10 and 11, turn on the optional
feature "OpenSSH Client" (Settings, Apps, Optional features).

### Prebuilt binary

Download the archive for your system from the
[Releases page](https://github.com/blokxz/bifrost/releases), unpack it, and put
`bifrost` (`bifrost.exe` on Windows) somewhere on your `PATH`.

| System | Archive |
|---|---|
| Linux, x86_64 (static, any distribution) | `bifrost-<version>-x86_64-unknown-linux-musl.tar.gz` |
| macOS, Apple silicon | `bifrost-<version>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `bifrost-<version>-x86_64-apple-darwin.tar.gz` |
| Windows, x86_64 | `bifrost-<version>-x86_64-pc-windows-msvc.zip` |

Every release has a `SHA256SUMS` file, and every archive has a build provenance
attestation that says which workflow, on which commit, built it. To check what you
downloaded:

```sh
# Linux: compares the archives that are in the folder
sha256sum -c SHA256SUMS --ignore-missing
# macOS: print the hash and find the same line in SHA256SUMS
shasum -a 256 bifrost-<version>-aarch64-apple-darwin.tar.gz
# Windows (PowerShell): the same
Get-FileHash .\bifrost-<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256

# Any system with the GitHub CLI: was it built by this repository's release workflow?
gh attestation verify bifrost-<version>-x86_64-unknown-linux-musl.tar.gz --repo blokxz/bifrost
```

The macOS binaries are not signed by Apple. If macOS refuses to open a downloaded
one, run `xattr -d com.apple.quarantine ./bifrost` once, or install with cargo
instead.

### With cargo

```sh
cargo install bifrost-ssh --locked
```

This needs Rust 1.88 or newer. The package is called `bifrost-ssh`; the program it
installs is called `bifrost`. `--locked` builds with the exact dependency versions
that were tested.

## First steps

Run `bifrost`. Press `?` at any time to see every key for the screen you are on.

1. **Add a host.** Press `a`. Fill in a name (any short label, like `web-prod`) and
   the host name or IP address; user and port are optional. Move with Tab and save
   with Ctrl+S. Each field is checked when you leave it, and the form tells you
   what is wrong in plain words.
2. **Connect.** Select the host and press Enter. If ssh asks for a password or for
   you to trust a new host, that is ssh talking: answer as you always do.
3. **Make a key.** Press `K` for the keys screen, then `g`. Give the key a name.
   Bifrost makes an ed25519 key with `ssh-keygen`, which asks for a passphrase
   itself. Bifrost never sees it. Press `a` on a key to add it to the ssh agent.
4. **Send the key to a server.** On the keys screen, select the key and press `c`,
   choose a host and confirm. Bifrost adds the public key to that server's
   `~/.ssh/authorized_keys`; ssh asks for your password once. Afterwards Bifrost
   offers to use the key for that host from then on.
5. **Connect without a password.** Back in the list, press Enter on the host.

Already have hosts in `~/.ssh/config`? Press `s`, then `i` to see which of them
Bifrost can import. Nothing is saved until you confirm. To use your Bifrost hosts
from plain `ssh` too, press `s`, then `e`: Bifrost writes a separate file and shows
you the one line to add to your own config. It never edits that file.

## Keys on every screen

`?` opens the full list inside Bifrost. Ctrl+C quits from anywhere.

**Host list**

| Key | Does |
|---|---|
| Up/Down, `j`/`k` | Move the selection (PgUp/PgDn, Home/End also work) |
| Enter | Connect to the selected host |
| `/` | Search by name, host name or tag. Letters can be spread out: `dbp` finds `db-prod` |
| `a`, `e` | Add a host, edit the selected one |
| `d` | Delete the selected host, after you type its name |
| `f` | Mark or unmark a favorite |
| `c` | Show the ssh command for the host and ask the terminal to copy it |
| `K` | Keys screen |
| `s` | ssh config screen (import and export) |
| `o` | Read what ssh printed during the last connection |
| `w` | Read the warnings found when your hosts were loaded |
| `?` | Help |
| Esc, `q` | Clear the search, or quit |

**Adding or editing a host**

| Key | Does |
|---|---|
| Tab, Shift+Tab | Next or previous field |
| Enter | Next field. On Identity file and Jump host it opens a list to choose from; on Advanced it shows or hides jump host, port forwards and agent forwarding |
| Space | Turn agent forwarding on or off (it is off by default) |
| Ctrl+S | Save. Not possible while a field has an error |
| Esc | Cancel, after asking if there are unsaved changes |

**Keys screen (`K`)**

| Key | Does |
|---|---|
| Up/Down, `j`/`k` | Move through your keys |
| `g` | Make a new ed25519 key |
| `a` | Add the selected key to the ssh agent |
| `c` | Send the selected public key to a saved host |
| `f` | Set a private key's permissions to 0600, after you confirm |
| `D` | Delete a key (both files), after you type its name |
| `r` | Read the keys and ask the agent again |
| Esc | Back to the list |

**ssh config screen (`s`)**

| Key | Does |
|---|---|
| `i` | Show what importing your ssh config would add |
| `e` | Show where your hosts would be exported |
| `y` | Confirm the import or the export. Nothing else confirms |
| `n`, Esc | Cancel and go back |

**After a failed connection:** `o` reads everything ssh printed, Enter or Esc goes
back. **When a server's identity changed:** Enter or Esc aborts (the safe choice),
`d` reads what ssh printed, and `r` offers to remove the old key after you type the
host name.

## Command line

```
bifrost              open the interface
bifrost <host>       connect to a saved host, without opening the interface
bifrost list         print the names of the saved hosts, one per line
bifrost --help       help, including the exit status
bifrost --version
```

`bifrost <host>` hands the terminal to ssh and then exits with ssh's own status,
so it works in scripts:

| Exit status | Meaning |
|---|---|
| 0 to 255 | The status of ssh or of the remote command, unchanged. ssh itself uses 255 when it cannot connect |
| 128 + N | ssh was ended by signal N (130 after Ctrl-C) |
| 2 | Bifrost itself could not connect: the host is not saved, the saved hosts cannot be read, or ssh is not installed. A remote command can also exit with 2; the message on stderr tells the two apart |

Other commands exit with 1 on an error.

## Where Bifrost keeps things

| System | Folder |
|---|---|
| Linux | `$XDG_CONFIG_HOME/bifrost`, by default `~/.config/bifrost` |
| macOS | `~/Library/Application Support/bifrost` |
| Windows | `%APPDATA%\bifrost` |

Set `BIFROST_CONFIG_DIR` to an absolute path to use another folder.

- `hosts.toml` holds your hosts, favorites and tags, as plain text you can read and
  back up. The previous version is kept next to it as `hosts.toml.bak`. If the file
  is damaged, Bifrost says which host or line is wrong and does not overwrite it.
- On Linux and macOS the folder is private to you (`0700`) and the file is `0600`;
  Bifrost warns if they are broader. On Windows it relies on the permissions that
  `%APPDATA%` already has.
- Bifrost keeps no log.

Outside that folder Bifrost only writes what you ask for: keys you make (in
`~/.ssh`, by `ssh-keygen`), `~/.ssh/bifrost_config` when you export, and a line in
a server's `authorized_keys` when you send a key.

## What Bifrost never does

- **It never stores secrets.** No passwords, no passphrases, no key material: only
  the path to a key file. Passwords and passphrases are asked by ssh itself, and a
  private key is never read.
- **It never edits your `~/.ssh/config`.** Export writes its own file,
  `~/.ssh/bifrost_config`, and refuses to replace a file that Bifrost did not make.
  You add the `Include` line yourself.
- **It never edits `known_hosts` on its own.** If a server's key has changed,
  Bifrost stops and explains. Removing the old key is a separate action that you
  confirm by typing the host name, and it is done with `ssh-keygen -R`.
- **It never turns off host key checking.** No `StrictHostKeyChecking=no`, and no
  `/dev/null` for the known hosts file.
- It never runs a shell to start ssh, never creates `ProxyCommand` or
  `LocalCommand`, and has no free-form ssh options field: everything it passes to
  ssh is a checked field.
- Agent forwarding is off unless you turn it on for a host, and Bifrost warns you
  when you do.

The reasoning behind these rules is in [docs/DECISIONS.md](docs/DECISIONS.md) and
[SECURITY.md](SECURITY.md).

## Known limitations

This is version 0.1.0. What you should know before you rely on it:

- **Jump hosts:** the key of a jump host is not passed to ssh for that hop. It must
  be in your ssh agent or be one of ssh's default keys.
- **Copying the ssh command** asks your terminal to copy it (OSC 52) and always
  shows it on screen too, because not every terminal or multiplexer allows copying.
- **Sending a key** needs a POSIX shell on the server, so it does not work on a
  server whose login shell is `cmd.exe` or PowerShell.
- **Importing** runs `ssh -G` for each host, with 5 seconds per host and 60 seconds
  in all. A command in your ssh config that hangs can make the screen wait for that
  long; the hosts that were not read are listed, with the reason.
- **Removing a changed host key** is offered only for the default `known_hosts`.
  For any other file Bifrost shows the problem and you remove the entry yourself.
- **Notes** are edited on one line: type `\n` for a line break.
- **On Windows:** Ctrl+C while ssh has the terminal also ends Bifrost (the terminal
  is not left broken), a command containing `%`, `!`, `$`, a backtick or a double
  quote is not shown, and the keys screen cannot check or fix file permissions;
  ssh.exe says so itself when it refuses a key.
- Not in 0.1.0: snippets, live host status, tmux and zellij, an SFTP browser,
  persistent tunnels and a settings screen.

The complete list, with the reasons, is under "Known limitations in 0.1.0" in
[docs/DECISIONS.md](docs/DECISIONS.md).

## Platform status

| System | Status |
|---|---|
| Linux | Tested: the automated tests run in CI and were run by hand against a real server. |
| Windows | Builds and passes the automated tests in CI; manual testing pending. |
| macOS | Covered by CI only: the test suite runs on macOS in CI, but nobody has used Bifrost by hand on a Mac yet. |

If something misbehaves on your system, please
[open an issue](https://github.com/blokxz/bifrost/issues) and say which system and
which OpenSSH version (`ssh -V`) you use.

## Security

To report a vulnerability, please do not open a public issue: see
[SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in Bifrost by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
