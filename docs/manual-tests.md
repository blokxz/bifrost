# Manual tests

What the automated tests cannot check: a real server, and Windows. Each item
says what to look for. Report anything that differs, with the exact text on the
screen.

## Against a real server (the Incus container)

The ignored tests run ssh against the server and check that Bifrost reads what
it prints:

```text
cargo test --test diagnose_real -- --ignored
BIFROST_TEST_SSH_TARGET=user@host[:port] cargo test --test diagnose_real -- --ignored
```

Without the variable the last three pass without testing anything. With it, the
changed-key test also checks that the fingerprint, the key type, the line, the
host and the file are read correctly, and that removal would be offered.

Then, in `bifrost`:

1. Connect (Enter) and log out. The list comes back; the terminal is as it was.
2. Break the key. Copy `~/.ssh/known_hosts`, replace the server's line with a
   line for the same host and a different key (or `ssh-keygen -R` it and add a
   key from `ssh-keygen -t ed25519`). Connect.
   - The screen says Stop, shows the fingerprint and `known_hosts, line N`, and
     offers `r`.
   - Enter aborts; `q`, `a`, `e` do nothing.
   - `r`, a wrong name: refused. The right name: removed, and `known_hosts.old`
     exists next to the file. Connect again: ssh asks whether to trust the new
     key.
3. Same with a jump host whose key changed: the screen names the jump host and
   asks for its name.
4. `bifrost <host>`: after `exit 3` on the server, `echo $?` prints 3. With a
   wrong port it prints ssh's message, then Bifrost's explanation, and 255.
   `bifrost nosuchhost` prints the closest names and 2.

## Making a key and adding it to the agent

The automated tests use fake `ssh-keygen` and `ssh-add`, and one ignored test
runs the real `ssh-keygen` (`cargo test --test pty_keys -- --ignored`). By hand,
with the real tools, in a real terminal:

1. **Generate.** `K`, `g`. Look for: a free name is in the form, the passphrase
   note is in the form, and Enter goes name, comment, then to `ssh-keygen`.
   `ssh-keygen` asks for the passphrase and its confirmation in the normal
   screen. Afterwards the keys screen is back, drawn correctly, with the new key
   selected and a line saying it was made. Try a passphrase, and an empty one.
2. **Cancel.** Start again and press Ctrl-C at the passphrase prompt. Look for:
   "Making the key was cancelled." and Bifrost still running.
3. **Never overwrite.** Give the name of an existing key: refused in the form.
   Give the name of a file that is not a key pair (a private file with no `.pub`):
   refused with a message. Neither file changes.
4. **Add.** With an agent running (`eval "$(ssh-agent -s)"` before starting
   Bifrost), select a key that has a passphrase and press `a`. Look for: `ssh-add`
   asks for it on the terminal, then the row says "loaded". A wrong passphrase
   gives an error that says what `ssh-add` said.
5. **No agent.** Start Bifrost without one: `a` explains, and does not run
   `ssh-add`.
6. **Permissions.** Make a key 0644 and press `a`: it points to `f`, and does not
   run `ssh-add`.

## Deleting a key

Automated: the library, the effect, the screen and `tests/pty_keys.rs` (which checks
what is on disk afterwards). By hand, on **a copy of** `~/.ssh` (set `HOME`) or with
keys you can lose:

1. **Not by accident.** `K`, select a key, press `d`: nothing happens. `D` opens
   "Delete the key '<name>'?". Esc: "Nothing was deleted.", the files are there.
2. **The question.** Save a host whose identity file is that key. `D` again. Look
   for: "Used by: <host>", the warning that Bifrost cannot know which servers have
   the key in `authorized_keys` and that deleting it means losing access until another
   is installed, the two paths that would be removed, and, if `ssh-add -l` shows the
   key, the note that the agent keeps it.
3. **The name.** Type the name with one letter in another case, or one letter fewer,
   then Enter: "That is not the key's name.", nothing removed. Type it exactly and
   Enter. Look for: the message with both paths and the hosts that still name the
   key; the key gone from the list; `ls ~/.ssh` shows nothing else changed
   (`config`, `known_hosts`, other keys and `.pub` files); `hosts.toml` is as it was.
4. **A link.** Make `ln -s /somewhere/real ~/.ssh/linked` with a `linked.pub`.
   The question says it is a link. After deleting, `/somewhere/real` is untouched.
5. **A small terminal.** At 60x15 the warning and the input line are still there.
6. **Cannot remove.** `chmod a-w ~/.ssh` and delete: the message says nothing was
   deleted and why; then `chmod u+w ~/.ssh`. Then, as root, `chattr +i ~/.ssh/<name>.pub` and
   delete that key: the message says the private key was deleted and the `.pub`
   is left over (`chattr -i` afterwards).

## Choosing the identity file, and using a key that was sent

Automated: `tests/pty_keys.rs`, with a fake `ssh` and `ssh-keygen`. By hand:

1. **The list.** `a` (or `e` on a host), Tab to Identity file, Enter. Look for:
   "(none)", each key of `~/.ssh` with its type (`ed25519`, `rsa 3072`), and
   "Another file". It opens at once even if `SSH_AUTH_SOCK` points at a dead agent.
2. **Choosing.** Pick a key and press Ctrl+S; the host list details show
   `~/.ssh/<name>`, and `bifrost <host>` connects with `-i` and `IdentitiesOnly`.
   Pick "(none)": the field is empty. Pick "Another file", type a path elsewhere and
   save: it is kept as typed.
3. **No keys.** With an empty `~/.ssh`: the list says how to make one (K, then g).
4. **After a send.** Send a key to a host (see below). Look for "Use this key for
   '<host>' from now on?". `n`: the host is unchanged. Send again and `y`: the
   message says the host now uses the key, and the host has it (`e` on it).
5. **Not asked.** Send the same key again: no question, the host has it. Send
   to a host whose password is wrong: no question.
6. **Replacing.** Give the host another key file first: the question says which one
   is replaced.

## The ssh config screen

Automated: `tests/pty_sshconfig.rs` runs the real binary against a fake `ssh -G`.
By hand, with the real ssh and your own `~/.ssh/config` (try it on a copy of your
home first if it has `Match exec` lines: `ssh -G` runs them):

1. **Import preview.** `s`, `i`. Look for: the hosts of your config that are not
   in Bifrost under "Will be imported", with the user, address, port, jump host and
   key ssh resolved. Hosts already saved under "Already in Bifrost". Wildcard hosts
   (`Host *`) are not listed. Nothing is saved: `~/.config/bifrost/hosts.toml` is
   unchanged, and `n` or Esc leaves it so.
2. **Import.** `y`. Look for "Saved", the list of what was imported, and that
   `hosts.toml.bak` holds the previous version. The hosts are on the host list.
   Your `~/.ssh/config` is byte for byte what it was.
3. **A host ssh cannot resolve** (for example an `Include` of a missing file): it is
   listed under "Skipped" with ssh's own reason, and the rest is imported.
4. **Export.** `e`. Look for the number of hosts and `~/.ssh/bifrost_config`, then
   `y`. Look for the `Include ~/.ssh/bifrost_config` line on its own. Add it at the
   top of `~/.ssh/config` and run `ssh -G <one of the hosts>`: it resolves.
5. **Include already there / after a Host line.** Export again: it says the
   config already includes it. Move the line below a `Host` line: it warns that
   it only applies to that block.
6. **A file Bifrost did not make.** Put your own text in `~/.ssh/bifrost_config`
   and export: it says it will not touch it, does not offer `y`, and leaves it.
7. **Very many hosts.** Import from a config with a few hundred hosts: note how
   long the screen waits, since it does not draw while ssh runs.
8. **A command that hangs.** Add `Match host slowhost exec "sleep 60"` and
   `Host slowhost` to a copy of your ssh config. Import: after about 5 seconds the
   preview lists `slowhost` under Skipped with "ssh did not answer within 5
   seconds", and the other hosts are there. `pgrep -f "sleep 60"` shows nothing
   left running (on Windows the command is not killed: note whether it is).
9. **Every host hangs.** Make the `Match exec` match `Host *` (a `Match exec
   "sleep 60"` line with no host). The import takes 5 seconds for each of the first
   hosts, and stops at 60 seconds in all: the preview lists the ones that did not
   answer, and then, as one entry, the hosts that were not read, with "the import
   was taking too long...". `pgrep -f "sleep 60"` shows nothing left running.
   Time it.

## Sending a public key to a host

The automated tests use a fake ssh (`tests/pty_keys.rs`). Against a real server,
with the real ssh:

```text
BIFROST_TEST_SSH_TARGET=user@host[:port] cargo test --test copy_real -- --ignored --nocapture
```

It adds a throwaway key to the server's `authorized_keys` and removes it again.
It needs a server this machine can log in to without typing (an agent or a
default key) and whose host key is in your `known_hosts`. By hand, from the keys
screen with a server that asks for a password:

1. **Send.** Select a key, press `c`, choose the host, Enter. Look for: the
   question names the key, its fingerprint and the host. `y`: ssh asks for the
   password on the normal screen, not in Bifrost, and after it the keys screen is
   back with "Sent the public key of ...". Then `ssh HOST` with that key logs in.
2. **Twice.** Send the same key again: the server's `authorized_keys` has the line
   once.
3. **Nothing sent by mistake.** `n` and Esc at the question send nothing.
4. **A wrong password** three times: the screen explains that the server refused
   the login and Esc goes back to the keys screen.
5. **Cancel.** Ctrl-C at the password prompt: "Sending the key was cancelled."
6. **A changed host key** (see the changed-key steps above): the blocking screen
   appears, aborting goes back to the keys, and after removing the old key the
   message says to send the key again.
7. **A server without `sh`** (a Windows server with the default shell): the
   message says the server ran the command and it failed, with what it said.
8. **A server whose login shell is fish or csh**: the key is still added once.
   (csh has not been tried.)
9. **A hostile `.pub`.** Put `command="id" ` in front of a key line in a copy of a
   `.pub`, or two keys on two lines: it is refused, and ssh is not run.

## Windows

`cargo test --locked` runs the command line tests (`cli_connect`) with a fake ssh,
and CI runs them on Windows. The pseudo-terminal tests are Unix only. By hand, in
the Windows VM, with the real `ssh.exe` (OpenSSH Client installed):

1. **Handover.** Open `bifrost`, connect to a host, log out. Look for: the
   interface comes back drawn correctly, the cursor is hidden in the list and
   visible in ssh, the shell prompt afterwards is normal. Try Windows Terminal
   and the legacy console host.
2. **Typing.** While connected, type quickly, then log out. Nothing typed should
   run as a command in Bifrost afterwards.
3. **Resize** the window while connected, then log out: the list fits the new size.
4. **Ctrl-C at a password prompt.** Expected on Windows (a known limitation):
   Bifrost ends together with ssh. Check that the console is sane afterwards:
   typing echoes, line editing works, Enter works.
5. **ssh killed.** End `ssh.exe` in Task Manager while connected. Look for:
   what state the console is left in (echo, line editing). This is the case the
   terminal-mode restore covers on Unix and cannot on Windows.
6. **Exit status.** `bifrost HOST`, then `exit 3` in the session: `echo %ERRORLEVEL%`
   (cmd) or `$LASTEXITCODE` (PowerShell) is 3. `bifrost nosuchhost` gives 2. A
   wrong port gives 255 and the explanation.
7. **Changed key.** Damage the server's line in `%USERPROFILE%\.ssh\known_hosts`
   as above, then connect.
   - Does the screen offer `r`? It only does if the path ssh.exe prints in
     `Offending ... key in <path>:N` matches `%USERPROFILE%\.ssh\known_hosts`. If
     it does not, note the exact line ssh printed: the comparison needs adjusting.
   - After removal, `known_hosts.old` exists.
   - `bifrost HOST` prints `ssh-keygen -R "[host]:port"` or `ssh-keygen -R host`:
     paste it into cmd and PowerShell and check it runs.
8. **`--help`** shows the exit status section.
9. **Generate.** `K`, `g`. Look for: `ssh-keygen.exe` asks for its passphrase and
   the interface comes back drawn correctly, in Windows Terminal and in the legacy
   console host. Ctrl-C at the prompt is expected to end Bifrost too (see item 4).
10. **Add.** With the "OpenSSH Authentication Agent" service running, select a
    key and press `a`. Look for: `ssh-add.exe` asks for the passphrase and the row
    says "loaded". With the service stopped: what does the screen say about the
    agent? Note the exact wording, it has not been checked.
11. **Send a public key.** `K`, select a key, `c`. Look for: does ssh.exe ask for the
    password on the console while its stdin is a pipe? Does the server get the
    key (`authorized_keys` on the server has one line for it)? The command's
    double quotes are the risk: if the server answers that the command failed,
    note exactly what it printed.
12. **The ssh config screen.** `s`, `i`, `e`. Look for: does `ssh -G` work for the
    hosts in `%USERPROFILE%\.ssh\config`? The Include line has its own step
    (15). Note what ssh printed if it does not.
13. **Deleting a key.** `K`, select a key, `D`, type the name. Look for: both
    files are gone, also when the `.pub` is read-only (Explorer shows the attribute),
    and a key whose file is a symbolic link (needs privileges or developer mode) is
    removed as a link. Note what the screen said if it failed.
14. **Choosing the identity file.** Does the list show the keys of
    `%USERPROFILE%\.ssh` with their types, and does `bifrost <host>` accept the
    stored `~/.ssh/<name>` for `-i`? Note what ssh printed if not.
15. **The Include line, with the real `ssh.exe`.** Bifrost tells the user to add
    `Include ~/.ssh/bifrost_config` on every platform, and that has to be read by
    OpenSSH for Windows. Export a host that has a jump host and a key file (`e`, `y`),
    then, with the line as the first line of `%USERPROFILE%\.ssh\config`:
    - `ssh -G <exported host>` prints that host's `hostname`, `user`, `port` and
      `identityfile`, plus `identitiesonly yes`. Without the line it prints the
      alias as the `hostname`. Look for: the difference.
    - The screen after the export says the config "already includes it". Move the
      line below a `Host` line: the screen says it has to move to the top, and
      `ssh -G` of a host that is not in that `Host` block stops seeing the export.
      Does the screen agree with ssh in both cases?
    - Do it again with a profile folder that has a space in its name (a local
      account called `John Smith`): the same line has to work there too.
    - If `~` is not read, try `Include bifrost_config` (relative to `~/.ssh`) and
      then `Include "C:/Users/<you>/.ssh/bifrost_config"`, and note which of them
      work. Do not change the line in Bifrost before reporting it: the decision to
      use `~` everywhere is in `DECISIONS.md`.
16. **A key file typed by hand, outside `.ssh`, through the export.** The list only
    stores `~/.ssh/<name>`; a path typed under "Another file" is stored as typed,
    and the export writes it quoted with `\` doubled. Make a key in a folder that
    is not `.ssh` (`ssh-keygen -t ed25519 -f C:\keys\id`, and again in
    `C:\my keys\id`), add it to a host that can log in with it, and for each
    of `C:\keys\id`, `C:/keys/id` and `C:\my keys\id`:
    - Save the host with that path (the form accepts it; the identity file
      warning does not appear, since the file exists), then export (`e`, `y`) and
      open `%USERPROFILE%\.ssh\bifrost_config`. Look for: the `IdentityFile` line
      is quoted and its backslashes are doubled (`"C:\\keys\\id"`).
    - With the Include line in place (step 15), `ssh -G <host>`: does
      `identityfile` print the path as you typed it, with single backslashes, or
      with the doubled ones? Doubled ones mean ssh.exe does not unescape, and the
      export cannot be used for keys outside `.ssh` on Windows: note exactly what
      it printed.
    - `ssh <host>` and `bifrost <host>` both log in with that key. The second
      passes the path as one argument to `-i` without quoting, so it should work
      even if the first does not.
    - The other direction, for a key that is in `~/.ssh`: type its full path
      (`C:\Users\<you>\.ssh\id`, then again with `/`, then in another case) as a
      host's identity file, save, and edit the host again. Look for: the list opens
      on that key's entry, and after sending that key to the host Bifrost does not
      ask whether to use it, because the host already does.
