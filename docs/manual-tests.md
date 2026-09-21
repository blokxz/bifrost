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
