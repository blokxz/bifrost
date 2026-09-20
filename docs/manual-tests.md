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
