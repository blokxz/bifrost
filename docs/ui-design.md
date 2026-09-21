# Bifrost — UI notes: reference mockups and proposals

**This is not a specification of what 0.1.0 does.** It holds the reference
mockups in `docs/ui/*.txt` and ideas for a later release, and it says for each
whether it is built. What is decided is in `CLAUDE.md` and `docs/DECISIONS.md`;
what is built is the code. Where this file disagrees with any of them, they win.

Anything under "Proposals for 0.2" is **not decided and not built**. A session
that reads this file must not treat it as a description of the program.

## What 0.1.0 has

- One start view: the host list (search, connect, add, edit, delete, favorite,
  copy the ssh command, help). There is no separate launcher and no view switch.
- One add/edit form, not a wizard.
- A screen for a failed connection, and a blocking screen for a changed host key.
- A keys screen (Block 6), opened with a capital `K` from the host list.
- The identity file of a host is chosen from a list of the keys in `~/.ssh` (Enter on
  the field), with "(none)" and "Another file" for a path typed by hand. After a
  key is sent to a host, a question offers to use it for that host.
- An ssh config screen (Block 6), opened with `s`: import from your ssh config
  (with a preview and a question) and export to `~/.ssh/bifrost_config`.
- Colors come from the terminal's 16 ANSI colors, and `NO_COLOR` removes them.
  The theme is `src/tui/theme.rs`.

## The mockups

| # | Screen | Reference | In 0.1.0 |
|---|--------|-----------|----------|
| 1 | Full view (split panels) | `ui/01-main.txt` | Proposal for 0.2. Not built. |
| 2 | Launcher | `ui/02-launcher.txt` | Proposal for 0.2. The host list is the only start view in 0.1.0; there is no `Tab` and no full view to switch to. |
| 3 | New host wizard | `ui/03-new-host.txt` | Proposal for 0.2. 0.1.0 has one form. |
| 4 | Keys | `ui/04-keys.txt` | Built in part (Block 6). See the notes in the file. |
| 5 | Host key changed | `ui/05-host-key-changed.txt` | Built, differently. See the notes in the file. |
| 6 | Settings | `ui/06-settings.txt` | Proposal for 0.2. There is no settings screen. |

The mockups are visual reference, not expected output. Nothing is tested against
them, and the built screens differ from them where the notes in each file say so.

## Proposals for 0.2 (not decided, not built)

- **Two start views.** A full view with panels (`01-main.txt`) and a launcher,
  which would be the existing host list. A setting would choose which opens, a
  flag such as `bifrost --launcher` could override it for one run, and `Tab`
  could switch between them keeping the selected host. The separate fuzzy
  launcher from the first mockups (a centered search box with recent hosts and a
  route preview) was considered and set aside.
- **A truecolor palette** (listed in `docs/ui/README.md`) with the 16-color
  fallback and `NO_COLOR` keeping the plain theme.
- **Beginner help toggles.** Tips panels such as "What is an SSH key?" and
  showing the equivalent `ssh` command for the selected host, each switchable.
- **A settings screen** for the above.

## Settings, when they exist

Decided in `CLAUDE.md`: settings live in a `[ui]` table inside `hosts.toml`.
There is no separate `config.toml`. No settings exist yet in 0.1.0, and the store
has no `[ui]` table.

## Security prompts are not configurable

The prompt for a new host key and the blocking screen for a changed one are never
configurable and never skipped. This is a rule in `CLAUDE.md` and it holds today.

## Verification

- Screens are tested by rendering them with `ratatui`'s `TestBackend` and
  asserting on what is drawn, at several sizes including the 60x15 minimum.
- There are no snapshot files, and no test compares a screen to a mockup in
  `docs/ui/`.
- When closing a UI block, run `bifrost` in a real terminal and look at it.
