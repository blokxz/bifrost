# Bifrost — UI design decisions

Status: accepted (2026-09-19, updated 2026-09-20). Reference layouts: `docs/ui/*.txt` (120×36), palette and conventions in `docs/ui/README.md`. The matching entries in `docs/DECISIONS.md` (Terminal interface) take precedence if anything here disagrees.

## Screens

| # | Screen | Reference | Role |
|---|--------|-----------|------|
| 1 | Full view (split panels) | `ui/01-main.txt` | Start view option A. New screen: hosts grouped by favorites/tags, detail panel, equivalent `ssh` command, notes. |
| 2 | Launcher | `ui/02-launcher.txt` | Start view option B. **The existing host list screen**, kept as it is. |
| 3 | New host wizard | `ui/03-new-host.txt` | Stepped flow: Connection → Authentication → Organize → Review, with a tips panel. |
| 4 | Keys | `ui/04-keys.txt` | Key table (type, agent, permissions, used by, health) + problems panel with one-key fixes (chmod 600, rotate). |
| 5 | Host key changed | `ui/05-host-key-changed.txt` | Blocking dialog: saved vs received fingerprint, "Abort" is the default, trusting requires typing the host name. |
| 6 | Settings | `ui/06-settings.txt` | Start view selector, beginner-help toggles, security policies shown as locked. |

## Start views (decided 2026-09-20)

- There are two: the **full view** (new, `01-main.txt`) and the **launcher**, which is the host list screen Bifrost already has.
- The separate fuzzy launcher from the first mockups (centered search box, recent hosts, route preview) is **dropped**. Do not build it.
- The launcher keeps everything it does today: `/` search, connect, add, edit, delete, favorite, copy command, help. The only additions are `Tab` to switch to the full view and the new palette.
- Config key: `ui.start_view = "full" | "launcher"`, default `"full"`.
- CLI override for a single run: `bifrost --launcher` (short `-l`).
- `Tab` switches between the two views at runtime and keeps the selected host.

## Palette (decided 2026-09-20)

- The truecolor palette in `docs/ui/README.md` is the Bifrost palette. It replaces the earlier ANSI-only theme decision.
- 16-color fallback on terminals without truecolor; `NO_COLOR` keeps the current plain theme.
- One theme module: `src/tui/theme.rs`. `src/tui/ui/theme.rs` is a draft to merge into it and delete.

## Beginner help toggles

- `ui.show_tips` (default `true`): tips panels such as "What is an SSH key?".
- `ui.show_command` (default `true`): show the equivalent `ssh` command for the selected host.

## Security settings are not configurable from the UI

- Always ask before trusting a new host key.
- Always block when a host key changes (explicit confirmation by typing the host name).

## Verification

- Every screen has a snapshot test rendered with `TestBackend` at 120×36, using fixture data that matches its reference file.
- When closing a UI block, run `bifrost` in a 120×36 terminal and compare against the reference and the design canvas.

## Open questions

- Settings in a separate `config.toml` vs. a `[ui]` table inside the existing host store TOML. The references show a separate `config.toml`, which is not decided yet.
- Which block of the plan implements the full view and the view switch.
