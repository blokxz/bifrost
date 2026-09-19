# Bifrost — UI design decisions

Status: accepted (2026-09-19). Reference layouts: `docs/ui/*.txt` (120×36), palette and conventions in `docs/ui/README.md`.

## Screens

All five concept screens are in scope. Only two of them are alternatives to each other; the rest are complementary.

| # | Screen | Reference | Role |
|---|--------|-----------|------|
| 1 | Full view (split panels) | `ui/01-main.txt` | Start view option A. Hosts grouped by favorites/tags, detail panel, equivalent `ssh` command, notes. |
| 2 | Quick launcher (fuzzy) | `ui/02-launcher.txt` | Start view option B. Search, recent hosts (1-9), ProxyJump route preview, connect. Nothing else. |
| 3 | New host wizard | `ui/03-new-host.txt` | Stepped flow: Connection → Authentication → Organize → Review, with a tips panel. |
| 4 | Keys | `ui/04-keys.txt` | Key table (type, agent, permissions, used by, health) + problems panel with one-key fixes (chmod 600, rotate). |
| 5 | Host key changed | `ui/05-host-key-changed.txt` | Blocking dialog: saved vs received fingerprint, "Abort" is the default, trusting requires typing the host name. |
| 6 | Settings | `ui/06-settings.txt` | Start view selector, beginner-help toggles, security policies shown as locked. |

## Start view is user-selectable

- Config key: `ui.start_view = "full" | "launcher"`, default `"full"` (more discoverable for beginners).
- CLI override for a single run: `bifrost --launcher` (short `-l`).
- `tab` switches between the two views at runtime.
- The launcher stays minimal (search + connect). Adding hosts, keys and settings live in the full view.

## Beginner help toggles

- `ui.show_tips` (default `true`): tips panels such as "What is an SSH key?".
- `ui.show_command` (default `true`): show the equivalent `ssh` command for the selected host.

## Security settings are not configurable from the UI

- Always ask before trusting a new host key.
- Always block when a host key changes (explicit confirmation by typing the host name).

## Verification

- Every screen has an `insta` snapshot test rendered with `TestBackend` at 120×36, using fixture data that matches its reference file.
- When closing a UI block, run `bifrost` in a 120×36 terminal and compare against the reference and the design canvas.

## Open questions

- Settings in a separate `config.toml` vs. a `[ui]` table inside the existing host store TOML. The references show a separate `config.toml` (`~/.config/bifrost/`, `%APPDATA%\bifrost\` on Windows), which is not decided yet.
- Which block of the plan implements the view switch (it depends on the full view and the launcher both existing).
