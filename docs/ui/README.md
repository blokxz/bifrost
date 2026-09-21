# UI reference layouts

These files are **visual reference mockups, not a specification**. Each one is a
render at 120 columns by 36 rows, followed by a `notes` section with colors and
behavior. The notes are not part of the render, and each one begins with a
**Status** line saying whether the screen is built in 0.1.0.

| File | Screen | In 0.1.0 |
|------|--------|----------|
| `01-main.txt` | Full view | Proposal for 0.2. Not built. |
| `02-launcher.txt` | Launcher | Proposal for 0.2. Hand-drawn; the host list is the only start view in 0.1.0. |
| `03-new-host.txt` | New host wizard, step 2 | Proposal for 0.2. Not built. |
| `04-keys.txt` | Keys tab with health checks | Built in part (Block 6). |
| `05-host-key-changed.txt` | Host key changed dialog | Built, differently. |
| `06-settings.txt` | Settings tab | Proposal for 0.2. Not built. |

The rationale and the list of proposals are in `../ui-design.md`. What is decided
is in `CLAUDE.md` and `../DECISIONS.md`; what is built is the code.

## How to use them

- They show a direction. They are not expected output: no test compares a screen
  to one of them, and the built screens differ where the notes say so.
- Only the 120x36 size is drawn. Bifrost's real minimum is 60x15, below which it
  shows a "terminal too small" message instead of a broken layout.
- Selection highlight and colors cannot be shown in plain text. The `›` marker is
  where the selected row is; the notes say how it would be styled. The built
  screens use ASCII markers (`>`, `*`).

## Palette (a proposal for 0.2; not implemented)

Bifrost today uses the terminal's 16 ANSI colors and removes them under
`NO_COLOR`. The theme is `src/tui/theme.rs`, and it is the only place colors are
defined. What follows is a truecolor palette proposed for a later release.

If it is adopted, the existing theme roles would map to it like this:

| Role in `Theme` | Style |
|-----------------|-------|
| `title` | `accent`, bold |
| `error` | `red`, bold |
| `warning` | `amber`, bold |
| `key` | `accent`, bold |
| `muted` | `muted` |
| `selected` | `selection` background, `bright` text (the `>` marker stays) |
| `highlight` | `accent`, bold, underlined |
| `favorite` | `amber`, bold |
| tags (new) | `violet` |
| borders (new) | `border`; `accent` on the focused panel |

| Token | Hex | Use |
|-------|-----|-----|
| `bg` | `#11131a` | Screen background |
| `bg-deep` | `#0b0d12` | Inset boxes (fingerprints, input line) |
| `text` | `#cdd3de` | Default text |
| `bright` | `#f2f4f8` | Emphasis, selected row text |
| `muted` | `#7c8599` | Labels, hints, secondary text |
| `ghost` | `#343a4a` | Background screen behind a modal |
| `border` | `#2e3445` | Unfocused panel borders |
| `selection` | `#1c2a33` | Selected row background |
| `keycap` | `#262b38` | Key hint background |
| `accent` | `#5fd7c3` | Focus, primary actions, cursor |
| `violet` | `#b39dfa` | Tags, TOML sections |
| `amber` | `#f5c86b` | Warnings, favorites, jump hosts |
| `red` | `#ff7a93` | Errors, danger, security alerts |
| `green` | `#8bd67a` | OK states, success |

Proposed rules: use `Color::Rgb` when the terminal reports truecolor
(`COLORTERM=truecolor` or `24bit`), and treat Windows Terminal (`WT_SESSION` set)
as truecolor. Otherwise fall back to the nearest ANSI 16 colors (accent to Cyan,
violet to Magenta, amber to Yellow, red to LightRed, green to Green, muted to
DarkGray). With `NO_COLOR` set, keep the plain theme (bold, dim, reverse video).
Meaning must never depend on color alone.

## Glyphs

The mockups use these single-width glyphs: `─ │ ┌ ┐ └ ┘ ├ ┤ ═ ║ ╔ ╗ ╚ ╝ ━ › ▾ ▸ ★ • ● ○ ✓ ✗ ▲ ■ ⇢ ❯ █ ⏎ … ·`.
Some terminals render a few of them badly (common with `⏎` and `★` on old Windows consoles); the built screens avoid the problem by using ASCII markers. A later release could offer the glyphs behind a setting.
