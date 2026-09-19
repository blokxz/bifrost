# UI reference layouts

These files are the source of truth for how each Bifrost screen looks. Each one is an exact render at **120 columns × 36 rows**, followed by a `notes` section with colors and behavior. The notes are not part of the render.

| File | Screen |
|------|--------|
| `01-main.txt` | Full view (start view `"full"`) |
| `02-launcher.txt` | Quick launcher (start view `"launcher"`, `bifrost --launcher`) |
| `03-new-host.txt` | New host wizard, step 2 |
| `04-keys.txt` | Keys tab with health checks |
| `05-host-key-changed.txt` | Host key changed dialog (modal over the full view) |
| `06-settings.txt` | Settings tab |

The design rationale is in `../ui-design.md`.

## How to use them

- Treat the layout, text, borders and keybindings as the spec. If an implementation needs to deviate, ask first.
- Every screen gets a snapshot test. Render it with `ratatui::backend::TestBackend::new(120, 36)` using fixture data that matches the reference (same hosts, keys and fingerprints), and snapshot the buffer with `insta`. The snapshot is approved only when it matches the reference.
- Only the 120×36 size is specified. Larger terminals: the right-hand panels grow and the lists get more rows. Smaller than 80×24: show a "terminal too small" message instead of a broken layout.
- Selection highlight and colors cannot be shown in plain text. The `›` marker is where the selected row is; the notes say how it is styled.

## Palette (src/ui/theme.rs)

All colors come from the theme module. Never hardcode a color in a widget.

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

Use `Color::Rgb` when the terminal supports truecolor (`COLORTERM=truecolor|24bit`). Otherwise fall back to the nearest ANSI 16 colors (accent → Cyan, violet → Magenta, amber → Yellow, red → LightRed, green → Green, muted → DarkGray).

## Glyphs

All glyphs used are single-width: `─ │ ┌ ┐ └ ┘ ├ ┤ ═ ║ ╔ ╗ ╚ ╝ ━ › ▾ ▸ ★ • ● ○ ✓ ✗ ▲ ■ ⇢ ❯ █ ⏎ … ·`.
If a terminal renders one of them badly (common with `⏎` and `★` on old Windows consoles), provide an ASCII fallback (`enter`, `*`) behind a setting rather than changing the layout.
