# Brand materials

**The site is the style. This folder is downstream of it, never the other way round.**

Everything here — the presentation cards, the square mark, any future slide or social
image — is built from the tokens the published site actually renders with. Those tokens
were not invented for this folder and must never be edited to taste here. They were read
off <https://augbastos.github.io/scpe/> with `getComputedStyle` and transcribed into
[`_style.css`](_style.css), which carries the source of each value in a comment.

If the site's visual style changes, this folder is stale until someone re-reads the site
and re-renders. That order is the rule: **site changes → tokens re-read → materials
re-rendered.** A card that looks "close enough" but was hand-tuned is worse than no card,
because it starts a second style nobody agreed to.

## What's here

| | |
|---|---|
| `_style.css` | The transcribed tokens: colours, type scale, the eyebrow/panel/pill/row components, the hero wash. |
| `card1.html` … `card4.html` | Presentation cards, 1600 × 900. |
| `thumb.html` | Square mark, 1200 × 1200. |
| `check.html` | Loads every card off-screen at its true frame size and reports vertical overflow. |
| `renders/` | The exported PNGs. |

Each card lays its content out in the site's own **1040 px column at the site's exact
pixel values**, then scales the whole block. The proportions are therefore the site's,
magnified — not a re-interpretation at a different size.

## Re-rendering

```bash
python -m http.server 8802 --directory docs/brand     # file:// is blocked by the renderer
```

Open `check.html` and call `fitReport()` first: it returns headroom per card, and a card
whose content overflows its frame is silently cropped in the export. Then screenshot each
card at its frame size (1600 × 900, or 1200 × 1200 for `thumb.html`) into `renders/`.

## Honesty

The seal shown on `card4.html` is **real output** — the verifier's verdict on an actual
signed contribution, `key_source: forge`, not a mock-up with invented field values. If a
future card shows a seal, it must be generated the same way. No invented metrics, no
placeholder logos, no adoption claims.
