# WireMesh brand assets

Three nodes, three edges — the smallest full mesh that exists. The mark is the topology,
not a generic network glyph.

| File | Colour | Use |
|---|---|---|
| `wiremesh-mark.svg` | teal `#0E9F9C` | README, docs, app-icon source. **The only file that carries colour.** |
| `wiremesh-menubarTemplate.svg` | black + alpha | macOS menu bar, connected |
| `wiremesh-menubar-offTemplate.svg` | black + alpha | macOS menu bar, disconnected |

## The `Template` suffix is functional, not decorative

AppKit keys off the `Template` filename suffix (and `NSImage.isTemplate`) to tint the icon
for the current menu bar and to invert it while the menu is open. **Drop the suffix and the
icon renders as flat black on a dark bar.** A template image must therefore contain black
and alpha only — the system supplies the colour.

```swift
let img = NSImage(named: "wiremesh-menubarTemplate")!
img.isTemplate = true
statusItem.button?.image = img
```

## The two states share a silhouette

Connected is solid nodes with continuous edges; disconnected keeps the **identical node
positions** with hollow nodes and severed edges. This is deliberate: differing bounding
shapes would make the icon visibly nudge its neighbours in the menu bar on every toggle.
State reads from fill and continuity, never colour — a template image has none available.

## Export

```sh
# 18pt menu bar item -> 18px @1x, 36px @2x
rsvg-convert -w 18 -h 18 wiremesh-menubarTemplate.svg     -o wiremesh-menubarTemplate.png
rsvg-convert -w 36 -h 36 wiremesh-menubarTemplate.svg     -o wiremesh-menubarTemplate@2x.png
rsvg-convert -w 18 -h 18 wiremesh-menubar-offTemplate.svg -o wiremesh-menubar-offTemplate.png
rsvg-convert -w 36 -h 36 wiremesh-menubar-offTemplate.svg -o wiremesh-menubar-offTemplate@2x.png
```

## Not an app icon yet

A `.icns` needs 16 through 1024 with **different optical weights at each end** — a 16px
icon wants heavier strokes and fewer details than a 1024px one, so it is a drawn set rather
than one SVG scaled. `wiremesh-mark.svg` is the source for that work, not the finished set.

Legibility holds to roughly 13px; the mark ships at 18pt in the bar.
