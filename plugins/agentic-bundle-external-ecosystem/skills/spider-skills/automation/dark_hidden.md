Dark/hidden challenge: Find elements on a very dark or hidden screen.

**Strategy:**
1. The screen appears dark — look VERY carefully at the screenshot.
2. There may be a faint outline, subtle glow, or slightly different shade.
3. Move the mouse around to reveal hidden elements (some respond to hover).
4. Use Evaluate to check for interactive elements: `document.querySelectorAll('[class*=hidden],[style*=opacity],[class*=dark]')`.
5. Try clicking in the center area or where you see subtle differences.

**Reveal approach:**
```json
"steps": [
  {"ClickPoint":{"x":400,"y":300}},
  {"Wait":500},
  {"ClickPoint":{"x":600,"y":400}},
  {"Wait":500}
]
```

If nothing visible, try clicking around the center systematically.
