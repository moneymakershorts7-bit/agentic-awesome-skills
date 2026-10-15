Rhythm/drum challenge: Reproduce a rhythm or sound pattern.

**Strategy:**
1. First round: WATCH/LISTEN to the pattern being played. Note the order of drum hits.
2. Second round: Click the drums/elements in the SAME order and timing.
3. Each drum/pad is a clickable element — click them in sequence.

**Pattern reproduction:**
```json
"steps": [
  {"ClickPoint":{"x":DRUM1x,"y":DRUM1y}},
  {"Wait":300},
  {"ClickPoint":{"x":DRUM2x,"y":DRUM2y}},
  {"Wait":300},
  {"ClickPoint":{"x":DRUM1x,"y":DRUM1y}},
  {"Wait":300}
]
```

Watch the demo first (1 round), then reproduce (1-2 rounds). Solve in 3-4 rounds.
