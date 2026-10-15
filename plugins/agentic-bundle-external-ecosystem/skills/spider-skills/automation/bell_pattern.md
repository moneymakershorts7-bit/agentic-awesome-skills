Bell/sound pattern: Reproduce a sequence of bell rings or sounds.

**Strategy:**
1. First round: observe the pattern being demonstrated (which bells ring in which order).
2. Note the sequence: left-right-left, or numbered positions.
3. Reproduce by clicking bells/elements in the same order.

**Pattern reproduction:**
```json
"steps": [
  {"ClickPoint":{"x":BELL1x,"y":BELL1y}},
  {"Wait":400},
  {"ClickPoint":{"x":BELL2x,"y":BELL2y}},
  {"Wait":400},
  {"ClickPoint":{"x":BELL3x,"y":BELL3y}}
]
```

Match the exact sequence and timing. Solve in 2-4 rounds.
