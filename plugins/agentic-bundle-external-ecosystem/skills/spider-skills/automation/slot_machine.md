Slot machine: Stop the reels to match symbols.

**Strategy:**
1. Watch the spinning reels.
2. Click STOP or the reel itself to stop each one.
3. Try to align matching symbols across reels.
4. Timing is key — click when you see the target symbol.

**Approach:**
```json
"steps": [
  {"Click":"[class*=reel]:nth-child(1)"},
  {"Wait":500},
  {"Click":"[class*=reel]:nth-child(2)"},
  {"Wait":500},
  {"Click":"[class*=reel]:nth-child(3)"}
]
```

Or look for a "Spin" then "Stop" button. Solve in 2-4 rounds.
