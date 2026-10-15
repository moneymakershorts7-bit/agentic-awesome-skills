Chess challenge: Make the best move or solve a chess puzzle.

**Strategy:**
1. Read the board position from the screenshot.
2. Identify: whose turn it is, which pieces are where.
3. Look for: checkmate in 1, forks, pins, skewers, hanging pieces.
4. Click the piece to move, then click the destination square.

**Common tactics:**
- Queen + Rook battery for back-rank mate
- Knight forks (attacking 2+ pieces)
- Bishop pins against the king
- Pawn promotion threats

**Steps:**
```json
"steps": [
  {"ClickPoint":{"x":PIECEx,"y":PIECEy}},
  {"Wait":300},
  {"ClickPoint":{"x":DESTx,"y":DESTy}},
  {"Wait":500}
]
```

Think carefully before moving. Solve in 3-8 rounds.
