Sliding tile puzzle: Move tiles to solve the puzzle by sliding into the empty space.

Title format: `SLIDE:{"n":N,"tiles":[{"id":N,"x":N,"y":N,"txt":"1"}...]}`

**Strategy:**
1. Read tile positions from the title data.
2. Identify the empty space (missing tile in the grid).
3. Click a tile adjacent to the empty space to slide it in.
4. Work top-to-bottom, left-to-right: solve first row, then second row, etc.

**Click the tile you want to move** (it slides into the empty space):
```json
"steps": [
  {"ClickPoint":{"x":TILEx,"y":TILEy}},
  {"Wait":300},
  {"ClickPoint":{"x":TILE2x,"y":TILE2y}},
  {"Wait":300}
]
```

Make 2-4 moves per round. Verify when solved. Solve in 5-10 rounds.
