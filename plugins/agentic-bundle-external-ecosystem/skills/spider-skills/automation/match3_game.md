Match-3 puzzle: Swap adjacent tiles to create rows/columns of 3+ matching items.

**Strategy:**
1. Scan the grid for potential 3-in-a-row matches.
2. Swap two adjacent tiles by clicking the first, then the second.
3. Or drag one tile onto its neighbor.
4. Look for where ONE swap creates a match of 3+ identical items.

**Swap approach:**
```json
"steps": [
  {"ClickPoint":{"x":TILE1x,"y":TILE1y}},
  {"Wait":200},
  {"ClickPoint":{"x":TILE2x,"y":TILE2y}},
  {"Wait":500}
]
```

Make 1-2 swaps per round. Verify when required matches are complete. Solve in 3-5 rounds.
