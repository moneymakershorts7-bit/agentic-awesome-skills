Strategy for sliding tile puzzle challenges (15-puzzle, 8-puzzle):

1. **Read the board state** using Evaluate:
   ```js
   document.title = 'TILES:' + JSON.stringify({
     tiles: [...document.querySelectorAll('[class*=tile], [class*=cell], [class*=square]')].map((el,i) => ({
       i, text: el.textContent?.trim(), cls: el.className,
       empty: el.classList.contains('empty') || el.textContent?.trim() === '',
       rect: el.getBoundingClientRect()
     })),
     size: Math.sqrt(document.querySelectorAll('[class*=tile], [class*=cell]').length)
   })
   ```
2. **Identify the empty slot** and current tile positions. Goal: arrange numbers 1..N in order
3. **Solve using a layer-by-layer approach**:
   - First solve the top row, then the left column
   - Work inward, solving row-by-row and column-by-column
   - For 3x3: solve top row, then middle row, then bottom falls into place
4. **Click tiles adjacent to the empty space** to slide them. Only tiles neighboring the gap can move
5. **Execute moves one at a time**, verifying state between moves
6. **If stuck in a loop**: Back up several moves and try an alternate path

Key pitfalls:
- Only tiles adjacent to the empty space can move. Clicking non-adjacent tiles does nothing.
- Not all initial configurations are solvable (50% of random arrangements are unsolvable).
- The solving algorithm must be executed step-by-step. Plan multiple moves ahead.
- Larger puzzles (4x4, 5x5) require many more moves - be patient and systematic.
