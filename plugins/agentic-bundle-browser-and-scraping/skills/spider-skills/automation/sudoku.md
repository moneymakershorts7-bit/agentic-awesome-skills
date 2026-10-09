Strategy for sudoku puzzle challenges:

1. **Extract the board** using Evaluate:
   ```js
   document.title = 'SUDOKU:' + JSON.stringify(
     [...document.querySelectorAll('[class*=cell], input, td')].slice(0,81).map((el,i) => ({
       i, row: Math.floor(i/9), col: i%9,
       val: el.value || el.textContent?.trim() || '',
       fixed: el.readOnly || el.disabled || el.classList.contains('given'),
       rect: el.getBoundingClientRect()
     }))
   )
   ```
2. **Build the puzzle grid**: Map 81 cells into a 9x9 grid. Fixed cells are given; empty cells need solving
3. **Solve using constraint propagation**:
   - For each empty cell, determine possible values (1-9 not in same row, column, or 3x3 box)
   - Fill cells that have only one possible value (naked singles)
   - Repeat until solved or stuck, then try logical techniques (hidden singles, pairs)
4. **Fill in the solution** by clicking each empty cell and typing the digit
5. **Use Evaluate to fill programmatically** for speed:
   ```js
   const cells = [...document.querySelectorAll('input[class*=cell]')];
   cells[INDEX].value = 'DIGIT'; cells[INDEX].dispatchEvent(new Event('input', {bubbles:true}));
   ```
6. **Click Verify/Submit** after filling all cells

Key pitfalls:
- Fixed/given cells are read-only. Do not try to modify them.
- Some interfaces require clicking a cell first, then pressing a number key.
- Validate that your solution has no conflicts before submitting.
- Large puzzles may need backtracking. Start with cells that have fewest possibilities.
