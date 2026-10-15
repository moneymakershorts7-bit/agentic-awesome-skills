Strategy for maze solving challenges:

1. **Extract the maze structure** using Evaluate:
   ```js
   document.title = JSON.stringify({
     cells: [...document.querySelectorAll('[class*=cell], [class*=maze] > *, td')].map((el,i) => ({
       i, cls: el.className, wall: el.classList.contains('wall') || getComputedStyle(el).backgroundColor === 'rgb(0, 0, 0)',
       start: el.classList.contains('start'), end: el.classList.contains('end') || el.classList.contains('goal'),
       rect: el.getBoundingClientRect()
     })),
     dims: { rows: document.querySelectorAll('[class*=row], tr').length }
   })
   ```
2. **Identify start and end positions** from class names or visual markers (green=start, red=end)
3. **Solve using wall-following or BFS** mentally or via Evaluate:
   ```js
   // Build a grid and BFS from start to end
   const cells = [...document.querySelectorAll('[class*=cell]')];
   const cols = Math.sqrt(cells.length); // adjust based on actual layout
   ```
4. **Navigate the path**: Click cells along the solution path, or use arrow keys if keyboard-controlled
5. **For interactive mazes**: Use Press with arrow keys (ArrowUp, ArrowDown, ArrowLeft, ArrowRight)
6. **Verify you reached the goal** before clicking any submit button

Key pitfalls:
- Maze walls may be defined by borders rather than separate wall cells. Check border styles.
- Some mazes use canvas rendering - DOM inspection won't help. Rely on the screenshot.
- Interactive mazes may have animation delays between moves. Wait briefly between key presses.
- Dead ends require backtracking. Keep track of visited cells in memory.
