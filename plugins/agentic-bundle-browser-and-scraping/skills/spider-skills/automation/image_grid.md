Strategy for image grid selection challenges (e.g., "select all stop signs"):

**GOAL: Solve in 2 rounds max. Round 1: select + verify. Round 2: adjust if wrong.**

1. **Look at the screenshot** carefully. Identify which tiles contain the target object by position (row, column).
2. **Use Evaluate to toggle tiles to the correct state in ONE step**:
   ```js
   const items = [...document.querySelectorAll('[class*=grid-item], [class*=grid] > *')];
   const correct = new Set([0, 1, 4, 5]); // replace with YOUR correct indices
   items.forEach((el, i) => {
     const sel = el.classList.contains('selected') || el.classList.contains('grid-item-selected');
     if (correct.has(i) !== sel) el.click(); // only toggle tiles in wrong state
   });
   document.title = 'DONE';
   ```
3. **Click Verify** in the same round after the Evaluate.
4. **If wrong**: try DIFFERENT tile indices. Don't repeat the same selection.

Key rules:
- Toggle only tiles that need changing, never deselect-all then reselect.
- From the screenshot, map tile positions to grid indices (left-to-right, top-to-bottom, 0-indexed).
- If stuck, use Evaluate to read alt text or image src hints: `items.map((el,i)=>({i, alt:el.querySelector('img')?.alt}))`
