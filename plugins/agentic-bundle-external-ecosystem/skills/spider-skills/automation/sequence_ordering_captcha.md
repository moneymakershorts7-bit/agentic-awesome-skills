Strategy for sequence ordering CAPTCHA challenges (arrange items in correct order):

1. **Inspect the ordering challenge** using Evaluate:
   ```js
   document.title = JSON.stringify({
     items: [...document.querySelectorAll('[class*=sortable] > *, [class*=order] > *, [draggable=true]')].map((el,i) => ({
       i, text: el.textContent?.trim()?.slice(0,30), cls: el.className,
       rect: el.getBoundingClientRect(), draggable: el.draggable
     })),
     instruction: document.querySelector('[class*=instruction], [class*=prompt]')?.textContent?.trim()
   })
   ```
2. **Read the instruction**: "Arrange in ascending order", "Put these steps in order", "Sort by size"
3. **Determine correct order**: Analyze the items and sort them according to the rule (numeric, alphabetic, chronological, size)
4. **Rearrange using drag-and-drop**: Use ClickDragPoint to move items to correct positions
5. **For click-to-swap interfaces**: Click items in the correct order, or click two items to swap
6. **Verify** the final arrangement matches the expected order, then submit

Key pitfalls:
- Drag-and-drop may use different libraries (Sortable.js, HTML5 drag, custom) with varying event needs.
- Some orderings require domain knowledge (historical dates, process steps).
- Items may snap to positions - ensure each item lands in the correct slot.
- If drag doesn't work, try clicking items sequentially to set order via number inputs.
