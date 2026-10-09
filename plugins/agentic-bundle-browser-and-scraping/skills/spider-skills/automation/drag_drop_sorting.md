Strategy for drag-and-drop sorting/reordering challenges:

1. **Map the sortable items** using Evaluate:
   ```js
   document.title = JSON.stringify({
     items: [...document.querySelectorAll('[class*=sortable] > *, [class*=draggable], [draggable=true], [class*=item]')].map((el,i) => ({
       i, text: el.textContent?.trim()?.slice(0,30), cls: el.className?.slice(0,30),
       rect: el.getBoundingClientRect(), data: el.getAttribute('data-id') || el.getAttribute('data-order')
     })),
     instruction: document.querySelector('[class*=instruction], [class*=prompt]')?.textContent?.trim()
   })
   ```
2. **Determine the correct order** from the instructions (alphabetical, numerical, by size, custom)
3. **Plan the minimum number of moves** to reach the target order
4. **Drag items one at a time** using ClickDragPoint:
   - Mouse down on the item to pick up
   - Drag to the target position (between two other items or to a specific slot)
   - Mouse up to drop
5. **Verify the new order** after each move using Evaluate
6. **Click Submit/Verify** when the order is correct

Key pitfalls:
- Drop zones may be narrow. Drag to the vertical center between two items.
- Some sortable libraries (SortableJS) use placeholder elements during drag. Wait for drop to settle.
- Items may animate/shift during drag. The visual position may lag behind the actual position.
- If an item doesn't move, try dragging it further. Some implementations need a minimum drag distance.
