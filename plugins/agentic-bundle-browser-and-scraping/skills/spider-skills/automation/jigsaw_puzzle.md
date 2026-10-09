Strategy for jigsaw puzzle challenges:

1. **Inspect the puzzle state** using Evaluate:
   ```js
   document.title = JSON.stringify({
     pieces: [...document.querySelectorAll('[class*=piece], [class*=tile], [draggable=true]')].map((el,i) => ({
       i, cls: el.className, rect: el.getBoundingClientRect(),
       transform: el.style.transform, bg: el.style.backgroundPosition
     })),
     board: document.querySelector('[class*=board], [class*=canvas], [class*=target]')?.getBoundingClientRect(),
     slots: [...document.querySelectorAll('[class*=slot], [class*=drop]')].map(el => el.getBoundingClientRect())
   })
   ```
2. **Analyze the screenshot** to understand the complete image and identify which piece goes where
3. **Match pieces to slots** by comparing background-position, shape edges, and visual content
4. **Drag each piece** to its correct position using ClickDragPoint from piece center to slot center
5. **Start with corner and edge pieces** - they have fewer valid positions
6. **Verify placement** after each piece - correctly placed pieces often snap into place or change appearance

Key pitfalls:
- Pieces may use background-position offsets to show different parts of the source image.
- Some puzzles require exact pixel placement; others snap within a tolerance.
- Dragging over other pieces may cause interference - move pieces to open areas first.
- Check if pieces rotate or only translate. Some jigsaws require rotation too.
