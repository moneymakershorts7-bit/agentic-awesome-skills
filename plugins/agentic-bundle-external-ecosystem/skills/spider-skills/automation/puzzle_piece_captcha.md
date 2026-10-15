Strategy for puzzle piece / jigsaw CAPTCHA challenges (drag piece into cutout):

1. **Identify the puzzle elements** using Evaluate:
   ```js
   document.title = JSON.stringify({
     piece: document.querySelector('[class*=piece], [class*=puzzle-drag], [class*=jigsaw]')?.getBoundingClientRect(),
     slot: document.querySelector('[class*=slot], [class*=cutout], [class*=target], [class*=gap]')?.getBoundingClientRect(),
     slider: document.querySelector('[class*=slider], input[type=range], [class*=handle]')?.getBoundingClientRect()
   })
   ```
2. **Determine the mechanism**: Either drag the piece directly, or use a horizontal slider to move it
3. **For slider-based**: Calculate the target X position where the piece outline aligns with the cutout
4. **Use ClickDragPoint** to drag from the handle/piece current position to the target:
   - Drag horizontally: from (handleX, handleY) to (targetX, handleY)
5. **Verify alignment** visually from the screenshot - the piece should snap into the cutout
6. **Fine-tune if needed**: If slightly off, adjust by small increments (2-5 pixels)

Key pitfalls:
- The cutout position is often randomized on each load.
- Some implementations detect too-fast or too-straight drags as bot behavior. Vary speed slightly.
- The slider may have momentum/inertia - release slightly before the target.
- If the puzzle resets after a failed attempt, re-detect the new cutout position.
