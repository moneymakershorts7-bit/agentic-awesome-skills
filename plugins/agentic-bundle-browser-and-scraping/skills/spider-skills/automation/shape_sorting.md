Strategy for shape sorting challenges (drag shapes to matching containers):

1. **Identify shapes and containers** using Evaluate:
   ```js
   document.title = JSON.stringify({
     shapes: [...document.querySelectorAll('[class*=shape], [draggable=true], [class*=drag]')].map((el,i) => ({
       i, cls: el.className, text: el.textContent?.trim(), type: el.getAttribute('data-shape') || el.getAttribute('data-type'),
       rect: el.getBoundingClientRect(), color: getComputedStyle(el).backgroundColor
     })),
     containers: [...document.querySelectorAll('[class*=container], [class*=drop], [class*=bucket], [class*=target]')].map((el,i) => ({
       i, cls: el.className, label: el.textContent?.trim(), type: el.getAttribute('data-accepts'),
       rect: el.getBoundingClientRect()
     }))
   })
   ```
2. **Match shapes to containers** by type (circle->circle bin), color, size, or label
3. **Drag each shape** to its correct container using ClickDragPoint
4. **Drop in the center of the container** to ensure proper registration
5. **Verify placement** - correctly placed shapes may change appearance or become fixed
6. **Handle compound rules**: "Sort by color AND shape" - read instructions carefully

Key pitfalls:
- Drag-and-drop may require specific event sequences (dragstart, dragover, drop).
- Some containers only accept specific shapes. Check data-accepts attributes.
- Shapes placed in wrong containers may bounce back or need to be re-dragged.
- SVG shapes won't have background-color. Check fill attribute or class names instead.
