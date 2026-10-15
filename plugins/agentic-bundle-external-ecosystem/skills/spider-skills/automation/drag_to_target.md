Strategy for drag-to-target challenges (drag item to a specific drop zone):

1. **Identify drag source and drop target** using Evaluate:
   ```js
   document.title = JSON.stringify({
     draggable: [...document.querySelectorAll('[draggable=true], [class*=drag], [class*=source]')].map((el,i) => ({
       i, text: el.textContent?.trim()?.slice(0,20), cls: el.className?.slice(0,30),
       rect: el.getBoundingClientRect()
     })),
     dropZones: [...document.querySelectorAll('[class*=drop], [class*=target], [class*=zone]')].map((el,i) => ({
       i, text: el.textContent?.trim()?.slice(0,20), cls: el.className?.slice(0,30),
       rect: el.getBoundingClientRect(), accepts: el.getAttribute('data-accepts')
     })),
     instruction: document.querySelector('[class*=instruction], [class*=prompt]')?.textContent?.trim()
   })
   ```
2. **Read the instruction**: Determines which item goes to which drop zone
3. **Drag from center of source to center of target** using ClickDragPoint
4. **Verify the drop was accepted**: Check if the item moved to the target zone
5. **For multiple items**: Drag each one to its correct zone
6. **If drag fails**: Try dispatching HTML5 drag events via Evaluate as fallback

Key pitfalls:
- HTML5 drag-and-drop requires specific event sequence (dragstart, dragenter, dragover, drop, dragend).
- Drop zones only accept items if the dragover event is prevented. Some need specific data types.
- The visual feedback during drag may not match the actual drop position.
- Mobile-style drag (touch events) differs from mouse-based drag.
