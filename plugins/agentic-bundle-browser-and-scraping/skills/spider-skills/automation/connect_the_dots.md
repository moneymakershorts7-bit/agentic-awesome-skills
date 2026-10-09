Strategy for connect-the-dots challenges:

1. **Find all numbered dots** using Evaluate:
   ```js
   document.title = JSON.stringify({
     dots: [...document.querySelectorAll('[class*=dot], [class*=point], circle, [class*=node]')].map((el,i) => ({
       i, num: parseInt(el.textContent?.trim() || el.getAttribute('data-number') || i),
       x: el.getBoundingClientRect().x + el.getBoundingClientRect().width/2,
       y: el.getBoundingClientRect().y + el.getBoundingClientRect().height/2,
       cls: el.className
     })).sort((a,b) => a.num - b.num)
   })
   ```
2. **Sort dots by their number** (1, 2, 3, ...) to determine connection order
3. **Connect sequentially**: Click or drag from dot 1 to dot 2, then dot 2 to dot 3, etc.
4. **For click-based**: Click each dot in numerical order
5. **For drag-based**: Use ClickDragPoint from each dot to the next in sequence
6. **Complete the circuit** - the last dot may need to connect back to dot 1

Key pitfalls:
- Dots may be rendered as SVG circles - use SVG-aware selectors.
- Numbers may overlap or be hard to read. Use Evaluate to extract data attributes.
- Some interfaces require holding the mouse button while connecting all dots in one drag.
- Missing a dot in sequence may require starting over.
