Strategy for icon/symbol CAPTCHA challenges (click the correct icon):

1. **Inspect the icon challenge** using Evaluate:
   ```js
   document.title = JSON.stringify({
     prompt: document.querySelector('[class*=prompt], [class*=instruction], [class*=task]')?.textContent?.trim(),
     icons: [...document.querySelectorAll('[class*=icon], [class*=symbol], [class*=captcha] img, [class*=option]')].map((el,i) => ({
       i, cls: el.className, alt: el.alt || el.title || el.getAttribute('aria-label'),
       src: el.querySelector('img')?.src?.slice(-40) || el.tagName === 'IMG' ? el.src?.slice(-40) : '',
       rect: el.getBoundingClientRect()
     }))
   })
   ```
2. **Read the instruction**: "Click the icon showing a car", "Select all hearts", "Click the arrow pointing up"
3. **Match the prompt to the icons** using screenshot analysis and alt text/labels
4. **Click the matching icon(s)** at their coordinates
5. **For ordered selection**: Click icons in the specified order (e.g., "Click: star, heart, arrow")
6. **Submit** after making selections

Key pitfalls:
- Icons may be custom SVGs with no alt text. Rely on visual identification from the screenshot.
- Similar-looking icons can be confusing (star vs asterisk, heart vs spade).
- Some challenges require clicking icons in a specific order. Read the prompt carefully.
- Icon colors or styles may vary to add difficulty.
