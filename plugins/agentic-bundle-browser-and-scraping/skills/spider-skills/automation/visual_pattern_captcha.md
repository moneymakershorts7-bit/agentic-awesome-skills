Strategy for visual pattern CAPTCHA challenges (identify the pattern, odd-one-out):

1. **Inspect the challenge elements** using Evaluate:
   ```js
   document.title = JSON.stringify({
     items: [...document.querySelectorAll('[class*=option], [class*=choice], [class*=item], [class*=pattern]')].map((el,i) => ({
       i, cls: el.className, text: el.textContent?.trim()?.slice(0,30),
       bg: getComputedStyle(el).backgroundColor, border: getComputedStyle(el).borderColor,
       img: el.querySelector('img')?.src?.slice(-40), rect: el.getBoundingClientRect()
     })),
     prompt: document.querySelector('[class*=prompt], [class*=instruction], [class*=question]')?.textContent?.trim()
   })
   ```
2. **Read the prompt**: "Select the image that is different", "Continue the pattern", "Which doesn't belong?"
3. **Analyze from the screenshot**: Look for color patterns, shape sequences, size progressions, rotation patterns
4. **For "odd one out"**: Identify which item breaks the pattern (different shape, color, orientation)
5. **Click the correct answer** using its coordinates or selector
6. **Verify submission** - if wrong, re-analyze the visual differences more carefully

Key pitfalls:
- Patterns can be subtle: rotation angle, slight color shift, mirror flip.
- "Continue the sequence" requires predicting the next item in a series.
- Some patterns involve multiple attributes changing simultaneously.
- Screenshot analysis is key - DOM inspection may not reveal visual pattern differences.
