Strategy for color matching challenges:

1. **Inspect color elements** using Evaluate:
   ```js
   document.title = JSON.stringify({
     items: [...document.querySelectorAll('[class*=color], [class*=swatch], [class*=tile], [class*=block]')].map((el,i) => ({
       i, bg: getComputedStyle(el).backgroundColor, border: getComputedStyle(el).borderColor,
       cls: el.className, text: el.textContent?.trim(), selected: el.classList.contains('selected'),
       data: el.getAttribute('data-color') || el.getAttribute('data-value'),
       rect: el.getBoundingClientRect()
     })),
     target: document.querySelector('[class*=target], [class*=goal], [class*=match]')?.style?.backgroundColor,
     prompt: document.querySelector('[class*=prompt], [class*=instruction]')?.textContent?.trim()
   })
   ```
2. **Identify the challenge type**: Match colors, find the different shade, mix colors to target
3. **For "find the different color"**: Compare RGB values - one item will have slightly different values
4. **For "match the target"**: Find the swatch closest to the target color
5. **Click the correct color item** using coordinates or selector
6. **For color mixing**: Adjust RGB/HSL sliders to match the target color value

Key pitfalls:
- Color differences may be subtle (e.g., rgb(200,100,50) vs rgb(200,105,50)). Use Evaluate to get exact values.
- Monitor calibration means the screenshot color may differ slightly from actual rendered color.
- data-color attributes may provide hex/RGB values directly - check before relying on visual analysis.
- Some challenges time out. Identify the odd color quickly by checking computed styles.
