Strategy for spot-the-difference image challenges:

1. **Detect the challenge layout** using Evaluate:
   ```js
   document.title = JSON.stringify({
     images: [...document.querySelectorAll('img, [class*=image], canvas')].map((el,i) => ({
       i, src: el.src?.slice(-50), rect: el.getBoundingClientRect(), cls: el.className?.slice(0,30)
     })),
     spots: document.querySelectorAll('[class*=spot], [class*=difference], [class*=found]').length,
     total: document.querySelector('[class*=count], [class*=remaining], [class*=total]')?.textContent?.trim(),
     prompt: document.querySelector('[class*=instruction], [class*=prompt]')?.textContent?.trim()
   })
   ```
2. **Compare the two images** side by side in the screenshot. Look for subtle differences
3. **Common difference types**: Missing object, color change, size change, added element, rotated element
4. **Click on each difference** as you find it. Click on the correct image (usually either works)
5. **Track found differences** - a counter usually shows remaining/total
6. **Scan systematically**: Compare images region by region (top-left to bottom-right)

Key pitfalls:
- Differences can be very subtle (slightly different shade, tiny missing detail). Zoom in mentally.
- Click precisely on the difference location. Clicking nearby but not on it may not register.
- Some challenges are timed. Prioritize the most obvious differences first.
- The two images may have slight overall differences (brightness, crop) that are not valid answers.
