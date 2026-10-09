Strategy for text-in-image CAPTCHA challenges (text embedded in noisy images):

1. **Locate the CAPTCHA image** using Evaluate:
   ```js
   document.title = JSON.stringify({
     img: document.querySelector('[class*=captcha] img, img[class*=captcha], img[alt*=captcha]')?.src?.slice(-50),
     canvas: !!document.querySelector('[class*=captcha] canvas'),
     input: document.querySelector('input[type=text], input[name*=captcha]')?.name,
     refresh: !!document.querySelector('[class*=refresh], [class*=reload], button[title*=new]')
   })
   ```
2. **Read the text from the screenshot** carefully. Characters may have:
   - Strikethrough lines, noise dots, gradient backgrounds
   - Mixed fonts, sizes, rotations per character
   - Overlapping characters
3. **Type your best reading** into the input field using Fill
4. **Common character substitution attempts if wrong**:
   - 0/O/D/Q, 1/I/l/L, 5/S, 8/B, 2/Z, 6/G, 9/g, rn/m, cl/d
5. **Use the refresh button** if the text is too distorted after 2-3 failures
6. **Check case sensitivity** - try uppercase if lowercase fails, or vice versa

Key pitfalls:
- Image text may use multiple fonts in the same CAPTCHA to increase ambiguity.
- Background noise lines are designed to confuse OCR - focus on the main character shapes.
- Some CAPTCHAs are case-insensitive but some are not. Try both.
- Do not submit the same answer twice. Track attempts in memory.
