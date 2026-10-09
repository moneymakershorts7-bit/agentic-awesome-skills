Strategy for image rotation CAPTCHA (rotate image to upright position):

1. **Detect the rotation CAPTCHA** using Evaluate:
   ```js
   document.title = JSON.stringify({
     image: document.querySelector('[class*=rotate] img, [class*=captcha] img')?.getBoundingClientRect(),
     transform: document.querySelector('[class*=rotate] img, [style*=rotate]')?.style?.transform,
     arrows: [...document.querySelectorAll('[class*=arrow], [class*=rotate-btn], button')].map(el => ({
       text: el.textContent?.trim() || el.title, rect: el.getBoundingClientRect(), cls: el.className?.slice(0,30)
     })),
     slider: document.querySelector('input[type=range], [class*=slider]')?.getBoundingClientRect()
   })
   ```
2. **Analyze the current rotation** from the screenshot - determine how many degrees the image is off
3. **For button-based rotation**: Click the rotate button (usually 90 degrees each click). Click until upright
4. **For slider-based**: Drag the slider to adjust rotation angle continuously
5. **Verify visually** that the image appears naturally upright before submitting
6. **Common rotation amounts**: Images are typically rotated by 30-330 degrees in 30-degree increments

Key pitfalls:
- "Upright" means the natural orientation of the subject (sky on top, ground on bottom).
- Each click may rotate by different amounts (30, 45, 60, or 90 degrees). Observe the change.
- Slider-based rotation needs fine adjustment. Overshoot is common.
- Some CAPTCHAs require near-perfect alignment. Small errors may still fail.
