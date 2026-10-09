Strategy for GeeTest CAPTCHA challenges (slide, click, match):

1. **Detect GeeTest** using Evaluate:
   ```js
   document.title = JSON.stringify({
     container: !!document.querySelector('[class*=geetest], [id*=geetest]'),
     slider: document.querySelector('[class*=geetest_slider], [class*=geetest_btn]')?.getBoundingClientRect(),
     canvas: !!document.querySelector('[class*=geetest] canvas'),
     type: document.querySelector('[class*=geetest_panel]')?.className
   })
   ```
2. **Identify the GeeTest variant**:
   - **Slide**: Drag puzzle piece to fill the gap (most common)
   - **Click**: Click specific icons/characters in order
   - **Match**: Select the item that matches a given word
3. **For slide type**: Locate the gap position from the screenshot, then ClickDragPoint the slider
4. **For click type**: Read which characters/icons to click and in what order from the prompt area
5. **For match type**: Read the word, then click the matching image from the displayed options
6. **Verify**: GeeTest auto-verifies after interaction. Watch for success/failure indicators

Key pitfalls:
- GeeTest slide detection checks mouse movement trajectory. Use non-linear drag paths.
- The gap position in slide challenges is randomized each load.
- Click-order challenges require precise sequence - wrong order fails the entire challenge.
- GeeTest uses canvas rendering which makes DOM inspection less useful. Rely on screenshots.
