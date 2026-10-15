Strategy for reCAPTCHA v2 challenges (checkbox + image selection):

1. **Detect reCAPTCHA v2** using Evaluate:
   ```js
   document.title = JSON.stringify({
     iframe: !!document.querySelector('iframe[src*=recaptcha], iframe[title*=reCAPTCHA]'),
     checkbox: !!document.querySelector('.recaptcha-checkbox, [class*=rc-anchor]'),
     challenge: !!document.querySelector('iframe[src*=bframe]'),
     sitekey: document.querySelector('[data-sitekey]')?.getAttribute('data-sitekey')
   })
   ```
2. **Click the "I'm not a robot" checkbox** first. This may be sufficient for low-risk sessions
3. **If an image challenge appears**: It loads in a separate iframe. Look for the task description ("Select all images with traffic lights")
4. **Select matching image tiles** by clicking them. New tiles may load to replace selected ones - wait and check
5. **Click Verify** when all matching tiles are selected
6. **If challenge cycles**: You may get multiple rounds. Complete each round patiently

Key pitfalls:
- reCAPTCHA runs inside iframes - direct DOM queries on the parent page won't find challenge elements.
- Rapid clicking patterns are detected as bot behavior. Pace clicks ~500ms apart.
- Image tiles may fade and reload after selection - wait for new tiles before clicking Verify.
- reCAPTCHA v2 may escalate difficulty after failed attempts.
- The checkbox alone may pass if the browser session appears legitimate.
