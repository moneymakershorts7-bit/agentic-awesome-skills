Strategy for hCaptcha challenges:

1. **Detect hCaptcha** using Evaluate:
   ```js
   document.title = JSON.stringify({
     iframe: !!document.querySelector('iframe[src*=hcaptcha], iframe[data-hcaptcha]'),
     checkbox: !!document.querySelector('[class*=hcaptcha], [id*=hcaptcha]'),
     sitekey: document.querySelector('[data-sitekey]')?.getAttribute('data-sitekey'),
     container: document.querySelector('[class*=h-captcha]')?.getBoundingClientRect()
   })
   ```
2. **Click the hCaptcha checkbox** - similar to reCAPTCHA, this may pass without a challenge
3. **If image challenge appears**: Read the task description (e.g., "Please click on all images containing a boat")
4. **Select all matching images** from the grid. hCaptcha typically shows a 3x3 or 4x4 grid
5. **Click Verify/Check** after selecting all matches
6. **Handle multiple rounds**: hCaptcha may present 2-3 rounds of challenges

Key pitfalls:
- hCaptcha uses iframes similar to reCAPTCHA - elements are inside the iframe context.
- Image challenges may use AI-generated or unusual images that are harder to classify.
- Clicking too fast triggers bot detection. Space clicks 300-500ms apart.
- hCaptcha accessibility mode may offer an easier alternative - look for accessibility links.
- Failed attempts increase difficulty and may add more rounds.
