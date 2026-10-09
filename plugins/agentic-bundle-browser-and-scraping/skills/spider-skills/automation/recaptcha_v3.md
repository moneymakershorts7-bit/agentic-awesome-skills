Strategy for reCAPTCHA v3 (invisible / score-based):

1. **Detect reCAPTCHA v3** using Evaluate:
   ```js
   document.title = JSON.stringify({
     v3Script: !!document.querySelector('script[src*="recaptcha/api.js?render="]'),
     badge: !!document.querySelector('.grecaptcha-badge'),
     token: !!document.querySelector('input[name=g-recaptcha-response], [id*=recaptcha-token]'),
     sitekey: (document.querySelector('script[src*=render]')?.src?.match(/render=([^&]+)/)||[])[1]
   })
   ```
2. **reCAPTCHA v3 has NO visual challenge** - it scores behavior silently (0.0 to 1.0)
3. **Behave naturally**: Move the mouse, scroll the page, spend time reading content before submitting
4. **Check if token is auto-populated** in hidden form fields:
   ```js
   document.title = 'TOKEN:' + (document.querySelector('[name=g-recaptcha-response]')?.value?.slice(0,20) || 'none')
   ```
5. **If form submission fails due to low score**: Retry after more natural page interaction (scroll, hover, wait)
6. **Proceed with form submission normally** - reCAPTCHA v3 runs in the background

Key pitfalls:
- There is no checkbox or image challenge to solve. The score is based on behavior.
- Submitting forms too quickly after page load results in low scores.
- Straight-line mouse movements and lack of scrolling lower the score.
- The token expires after ~2 minutes. If you waited too long, reload and try again.
