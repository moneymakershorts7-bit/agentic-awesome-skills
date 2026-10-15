Strategy for Cloudflare Turnstile challenges:

1. **Detect Turnstile** using Evaluate:
   ```js
   document.title = JSON.stringify({
     iframe: !!document.querySelector('iframe[src*=turnstile], iframe[src*=challenges.cloudflare]'),
     widget: !!document.querySelector('[class*=cf-turnstile], [data-sitekey]'),
     managed: !!document.querySelector('[class*=cf-challenge], [id*=challenge]'),
     token: document.querySelector('input[name=cf-turnstile-response]')?.value?.slice(0,20)
   })
   ```
2. **Turnstile is often automatic** - it runs a background challenge and auto-completes
3. **If a checkbox appears**, click it. Turnstile's visible mode shows a simple checkbox
4. **Wait for completion**: The widget transitions from loading spinner to checkmark
5. **Check if token is populated** before proceeding with form submission:
   ```js
   document.title = 'CF_TOKEN:' + (document.querySelector('[name=cf-turnstile-response]')?.value ? 'present' : 'missing')
   ```
6. **If stuck on loading**: Reload the page and wait longer. Turnstile may need time to verify

Key pitfalls:
- Turnstile runs entirely inside an iframe - you cannot directly manipulate its internals.
- The managed challenge mode shows a full-page interstitial that auto-redirects on success.
- Turnstile checks browser fingerprints - headless browsers may fail silently.
- Do not click the widget repeatedly. Click once and wait for the result.
