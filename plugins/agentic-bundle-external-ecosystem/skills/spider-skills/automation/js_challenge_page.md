Strategy for JavaScript challenge / interstitial pages:

1. **Detect JS challenge pages** using Evaluate:
   ```js
   document.title = JSON.stringify({
     isChallenge: document.body?.textContent?.includes('Checking your browser') ||
                  document.body?.textContent?.includes('Please wait') ||
                  document.body?.textContent?.includes('Just a moment'),
     meta: document.querySelector('meta[http-equiv=refresh]')?.content,
     noscript: !!document.querySelector('noscript'),
     scripts: document.querySelectorAll('script').length,
     cookies: document.cookie?.split(';')?.length,
     url: window.location.href
   })
   ```
2. **Wait for the JS to execute**: These pages run scripts that verify the browser and auto-redirect
3. **Do NOT interact with the page** during the challenge. Let the scripts complete
4. **Monitor for redirect**: After 3-10 seconds, the page should redirect to the target URL
5. **If no redirect occurs**: Check for a manual "Continue" link or button that appeared
6. **After redirect, verify** you reached the intended destination page

Key pitfalls:
- JS challenge pages set cookies required for subsequent requests. Do not clear cookies.
- Refreshing during the challenge restarts the process and may increase difficulty.
- These are common on Cloudflare, Akamai, and other CDN/WAF providers.
- The challenge may fail silently if JavaScript execution is restricted.
