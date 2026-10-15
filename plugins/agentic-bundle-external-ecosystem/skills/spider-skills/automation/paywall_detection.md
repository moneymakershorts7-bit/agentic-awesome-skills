Strategy for paywall detection and navigation:

1. **Detect paywall indicators** using Evaluate:
   ```js
   document.title = JSON.stringify({
     paywall: !!document.querySelector('[class*=paywall], [class*=subscribe], [class*=premium], [id*=paywall]'),
     truncated: !!document.querySelector('[class*=truncat], [class*=fade-out], [class*=blur]'),
     overlay: !!document.querySelector('[class*=overlay][class*=pay], [class*=gate]'),
     visibleText: document.querySelector('article, [class*=article], [class*=content]')?.textContent?.trim()?.length,
     cta: [...document.querySelectorAll('a[href*=subscribe], button[class*=subscribe]')].map(el => el.textContent?.trim())
   })
   ```
2. **Check for available content**: Some paywalls show a preview of the first few paragraphs
3. **Look for "free article" alternatives**: Some sites offer a limited number of free reads
4. **Try removing the paywall overlay** via Evaluate (may not always work):
   ```js
   document.querySelectorAll('[class*=paywall], [class*=overlay]').forEach(el => el.remove());
   document.querySelectorAll('[class*=truncat], [class*=blur]').forEach(el => el.style.cssText = 'max-height:none;overflow:visible;-webkit-mask:none;filter:none');
   ```
5. **Extract whatever content is visible** from the article before the paywall cutoff
6. **Report to the user** if full content requires a subscription

Key pitfalls:
- Paywall content may be rendered server-side and never sent to the browser. DOM tricks won't help.
- Some sites detect paywall bypass attempts and show less content as punishment.
- Metered paywalls track article count. Incognito/cookie clearing may reset the meter.
- Dynamic paywalls load the full content then hide it. Check the HTML source before overlays render.
