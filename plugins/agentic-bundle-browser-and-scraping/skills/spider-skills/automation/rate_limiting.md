Strategy for rate limiting detection and handling:

1. **Detect rate limiting signals** using Evaluate:
   ```js
   document.title = JSON.stringify({
     status: document.title,
     body: document.body?.textContent?.trim()?.slice(0,200),
     h1: document.querySelector('h1')?.textContent?.trim(),
     retryAfter: document.querySelector('meta[http-equiv=retry-after]')?.content,
     is429: document.body?.textContent?.includes('429') || document.body?.textContent?.includes('Too Many'),
     is503: document.body?.textContent?.includes('503') || document.body?.textContent?.includes('Service Unavailable'),
     countdown: document.querySelector('[class*=countdown], [class*=timer]')?.textContent?.trim()
   })
   ```
2. **If rate limited (429/503)**: Wait before retrying. Check for Retry-After header or countdown timer
3. **Slow down requests**: Increase the interval between actions. Wait 5-30 seconds between page loads
4. **Vary request patterns**: Do not repeat the exact same sequence of actions
5. **Check for CAPTCHA**: Rate limiting may escalate to CAPTCHA challenges. Solve them to continue
6. **Back off exponentially**: If still blocked, double the wait time (5s, 10s, 20s, 40s)

Key pitfalls:
- Rate limits may apply per-IP, per-session, or per-account. Clearing cookies may not help.
- Some sites silently throttle rather than returning error pages. Results may be incomplete.
- Aggressive retry without backoff can result in longer or permanent blocks.
- Look for Retry-After values in page content or meta tags to know exactly how long to wait.
