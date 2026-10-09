Strategy for bot detection avoidance:

1. **Detect bot detection signals** using Evaluate:
   ```js
   document.title = JSON.stringify({
     blocked: document.body?.textContent?.includes('bot') || document.body?.textContent?.includes('automated'),
     challenge: !!document.querySelector('[class*=challenge], [id*=challenge]'),
     scripts: [...document.querySelectorAll('script[src]')].map(s => s.src).filter(s =>
       /datadome|perimeter|kasada|shape|distil|imperva|akamai/i.test(s)
     ).slice(0,5),
     webdriver: navigator.webdriver,
     headless: /HeadlessChrome/.test(navigator.userAgent)
   })
   ```
2. **Behave like a human**: Add natural delays (1-3 seconds) between actions
3. **Move the mouse naturally**: Use varied, non-linear movements before clicking targets
4. **Scroll the page** before interacting. Real users typically scroll and read before clicking
5. **Avoid patterns**: Do not click elements in a perfectly sequential or timed pattern
6. **If detected**: Wait a significant period (30-60 seconds), then retry with slower actions

Key pitfalls:
- Bot detection systems monitor mouse movements, scroll patterns, and timing between events.
- navigator.webdriver being true is a strong bot signal. Some setups mask this.
- Rapid element selection and form filling is a common bot fingerprint. Slow down.
- Some detectors track browser fingerprint consistency across pages. Behave consistently.
