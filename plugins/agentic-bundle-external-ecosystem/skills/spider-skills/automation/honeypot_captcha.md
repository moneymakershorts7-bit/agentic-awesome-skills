Strategy for honeypot CAPTCHA / hidden field challenges:

1. **Detect honeypot fields** using Evaluate:
   ```js
   document.title = JSON.stringify({
     hidden: [...document.querySelectorAll('input')].filter(el => {
       const s = getComputedStyle(el);
       return s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0' ||
              el.offsetWidth === 0 || el.offsetHeight === 0 || el.type === 'hidden' ||
              el.tabIndex === -1 || el.getAttribute('autocomplete') === 'off'
     }).map(el => ({ name: el.name, id: el.id, type: el.type, val: el.value })),
     visible: [...document.querySelectorAll('input:not([type=hidden])')].filter(el => {
       const s = getComputedStyle(el); return s.display !== 'none' && el.offsetWidth > 0
     }).map(el => ({ name: el.name, id: el.id, type: el.type }))
   })
   ```
2. **NEVER fill honeypot fields** - they are traps. Leave them empty/default
3. **Only interact with visible, user-facing fields** that appear on screen
4. **Common honeypot patterns**: fields named "website", "url", "phone2", "address2", or with CSS hiding
5. **Submit the form** with only legitimate fields filled
6. **Check for timing-based checks**: Some forms require a minimum time before submission. Wait 2-3 seconds.

Key pitfalls:
- Honeypot fields are intentionally invisible. Filling them flags you as a bot.
- Some honeypots use CSS positioning (left: -9999px) rather than display:none.
- Check for JavaScript that tracks which fields receive focus - avoid focusing honeypots.
- Time-based honeypots reject forms submitted too quickly after page load.
