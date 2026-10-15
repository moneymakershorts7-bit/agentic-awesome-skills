Strategy for cookie consent banner challenges:

1. **Detect cookie consent banners** using Evaluate:
   ```js
   document.title = JSON.stringify({
     banners: [...document.querySelectorAll('[class*=cookie], [class*=consent], [class*=gdpr], [id*=cookie], [class*=cc-]')].map(el => ({
       visible: getComputedStyle(el).display !== 'none' && el.offsetHeight > 0,
       text: el.textContent?.trim()?.slice(0,80),
       buttons: [...el.querySelectorAll('button, a[class*=btn]')].map(b => ({
         text: b.textContent?.trim(), cls: b.className?.slice(0,30)
       }))
     })),
     onetrust: !!document.querySelector('#onetrust-banner-sdk'),
     cookiebot: !!document.querySelector('#CybotCookiebotDialog')
   })
   ```
2. **Click "Accept All" or "Accept"** button to dismiss the banner quickly
3. **For "manage preferences"**: If you need to customize, click the settings/manage button
4. **Common consent frameworks**: OneTrust, Cookiebot, CookieYes, Osano - each has standard button classes
5. **If banner blocks the page**: Must be dismissed before interacting with content beneath
6. **Verify banner is dismissed** after clicking accept

Key pitfalls:
- Cookie banners often overlay the bottom or top of the page, blocking Click targets beneath.
- Some banners have deliberately hidden "reject" buttons. The "Accept All" is usually most prominent.
- After accepting, the banner may slide away with animation. Wait briefly before clicking elements underneath.
- Some sites show the banner in an iframe. Check for iframe-based consent managers.
