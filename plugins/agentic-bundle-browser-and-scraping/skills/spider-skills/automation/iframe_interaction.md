Strategy for iframe interaction challenges:

1. **Detect and catalog iframes** using Evaluate:
   ```js
   document.title = JSON.stringify({
     iframes: [...document.querySelectorAll('iframe')].map((el,i) => ({
       i, src: el.src?.slice(0,80), name: el.name, id: el.id, title: el.title,
       rect: el.getBoundingClientRect(), sameOrigin: (() => { try { return !!el.contentDocument; } catch(e) { return false; } })()
     }))
   })
   ```
2. **For same-origin iframes**: Access content via Evaluate:
   ```js
   const iframe = document.querySelector('iframe');
   document.title = 'IFRAME:' + iframe.contentDocument?.body?.innerHTML?.slice(0,500);
   ```
3. **For cross-origin iframes**: Cannot access DOM directly. Use ClickPoint with coordinates relative to the iframe's position on the parent page
4. **Click inside iframes** by calculating: parentOffset + iframeRect + elementPosition
5. **For nested iframes**: Navigate the iframe hierarchy level by level
6. **If the iframe content is the main challenge**, focus interactions within the iframe bounds

Key pitfalls:
- Cross-origin iframes block DOM access due to same-origin policy. Only visual/click interaction works.
- iframe positions may shift with page layout changes. Re-detect positions frequently.
- Some iframes are invisible (0x0 size) and used for tracking. Ignore these.
- Scrolling within an iframe requires the mouse to be over the iframe area.
