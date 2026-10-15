Strategy for infinite scroll / lazy-loaded content challenges:

1. **Detect infinite scroll pattern** using Evaluate:
   ```js
   document.title = JSON.stringify({
     scrollHeight: document.documentElement.scrollHeight,
     clientHeight: document.documentElement.clientHeight,
     itemCount: document.querySelectorAll('[class*=item], [class*=card], [class*=post], article').length,
     sentinel: !!document.querySelector('[class*=sentinel], [class*=loader], [class*=loading], [class*=spinner]'),
     pagination: !!document.querySelector('[class*=pagination], [class*=load-more], [rel=next]')
   })
   ```
2. **Scroll to the bottom** to trigger loading more content: Use Scroll action or Evaluate:
   ```js
   window.scrollTo(0, document.documentElement.scrollHeight);
   document.title = 'SCROLLED:' + document.documentElement.scrollHeight;
   ```
3. **Wait for new content** to load (1-2 seconds), then re-check item count
4. **Repeat scrolling** until you have enough content or reach the end (no new items after scroll)
5. **For "load more" buttons**: Click the button instead of scrolling
6. **Extract data** from all loaded items after sufficient content is loaded

Key pitfalls:
- Scrolling too fast may skip loading triggers. Scroll incrementally and wait between scrolls.
- Some infinite scrolls use IntersectionObserver. The sentinel element must be in viewport.
- Content may load asynchronously. Always verify new items appeared before scrolling again.
- The page may have a maximum item limit even with infinite scroll.
