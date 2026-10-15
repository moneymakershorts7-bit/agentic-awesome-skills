Strategy for lazy-loaded content challenges:

1. **Check for lazy loading indicators** using Evaluate:
   ```js
   document.title = JSON.stringify({
     lazyImgs: document.querySelectorAll('img[loading=lazy], img[data-src], img[data-lazy]').length,
     placeholders: document.querySelectorAll('[class*=placeholder], [class*=skeleton], [class*=shimmer]').length,
     loadedImgs: [...document.querySelectorAll('img')].filter(img => img.complete && img.naturalHeight > 0).length,
     totalImgs: document.querySelectorAll('img').length,
     observer: !!window.IntersectionObserver
   })
   ```
2. **Scroll elements into view** to trigger lazy loading:
   ```js
   document.querySelectorAll('img[data-src]').forEach(img => {
     img.src = img.dataset.src; img.removeAttribute('data-src');
   });
   document.title = 'FORCED_LOAD:' + document.querySelectorAll('img[src]:not([data-src])').length;
   ```
3. **Scroll the page gradually** to trigger IntersectionObserver-based lazy loading
4. **Wait for images/content to load** (500ms-2s after scrolling into view)
5. **Force-load content** if needed by setting src from data-src attributes via Evaluate
6. **Verify content is loaded** by checking image naturalHeight or element innerHTML

Key pitfalls:
- Lazy content won't appear in screenshots until scrolled into view and loaded.
- Skeleton/placeholder elements indicate content is still loading. Wait for them to be replaced.
- Force-loading via Evaluate may not trigger associated event handlers.
- Virtualized lists (react-window, etc.) only render items currently in viewport. Scroll to see more.
