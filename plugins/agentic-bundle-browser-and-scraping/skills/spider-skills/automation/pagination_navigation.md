Strategy for pagination navigation challenges:

1. **Detect pagination elements** using Evaluate:
   ```js
   document.title = JSON.stringify({
     pages: [...document.querySelectorAll('[class*=pagination] a, [class*=pagination] button, [class*=page-link]')].map(el => ({
       text: el.textContent?.trim(), href: el.href, active: el.classList.contains('active') || el.getAttribute('aria-current') === 'page',
       disabled: el.classList.contains('disabled') || el.hasAttribute('disabled')
     })),
     currentPage: document.querySelector('[class*=active][class*=page], [aria-current=page]')?.textContent?.trim(),
     totalPages: document.querySelector('[class*=total], [class*=count]')?.textContent?.trim(),
     prevNext: {
       prev: !!document.querySelector('[class*=prev]:not([disabled]), [rel=prev]'),
       next: !!document.querySelector('[class*=next]:not([disabled]), [rel=next]')
     },
     perPage: document.querySelector('select[class*=per-page], [class*=show]')?.value
   })
   ```
2. **Navigate pages** by clicking page numbers or Next/Previous buttons
3. **To jump to a specific page**: Click the page number directly if visible
4. **For ellipsis gaps**: Click Last, or type the page number if a "Go to page" input exists
5. **Track current page** to avoid revisiting pages
6. **Extract data from each page** before moving to the next

Key pitfalls:
- Disabled Previous on page 1 and disabled Next on last page. Check before clicking.
- Some paginations use AJAX/URL hash. Content updates without full page reload.
- URL-based pagination (page=N) allows direct navigation via Navigate action.
- Changing "per page" count resets to page 1. Set desired count before paginating.
