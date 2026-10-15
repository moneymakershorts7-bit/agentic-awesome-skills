Strategy for search result navigation and extraction:

1. **Analyze the search results page** using Evaluate:
   ```js
   document.title = JSON.stringify({
     results: [...document.querySelectorAll('[class*=result], [class*=search-item], [class*=listing]')].slice(0,5).map((el,i) => ({
       i, title: el.querySelector('h2, h3, a[class*=title]')?.textContent?.trim(),
       url: el.querySelector('a')?.href, snippet: el.querySelector('[class*=snippet], [class*=description], p')?.textContent?.trim()?.slice(0,80)
     })),
     total: document.querySelector('[class*=count], [class*=total]')?.textContent?.trim(),
     searchBox: document.querySelector('input[type=search], input[name=q], input[class*=search]')?.value,
     pagination: !!document.querySelector('[class*=pagination], [class*=page-nav]'),
     filters: [...document.querySelectorAll('[class*=filter] a, [class*=facet] a')].map(el => el.textContent?.trim()).slice(0,10)
   })
   ```
2. **Extract key data** from each result: Title, URL, snippet/description
3. **Click into specific results** for more detail, then navigate back
4. **Refine searches**: Type in the search box and submit to narrow results
5. **Apply filters**: Click category or filter links to focus results
6. **Paginate**: Click "Next" or page numbers to access more results

Key pitfalls:
- Search results may include ads/sponsored items at the top. Distinguish organic from paid results.
- Pagination may use AJAX without URL change. Check for dynamically loaded content.
- Some search engines randomize result order. Results may differ between pages.
- Featured snippets or knowledge panels may appear above regular results.
