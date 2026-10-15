Strategy for product listing data extraction:

1. **Map the product listing structure** using Evaluate:
   ```js
   document.title = JSON.stringify({
     products: [...document.querySelectorAll('[class*=product], [class*=item], article[class*=card]')].slice(0,5).map((el,i) => ({
       i, name: el.querySelector('[class*=name], [class*=title], h2, h3')?.textContent?.trim(),
       price: el.querySelector('[class*=price], [class*=cost]')?.textContent?.trim(),
       img: el.querySelector('img')?.src?.slice(-40),
       link: el.querySelector('a')?.href?.slice(-50),
       rating: el.querySelector('[class*=rating], [class*=star]')?.textContent?.trim()
     })),
     total: document.querySelectorAll('[class*=product], [class*=item]').length,
     pagination: !!document.querySelector('[class*=pagination], [class*=load-more]')
   })
   ```
2. **Extract key fields per product**: Name, price, image URL, rating, availability, product URL
3. **Handle price formats**: Strip currency symbols, handle sale/original price pairs
4. **Paginate through all results**: Click next page or scroll for infinite loading
5. **For detailed data**: Click into each product page, extract details, then navigate back
6. **Compile all products** into a structured list

Key pitfalls:
- Product cards may have varying structures within the same page. Adapt selectors per element.
- Prices may show as "From $X" or "$X - $Y" range. Extract all price components.
- Out-of-stock products may have different markup. Check availability indicators.
- Lazy-loaded images may show placeholder URLs. Scroll items into view first.
