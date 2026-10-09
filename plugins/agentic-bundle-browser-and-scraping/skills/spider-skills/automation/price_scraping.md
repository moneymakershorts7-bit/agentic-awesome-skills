Strategy for price/currency data extraction:

1. **Extract price data** using Evaluate:
   ```js
   document.title = JSON.stringify({
     prices: [...document.querySelectorAll('[class*=price], [class*=cost], [class*=amount], [itemprop=price]')].map(el => ({
       text: el.textContent?.trim(), content: el.getAttribute('content'),
       currency: el.closest('[itemprop=offers]')?.querySelector('[itemprop=priceCurrency]')?.content,
       sale: el.classList.contains('sale') || el.classList.contains('discount'),
       original: el.parentElement?.querySelector('[class*=original], [class*=was], del, s')?.textContent?.trim()
     })),
     schema: (() => { try {
       const ld = JSON.parse(document.querySelector('[type="application/ld+json"]')?.textContent || '{}');
       return ld.offers ? { price: ld.offers.price, currency: ld.offers.priceCurrency } : null;
     } catch(e) { return null; } })(),
     currency: document.querySelector('[class*=currency]')?.textContent?.trim()
   })
   ```
2. **Check schema.org data first** - JSON-LD provides clean structured pricing
3. **Parse price text**: Strip currency symbols, commas, and spaces. Handle "From $X" patterns
4. **Identify sale vs original prices**: Look for strikethrough text, "was/now" labels
5. **Handle price ranges**: "$10 - $20" or "From $5.99"
6. **Convert currency** if needed: Note the currency code (USD, EUR, GBP)

Key pitfalls:
- Prices may be split across elements ($, 99, .99 in separate spans). Combine parent text.
- Some sites load prices dynamically via AJAX. Wait for price elements to populate.
- Member vs non-member pricing may show different values. Check for membership indicators.
- Currency symbols vary ($ can be USD, CAD, AUD). Check the currency code if available.
