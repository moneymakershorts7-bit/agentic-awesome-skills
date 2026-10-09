Strategy for contact information extraction:

1. **Scan for contact details** using Evaluate:
   ```js
   document.title = JSON.stringify({
     emails: document.body.innerHTML.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g)?.slice(0,5),
     phones: document.body.textContent.match(/[\+]?[(]?[0-9]{1,4}[)]?[-\s./0-9]{7,15}/g)?.slice(0,5),
     links: [...document.querySelectorAll('a[href^="mailto:"], a[href^="tel:"]')].map(a => a.href),
     social: [...document.querySelectorAll('a[href*=twitter], a[href*=linkedin], a[href*=facebook], a[href*=instagram]')].map(a => a.href),
     address: document.querySelector('[class*=address], address, [itemtype*=PostalAddress]')?.textContent?.trim(),
     schema: document.querySelector('[type="application/ld+json"]')?.textContent?.slice(0,200)
   })
   ```
2. **Check the Contact page** if not on it already: Look for "Contact", "About Us" nav links
3. **Extract structured data** from schema.org/JSON-LD if available
4. **Check footer**: Contact info is commonly in the page footer
5. **Handle obfuscated emails**: Some sites encode emails as images or use JS to decode them
6. **Extract social media profiles** from icon links in header/footer

Key pitfalls:
- Emails may be obfuscated with [at] or encoded as HTML entities to prevent scraping.
- Phone numbers vary widely in format. Match liberally and normalize the results.
- Contact info may be in a popup/modal triggered by a "Contact Us" button.
- Schema.org data (JSON-LD, microdata) provides structured contact info if available.
