Strategy for pattern matching challenges (find the matching pair/set):

1. **Inspect all items** using Evaluate:
   ```js
   document.title = JSON.stringify({
     items: [...document.querySelectorAll('[class*=card], [class*=item], [class*=option], [class*=choice]')].map((el,i) => ({
       i, cls: el.className, text: el.textContent?.trim()?.slice(0,20),
       bg: getComputedStyle(el).backgroundImage?.slice(0,50),
       img: el.querySelector('img')?.src?.slice(-40),
       data: el.getAttribute('data-value') || el.getAttribute('data-type'),
       rect: el.getBoundingClientRect()
     })),
     prompt: document.querySelector('[class*=prompt], [class*=question], h1, h2')?.textContent?.trim()
   })
   ```
2. **Understand the matching rule**: Same shape, same color, complete the analogy, find the pair
3. **Group items by shared attributes** (data-value, background image, text content)
4. **Click matching items** - usually click two items that form a pair
5. **For "which completes the pattern"**: Analyze the sequence logic and select the answer
6. **Verify each match** before moving to the next pair

Key pitfalls:
- Matching criteria may be visual (color, shape) rather than in the DOM. Use screenshot analysis.
- Some matching games flip cards face-down after a failed match attempt.
- Data attributes may reveal matching pairs when visual analysis is insufficient.
- Timed challenges may require quick matching. Catalog all items first, then match rapidly.
