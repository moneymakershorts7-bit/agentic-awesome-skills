Strategy for memory card game challenges (flip and match pairs):

1. **Survey the board** using Evaluate:
   ```js
   document.title = JSON.stringify({
     cards: [...document.querySelectorAll('[class*=card], [class*=tile], [class*=flip]')].map((el,i) => ({
       i, cls: el.className, flipped: el.classList.contains('flipped') || el.classList.contains('matched'),
       face: el.querySelector('[class*=front], [class*=face]')?.textContent?.trim()?.slice(0,20),
       back: el.querySelector('[class*=back]')?.textContent?.trim(),
       img: el.querySelector('img')?.src?.slice(-30),
       data: el.getAttribute('data-value') || el.getAttribute('data-card'),
       rect: el.getBoundingClientRect()
     })),
     matchedCount: document.querySelectorAll('[class*=matched]').length
   })
   ```
2. **Track revealed cards in memory**: Use memory_ops to store card positions and values
3. **Strategy**: Click first card to reveal, memorize it. Click second card:
   - If you know where its match is (from previous reveals), click the match
   - If unknown, click a new card to gather information
4. **After each reveal pair**, update your memory map of card positions
5. **Prioritize known pairs**: Once you've seen both cards of a pair, match them immediately
6. **Check DOM for data attributes** that may reveal card values without flipping:
   ```js
   document.title = JSON.stringify([...document.querySelectorAll('[data-value]')].map((el,i) => ({i, v: el.dataset.value})))
   ```

Key pitfalls:
- Cards flip back face-down after a short delay if they don't match. Memorize quickly.
- Some implementations hide the value in data attributes - check before playing the visual game.
- Matched pairs stay face-up. Don't click already-matched cards.
- The board may shuffle after a failed attempt in some variants.
