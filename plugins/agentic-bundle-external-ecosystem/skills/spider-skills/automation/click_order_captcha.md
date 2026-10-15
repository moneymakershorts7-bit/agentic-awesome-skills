Strategy for click-in-order CAPTCHA challenges (click items in specified sequence):

1. **Inspect the challenge** using Evaluate:
   ```js
   document.title = JSON.stringify({
     instruction: document.querySelector('[class*=instruction], [class*=prompt], [class*=order]')?.textContent?.trim(),
     items: [...document.querySelectorAll('[class*=item], [class*=target], [class*=clickable]')].map((el,i) => ({
       i, text: el.textContent?.trim(), cls: el.className?.slice(0,30),
       img: el.querySelector('img')?.alt || el.querySelector('img')?.src?.slice(-30),
       rect: el.getBoundingClientRect(), clicked: el.classList.contains('clicked') || el.classList.contains('selected')
     })),
     progress: document.querySelector('[class*=progress], [class*=step]')?.textContent?.trim()
   })
   ```
2. **Read the required order**: "Click in order: cat, dog, bird" or "Click numbers 1-5 in order"
3. **Identify each item** on the page by matching text, images, or labels to the ordered list
4. **Click items in the exact specified order**, waiting briefly between clicks
5. **Monitor progress**: Some challenges show which step you are on or highlight completed items
6. **If a wrong click is made**: The challenge may reset. Start over with the correct sequence

Key pitfalls:
- Clicking out of order typically resets the entire sequence. Be precise.
- Items may be scattered randomly on the page. Plan all positions before clicking.
- The instruction may use images instead of text to describe the order.
- Some challenges add new items after each correct click. Re-read the state each time.
