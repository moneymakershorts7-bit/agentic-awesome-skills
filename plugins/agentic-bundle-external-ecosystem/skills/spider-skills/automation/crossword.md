Strategy for crossword puzzle challenges:

1. **Extract the grid and clues** using Evaluate:
   ```js
   document.title = JSON.stringify({
     cells: [...document.querySelectorAll('[class*=cell], input[maxlength="1"], td')].map((el,i) => ({
       i, val: el.value || el.textContent?.trim(), black: el.classList.contains('black') || el.classList.contains('blocked'),
       num: el.querySelector('[class*=number], sup')?.textContent, rect: el.getBoundingClientRect()
     })),
     across: [...document.querySelectorAll('[class*=across] li, [class*=across] [class*=clue]')].map(el => el.textContent?.trim()),
     down: [...document.querySelectorAll('[class*=down] li, [class*=down] [class*=clue]')].map(el => el.textContent?.trim())
   })
   ```
2. **Map clue numbers to grid positions**: Find numbered cells and trace across/down from each
3. **Solve easiest clues first**: Start with short words and clues you are confident about
4. **Use crossing letters** to help solve harder clues. Each intersection constrains both words
5. **Fill answers** by clicking each cell and typing letters. Tab or arrow keys may advance to next cell
6. **Verify** the completed grid - check that all crossing letters are consistent

Key pitfalls:
- Black cells separate words. Map the grid structure before solving.
- Clue numbering follows left-to-right, top-to-bottom scanning order.
- Some crossword UIs auto-advance the cursor after typing a letter.
- If a cell belongs to both an across and down word, the letter must satisfy both clues.
