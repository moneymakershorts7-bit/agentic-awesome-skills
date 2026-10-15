Strategy for semantic/question-based CAPTCHA challenges:

1. **Extract the question** using Evaluate:
   ```js
   document.title = JSON.stringify({
     question: document.querySelector('[class*=captcha] label, [class*=question], [class*=captcha] p')?.textContent?.trim(),
     input: document.querySelector('input[type=text], input[name*=captcha]')?.name,
     options: [...document.querySelectorAll('[class*=captcha] [class*=option], [class*=captcha] button')].map(el => el.textContent?.trim()),
     hint: document.querySelector('[class*=hint]')?.textContent?.trim()
   })
   ```
2. **Parse the question type**:
   - Trivia: "What color is the sky?" -> "blue"
   - Reverse: "Type the word 'hello' backwards" -> "olleh"
   - Simple logic: "Which is bigger, a mouse or elephant?" -> "elephant"
   - Anti-spam: "What is the name of this website?" -> Read from page title or logo
3. **Answer the question** by typing in the input field or selecting an option
4. **For math-in-words**: "What is five plus three?" -> "8" or "eight"
5. **Submit the answer** and check if it was accepted
6. **If wrong**: Re-read the question for nuances. Some questions have trick answers

Key pitfalls:
- Answers may need to be in a specific format (number vs word, lowercase vs uppercase).
- Some questions are intentionally tricky ("What is 2+2? Hint: it's not 4" -> could be a trick).
- Website-specific questions ("What is our company name?") require reading the page context.
- Multiple valid answers may exist. Try the most common/simple one first.
