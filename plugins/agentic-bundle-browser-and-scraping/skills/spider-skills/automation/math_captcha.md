Strategy for math CAPTCHA challenges:

1. **Extract the math problem** using Evaluate:
   ```js
   document.title = 'MATH:' + JSON.stringify({
     text: document.querySelector('[class*=captcha], [class*=math], [class*=question], label')?.textContent?.trim(),
     img: document.querySelector('[class*=captcha] img, [class*=math] img')?.alt,
     input: document.querySelector('input[type=text], input[type=number]')?.name
   })
   ```
2. **Parse the math expression** from the text or screenshot. Common operations: +, -, x, *, /, =
3. **Calculate the answer**:
   - Simple arithmetic: "What is 7 + 3?" -> 10
   - Word problems: "seven plus three" -> 10
   - Visual math: Read numbers from distorted image
4. **Enter the numeric answer** using Fill on the input field
5. **Submit the form** by clicking the submit button
6. **If wrong, re-read the problem** - check for visual tricks (e.g., "12 + 5" displayed as image may be "I2 + S")

Key pitfalls:
- Math may be presented as an image with distorted numbers. Read carefully from screenshot.
- Some use word-based numbers ("twelve") - convert to digits for the answer.
- Watch for trick questions: "What color is the sky?" mixed in with math.
- The answer field may require a specific format (integer only, no spaces).
