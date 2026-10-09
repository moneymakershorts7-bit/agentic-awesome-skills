Strategy for number sequence challenges (find the next number):

1. **Extract the sequence and input** using Evaluate:
   ```js
   document.title = JSON.stringify({
     sequence: [...document.querySelectorAll('[class*=number], [class*=seq], [class*=term], span')].map(el => el.textContent?.trim()).filter(t => /^\d+$/.test(t)),
     prompt: document.querySelector('[class*=question], [class*=prompt], p, h2')?.textContent?.trim(),
     input: !!document.querySelector('input[type=text], input[type=number]'),
     options: [...document.querySelectorAll('[class*=option], [class*=choice], button')].map(el => el.textContent?.trim()).filter(t => /^\d+$/.test(t))
   })
   ```
2. **Analyze the sequence pattern**: Check for:
   - Arithmetic: constant difference (2, 5, 8, 11 -> +3)
   - Geometric: constant ratio (2, 6, 18, 54 -> x3)
   - Fibonacci-like: each term is sum of previous two
   - Squares/cubes: 1, 4, 9, 16, 25 (perfect squares)
   - Alternating: two interleaved sequences
3. **Calculate differences between consecutive terms** to find the pattern
4. **Compute the next term** based on the identified pattern
5. **Enter the answer** in the input field or click the correct option
6. **If multiple patterns seem to fit**: Try the simplest one first (arithmetic > geometric > other)

Key pitfalls:
- Some sequences have non-obvious patterns (primes, triangular numbers, Fibonacci variants).
- The sequence may involve fractions or negative numbers.
- Double-check by verifying the pattern holds for all given terms, not just adjacent pairs.
- If the answer is wrong, try an alternative pattern interpretation.
