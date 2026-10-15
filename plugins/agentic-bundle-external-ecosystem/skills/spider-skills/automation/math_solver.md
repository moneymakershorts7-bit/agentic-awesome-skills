Mathematics challenge: Solve a math equation or expression.

Title format: `MATH:{"expr":"2 + 3 * 4","answer":"14"}`

**Strategy:**
1. Read the math expression from the title (pre-evaluate extracts and solves it).
2. If answer is provided, type it directly using Fill.
3. If answer is empty, solve the expression yourself and type the result.
4. Submit via verify button.

```json
"steps": [
  {"Fill":{"selector":"input","value":"ANSWER"}},
  {"Wait":300},
  {"Click":"#captcha-verify-button"}
]
```

Solve in 1 round.
