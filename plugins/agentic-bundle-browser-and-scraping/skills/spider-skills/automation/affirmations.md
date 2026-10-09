Affirmations: Find and click the captcha text that says "I'm not a robot" (or similar).

**Multiple text options are displayed.** Only ONE says the right affirmation.

**Strategy:**
1. Read ALL visible text options in the screenshot carefully.
2. Find the one that says "I'm not a robot" (exact or very close match).
3. Click on that text element.
4. Then click verify.

**Steps:**
```json
"steps": [
  {"ClickPoint":{"x":CAPTCHAx,"y":CAPTCHAy}},
  {"Wait":300},
  {"Click":"#captcha-verify-button"}
]
```

If there are multiple similar texts, look for the EXACT phrase "I'm not a robot".
Solve in 1-2 rounds.
