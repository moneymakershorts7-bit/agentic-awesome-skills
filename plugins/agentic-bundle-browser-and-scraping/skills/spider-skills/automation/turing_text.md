Reverse Turing test: Type text that proves you're human, not a robot.

**Strategy:**
1. Find the text input field.
2. Type something genuinely human — personal, creative, emotional.
3. Good examples: "I love the smell of rain on warm pavement" or "My grandma's cookies always made me smile"
4. Avoid robotic/formal language. Be casual and personal.

```json
"steps": [
  {"Fill":{"selector":"input,textarea","value":"I love watching sunsets while eating ice cream — the orange sky reminds me of childhood summers."}},
  {"Wait":300},
  {"Click":"#captcha-verify-button"}
]
```

Be authentic, not formulaic. Solve in 1-2 rounds.
