Where's Waldo: Find Waldo in a crowded beach scene grid.

**Waldo's appearance:**
- Tall man with dark brown hair and black glasses
- Red and white horizontally STRIPED shirt (most distinctive feature)
- Blue jeans
- Red and white striped beanie/hat
- Often partially hidden behind other characters

**STRATEGY:**
1. Scan the screenshot carefully for red-and-white stripes.
2. Waldo is typically in the upper-right area of the image.
3. Once found, click the grid square(s) containing Waldo.
4. He spans 2 vertical squares — select BOTH (head square + body square).

**Steps:**
```json
"steps": [
  {"ClickPoint":{"x":WALDOx,"y":WALDOy_HEAD}},
  {"ClickPoint":{"x":WALDOx,"y":WALDOy_BODY}},
  {"Wait":500},
  {"Click":"#captcha-verify-button"}
]
```

**Tips:**
- Look for the RED AND WHITE STRIPES pattern — it's the most visible feature.
- Don't confuse with other striped items (umbrellas, towels). Waldo is a PERSON.
- If verify fails, you may have missed a square. Check for his hat above.
- After 2 fails -> refresh: `[{"Click":".captcha-refresh"},{"Wait":1000}]`
