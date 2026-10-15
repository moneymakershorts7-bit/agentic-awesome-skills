Rotation puzzle: tiles form an image, some rotated 90/180/270. Each click = +90 clockwise.
Read `document.title` for auto-detected rotation state.

Title format: `ROT:{"n":9,"done":false,"clicks":"1:1,2:2,6:3,7:2,8:3"}`
- `n` = number of tiles
- `done` = true when all tiles are upright -> click verify
- `clicks` = "tileIndex:clicksNeeded" pairs (0-indexed tiles, use nth-child = index+1)

**Rules:**
- **done is true** -> all upright, verify: `[{"Click":"#captcha-verify-button"}]`
- **done is false** -> click each tile the number of times shown. Use `.rotating-item:nth-child(N)` (N = index+1, 1-indexed):
```json
"steps": [
  {"Click":".rotating-item:nth-child(2)"},
  {"Click":".rotating-item:nth-child(3)"},{"Click":".rotating-item:nth-child(3)"},
  {"Click":".rotating-item:nth-child(7)"},{"Click":".rotating-item:nth-child(7)"},{"Click":".rotating-item:nth-child(7)"},
  {"Wait":500},
  {"Click":"#captcha-verify-button"}
]
```
- **ROT_ERR or n is 0** -> wait: `[{"Wait":1000}]`
- After verify, if still on rotation level, refresh and retry: `[{"Click":".captcha-refresh"},{"Wait":800}]`

**Do NOT write any Evaluate JS. Rotation state is auto-detected.**
