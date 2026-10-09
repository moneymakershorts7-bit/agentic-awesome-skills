License plate challenge: Read the license plate from the car image and type it exactly.

**CRITICAL RULES:**
- Look at the screenshot carefully for the license plate on the back of the car.
- Type the plate EXACTLY as shown — include spaces, dashes, and correct capitalization.
- Letters are uppercase. Include any state/country text only if the input field expects it.

**Steps (solve in 1 round):**
```json
"steps": [
  {"Clear":".captcha-input-text"},
  {"Fill":{"selector":".captcha-input-text","value":"ABC 1234"}},
  {"Click":"#captcha-verify-button"}
]
```

If wrong after 1 try: re-read the plate carefully — common confusions: 0/O, 1/I/L, 8/B, 5/S.
**After 2 fails -> refresh:** `[{"Click":".captcha-refresh"},{"Wait":1000}]`
