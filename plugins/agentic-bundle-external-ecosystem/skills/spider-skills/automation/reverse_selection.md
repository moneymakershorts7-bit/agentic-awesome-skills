Reverse selection: Select all images that do NOT contain the specified object.

**THIS IS THE OPPOSITE of normal selection.** The title says "select images WITHOUT [object]".

**CRITICAL:** You must select tiles that DO NOT have the object. Leave tiles WITH the object unselected.

**Strategy:**
1. Read the instruction carefully — note what object to AVOID.
2. Look at each grid tile in the screenshot.
3. Click tiles that do NOT contain the specified object.
4. Leave tiles containing the object UNCLICKED.

**Common object: traffic lights**
- Tiles WITH traffic lights -> do NOT click
- Tiles WITHOUT traffic lights -> DO click

**Steps:**
```json
"steps": [
  {"Click":".grid-item:nth-child(1)"},
  {"Click":".grid-item:nth-child(3)"},
  {"Click":".grid-item:nth-child(5)"},
  ... (all tiles WITHOUT the object)
  {"Wait":300},
  {"Click":"#captcha-verify-button"}
]
```

**SOLVE IN 2 ROUNDS MAX.** After 2 fails -> refresh: `[{"Click":".captcha-refresh"},{"Wait":1000}]`
