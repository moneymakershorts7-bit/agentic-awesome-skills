Word search puzzle: Words are auto-found and auto-dragged by the engine. Read `document.title`.

**(Skip image-grid-selection skill -- this is a word search, NOT an image grid.)**

Title formats:
- `WS_DONE:{"dragged":["STOPSIGN","BIKE"]}` -- engine dragged all words. Click verify!
- `WS:{"n":100,...,"words":[],"found":{}}` -- grid found but words not detected.
- `WS_ERR:...` or `WS:{"n":0,...}` -- grid not loaded.

**Rules (check title EVERY round):**
- **WS_DONE** -> words selected by engine! Click verify: `[{"Click":"#captcha-verify-button"}]`
- **WS: with found empty** -> words not detected. Use Evaluate to read page instruction text.
- **WS_ERR or n is 0** -> grid not loaded: `[{"Wait":1000}]`
- After verify, if still on word search, refresh: `[{"Click":".captcha-refresh"},{"Wait":800}]`

**Do NOT write any drag/click JS. Word selection is automatic.**
