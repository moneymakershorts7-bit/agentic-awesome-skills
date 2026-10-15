Nested grid: "Select all squares with a stop sign" — squares SUBDIVIDE when clicked correctly.

**Engine auto-solves this level.** Pre-evaluate detects stop sign overlap and clicks boxes automatically.
Title format: `NEST:{"total":N,"sel":N,"toClick":[ids],"hasSign":true,"boxes":[...]}`

If engine already solved (title starts with NEST_DONE), just click verify:
`[{"Click":"#captcha-verify-button"}]`

If engine missed boxes (verify failed), look at screenshot for any unselected boxes overlapping the stop sign.
Click them with `[data-spider-id='N']` selectors, then re-verify.
