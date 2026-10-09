Whack-a-Mole: Click moles as they pop up. Hit 5 moles to pass.

**Auto-detection runs via pre_evaluate.** Read `document.title` for state.

Title format: `WAM:{"moles":N,"clicked":N}`

**Rules (check title EVERY round):**
- **clicked > 0** — moles were auto-clicked! Wait for more to appear: `[{"Wait":800}]`
- **moles is 0** — no moles visible yet. Wait: `[{"Wait":500}]`
- **WAM_ERR** — detection failed. Use screenshot to find moles visually.

**If auto-detection misses moles (you see them in screenshot):**
- Use ClickPoint on each visible mole: `[{"ClickPoint":{"x":300,"y":400}},{"Wait":300}]`
- Moles pop up briefly — click fast, don't wait between clicks.
- You need to hit 5 total. If you accidentally click grass, it may deselect.

**After 5 hits, click verify:** `[{"Click":"#captcha-verify-button"}]`
