Muffins? challenge: Select all CHIHUAHUAS — not the muffins!

**The classic chihuahua vs muffin visual trick.** Images of chihuahuas and blueberry muffins look very similar.

**How to tell them apart:**
- **Chihuahuas**: Have EYES (shiny, reflective), a NOSE (small dark triangle), EARS (pointed, stand up), fur texture varies
- **Muffins**: Have a WRAPPER/PAPER cup at bottom, more uniform round dome shape, visible blueberries/chocolate chips as dark spots, crumbly top texture

**Key differences:**
- Chihuahuas have a visible snout/mouth area; muffins have a flat dome
- Chihuahuas' eyes are positioned symmetrically and REFLECT light; muffin spots don't
- Muffin wrappers have ridged edges at the base
- Chihuahua ears are triangular and stick up; muffins have no pointy features

**Steps:**
```json
"steps": [
  {"Click":".grid-item:nth-child(N)"},
  ... (all chihuahua tiles)
  {"Wait":300},
  {"Click":"#captcha-verify-button"}
]
```

**SOLVE IN 2 ROUNDS MAX.** If verify fails, toggle your selections and retry.
After 2 fails -> refresh: `[{"Click":".captcha-refresh"},{"Wait":1000}]`
