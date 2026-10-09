# Skills Reference

Canonical reference for all skills in the `spider_skills` crate.

## How Skills Work

Skills are self-contained LLM prompt fragments with trigger conditions. When the spider agent visits a page, matching skills are automatically injected into the model's context for that round.

```
Page State (URL, title, HTML)
         │
         ▼
  SkillRegistry.match_context()
         │
    ┌────┴────┐
    │ Matched │──▶ Skill content injected into system_prompt_extra
    └─────────┘
```

Each round, `match_context_limited()` evaluates all registered skills against the current page state. Up to 3 skills (4000 chars max) are injected per round, highest priority first.

## Skill Anatomy

```rust
Skill {
    name: "image-grid-selection",      // Unique ID (lowercase, hyphens)
    description: "Select matching...", // Human summary
    triggers: [                        // ANY match activates the skill
        HtmlContains("grid-item"),
        TitleContains("select all"),
    ],
    content: "...",                    // Prompt text injected into LLM context
    pre_evaluate: Some("..."),         // Optional JS run BEFORE LLM inference
    code_snippets: {},                 // Optional named JS snippets
    priority: 5,                       // Higher = injected first (1-10 scale)
}
```

### Trigger Types

| Type | Example | Match Logic |
|------|---------|-------------|
| `TitleContains(s)` | `"select all"` | Case-insensitive substring match on `document.title` |
| `UrlContains(s)` | `"/challenge/"` | Case-insensitive substring match on page URL |
| `HtmlContains(s)` | `"grid-item"` | Case-insensitive substring match on page HTML |
| `Always` | — | Always activates (for manually-loaded skills) |

### Priority Scale

| Range | Usage | Examples |
|-------|-------|---------|
| 1-2 | Low — broad matches, extraction | `table-extraction`, `pagination-navigation` |
| 3-4 | Medium — specific challenges | `text-captcha`, `math-captcha`, `audio-captcha` |
| 5-6 | High — precise matches | `recaptcha-v2`, `cloudflare-turnstile`, `parking-challenge` |
| 7-8 | Very high — game/puzzle skills | `word-search`, `chess-challenge`, `math-solver` |
| 9-10 | Critical — engine-assisted skills | `tic-tac-toe`, `nested-grid`, `whack-a-mole` |

### Pre-Evaluate JS

Some skills have a `pre_evaluate` field — JavaScript executed by the engine via `page.evaluate()` **before** the LLM sees the page. Results are written to `document.title` so the model can read structured data without writing its own extraction code.

Pre-evaluate is set by the consuming engine (e.g., `spider_agent`), not in the `.md` files. See [spider_agent/SKILLS.md](../spider/spider_agent/SKILLS.md) for engine-specific overlays.

## Skill Catalog (110 skills)

### CAPTCHAs (20 skills)

| Skill | Triggers | Pri | Description |
|-------|----------|-----|-------------|
| `text-captcha` | `captcha-input`, `captcha-text`, title:`wiggles` | 3 | Distorted text, math challenges |
| `audio-captcha` | `audio-captcha`, `audiochallenge` | 4 | Audio-based CAPTCHAs |
| `math-captcha` | `math-captcha`, `arithmetic` | 4 | Math expression CAPTCHAs |
| `puzzle-piece-captcha` | `puzzle-piece`, `jigsaw-captcha`, `slide-captcha` | 5 | Slide-to-fit puzzle pieces |
| `image-rotation-captcha` | `rotate-captcha`, title:`rotate the image` | 5 | Rotate image to correct orientation |
| `text-in-image-captcha` | `captcha-image`, `captchaImg` | 4 | Text embedded in noisy images |
| `icon-captcha` | `icon-captcha`, `IconCaptcha` | 4 | Icon/symbol selection |
| `semantic-captcha` | `question-captcha`, `text-captcha-question` | 3 | Question-based semantic CAPTCHAs |
| `click-order-captcha` | title:`click in order`, `click-order` | 4 | Click targets in sequence |
| `sequence-ordering-captcha` | `sortable-captcha`, title:`arrange in order` | 4 | Reorder items correctly |
| `visual-pattern-captcha` | `pattern-captcha`, title:`odd one out` | 4 | Visual pattern recognition |
| `captcha-3d-object` | `3d-captcha`, `captcha-3d` | 4 | 3D object identification |
| `captcha-audio-v2` | `rc-audiochallenge`, `audio-response` | 4 | reCAPTCHA audio fallback |
| `honeypot-captcha` | `honeypot`, `hp-field` | 2 | Detect and avoid honeypot traps |
| `recaptcha-v2` | `g-recaptcha`, `recaptcha`, `rc-anchor` | 5 | reCAPTCHA v2 checkbox + images |
| `recaptcha-v3` | `grecaptcha-badge`, `recaptcha/api.js?render` | 3 | Invisible reCAPTCHA v3 |
| `hcaptcha` | `hcaptcha`, `h-captcha` | 5 | hCaptcha challenges |
| `cloudflare-turnstile` | `cf-turnstile`, `challenges.cloudflare` | 5 | Cloudflare Turnstile |
| `geetest` | `geetest`, `gt_slider` | 5 | GeeTest slide/click/match |
| `arkose-funcaptcha` | `arkoselabs`, `funcaptcha`, `arkose` | 5 | Arkose Labs / FunCaptcha |

### Interactive Puzzles (19 skills)

| Skill | Triggers | Pri | Description |
|-------|----------|-----|-------------|
| `image-grid-selection` | `grid-item`, `challenge-grid`, title:`select all` | 5 | Select matching images from grid |
| `rotation-puzzle` | title:`rotat`, `rotating-item` | 5 | Rotate elements to correct orientation |
| `tic-tac-toe` | title:`xoxo`/`tic-tac`, `cell-selected`/`cell-disabled` | 10 | Play tic-tac-toe (engine-assisted) |
| `word-search` | title:`word search`, `word-search-grid-item` | 8 | Find words in letter grid (engine-assisted) |
| `slider-drag` | `slider-track`, `slider-handle`, `range-slider` | 4 | Slider and drag-to-position |
| `jigsaw-puzzle` | title:`jigsaw`, `puzzle-piece` | 5 | Jigsaw puzzle assembly |
| `sliding-tile-puzzle` | title:`sliding puzzle`/`15 puzzle`/`8 puzzle` | 5 | Sliding tile (15-puzzle) |
| `maze-solving` | title:`maze`, `maze` | 5 | Navigate mazes |
| `sudoku` | title:`sudoku`, `sudoku` | 5 | Solve sudoku grids |
| `crossword` | title:`crossword`, `crossword` | 5 | Solve crossword puzzles |
| `connect-the-dots` | title:`connect the dots`/`dot to dot` | 5 | Connect numbered dots |
| `pattern-matching` | title:`match`/`pattern`, `matching-game` | 3 | Pattern matching/pairing |
| `memory-card-game` | title:`memory game`/`memory card`, `card-flip` | 5 | Memory card matching |
| `number-sequence` | title:`number sequence`/`next number` | 4 | Number sequence patterns |
| `color-matching` | title:`color match`/`colour match` | 4 | Color identification |
| `shape-sorting` | title:`shape sort`/`sort the shapes` | 4 | Shape categorization |
| `spot-the-difference` | title:`spot the difference`/`find the difference` | 5 | Find differences between images |
| `object-counting` | title:`how many`/`count the` | 4 | Count objects in images |
| `drag-drop-sorting` | `sortable`, `draggable`, title:`drag and drop` | 4 | Drag-and-drop reordering |

### Interactive Challenges (41 skills)

These cover the [neal.fun/not-a-robot](https://neal.fun/not-a-robot/) levels (L1-L48):

| Skill | Level | Pri | Description |
|-------|-------|-----|-------------|
| `checkbox-click` | L1 | 2 | Click a checkbox |
| `license-plate` | L8 | 6 | Read license plate from image |
| `nested-grid` | L9 | 9 | Recursive grid subdivision (engine-assisted) |
| `whack-a-mole` | L10 | 9 | Click moles as they appear (engine-assisted) |
| `find-waldo` | L11 | 9 | Find Waldo in crowded scene |
| `chihuahua-muffin` | L12 | 9 | Distinguish chihuahuas from muffins |
| `reverse-selection` | L13 | 9 | Select images NOT containing target |
| `affirmations` | L14 | 6 | Find specific text in captcha |
| `parking-challenge` | L15 | 6 | Navigate object into target zone |
| `3d-object` | L16 | 6 | Identify 3D objects |
| `draw-circle` | L17 | 8 | Draw shape by tracing mouse path (engine-assisted) |
| `push-drag` | L18 | 6 | Repeatedly drag object (Sisyphus) |
| `dark-hidden` | L19 | 6 | Find elements hidden in darkness |
| `inkblot-choice` | L20 | 6 | Interpret Rorschach-style prompts |
| `crafting-recipe` | L21 | 6 | Solve crafting/assembly challenges |
| `counting-items` | L22 | 6 | Count or arrange items |
| `panorama-match` | L23 | 6 | Match panoramic image segments |
| `eye-chart` | L24 | 6 | Read decreasing-size text |
| `creative-draw` | L25 | 6 | Draw something original |
| `network-connect` | L27 | 6 | Connect nodes together |
| `trading-timing` | L28 | 6 | Buy/sell at right time |
| `text-choice` | L29 | 5 | Text-based choice/response |
| `sliding-puzzle` | L30 | 8 | Sliding tile puzzle v2 (engine-assisted) |
| `traffic-signal` | L31 | 6 | Interact with traffic signals |
| `rhythm-pattern` | L32 | 7 | Reproduce rhythm/sound pattern |
| `brand-logo` | L33 | 6 | Identify brand logos |
| `math-solver` | L34 | 7 | Solve math equations (engine-assisted) |
| `card-tracking` | L35 | 7 | Track object through shuffle |
| `match3-game` | L36 | 7 | Match-3 tile puzzle |
| `odd-one-out` | L37 | 7 | Find the impostor/odd item |
| `decision-choice` | L38 | 5 | Choose between options |
| `face-matching` | L39 | 6 | Match/compare faces |
| `slot-machine` | L40 | 6 | Stop spinning at right moment |
| `dig-find` | L41 | 6 | Search for hidden element |
| `turing-text` | L42 | 7 | Write convincing human-like text |
| `assembly-id` | L43 | 6 | Identify IKEA-style items |
| `chess-challenge` | L44 | 8 | Make best chess move |
| `find-person` | L45 | 6 | Find person in crowd |
| `floor-nav` | L46 | 6 | Navigate building floors |
| `bell-pattern` | L47 | 7 | Reproduce bell/sound sequence |
| `final-creative` | L48 | 6 | Creative final challenge |

### Form Automation (7 skills)

| Skill | Triggers | Pri | Description |
|-------|----------|-----|-------------|
| `multi-step-form` | `step-wizard`, `form-wizard`, `multi-step` | 3 | Multi-step form wizards |
| `file-upload` | `file-upload`, `dropzone`, `upload-area` | 3 | File upload dialogs |
| `address-form` | `address-form`, `shipping-address` | 3 | Address form field mapping |
| `payment-form` | `payment-form`, `StripeElement`, `braintree` | 4 | Payment/card input forms |
| `form-validation` | `field-error`, `validation-error` | 2 | Fix validation errors |
| `otp-input` | `otp-input`, `verification-code` | 4 | OTP/verification code input |
| `web-form-autofill` | `registration-form`, `signup-form` | 2 | Systematic form filling |

### Access Barriers (10 skills)

| Skill | Triggers | Pri | Description |
|-------|----------|-----|-------------|
| `cookie-consent` | `cookie-consent`, `cookie-banner`, `gdpr`, `onetrust` | 6 | Cookie consent banners |
| `popup-modal` | `modal-open`, `modal-backdrop`, `popup-overlay` | 6 | Dismiss popups/modals |
| `age-verification` | `age-gate`, `age-verification` | 6 | Age verification gates |
| `login-wall` | `login-form`, `signin-form`, title:`sign in` | 4 | Login/auth gates |
| `paywall-detection` | `paywall`, `subscribe-wall`, `premium-content` | 3 | Paywall navigation |
| `redirect-chain` | `redirect`, title:`redirecting`/`please wait` | 3 | Redirect chains |
| `iframe-interaction` | `<iframe` | 2 | Interact within iframes |
| `lazy-loaded-content` | `loading="lazy"`, `data-src`, `lazyload` | 2 | Lazy-loaded images/content |
| `pagination-navigation` | `pagination`, `page-nav` | 2 | Navigate paginated content |
| `infinite-scroll` | `infinite-scroll`, `load-more` | 3 | Infinite scroll handling |

### Anti-Bot / Security (6 skills)

| Skill | Triggers | Pri | Description |
|-------|----------|-----|-------------|
| `js-challenge-page` | title:`checking your browser`/`just a moment` | 6 | JS challenge interstitials |
| `bot-detection` | `datadome`, `perimeter`, `kasada`, title:`access denied` | 6 | Bot detection systems |
| `rate-limiting` | title:`429`/`too many requests`/`rate limit` | 6 | Rate limiting detection |
| `proof-of-work` | `proof-of-work`, `hashcash` | 5 | Browser proof-of-work |
| `device-verification` | `device-verification`, `trusted-device` | 5 | Device verification |
| `fingerprint-challenge` | `fingerprintjs`, `fpjs` | 3 | Browser fingerprint checks |

### Data Extraction (5 skills)

| Skill | Triggers | Pri | Description |
|-------|----------|-----|-------------|
| `table-extraction` | `<table` | 1 | Structured table data |
| `product-listing` | `product-card`, `product-list`, `product-grid` | 2 | Product listing data |
| `contact-extraction` | title:`contact`, `contact-info`, url:`contact` | 2 | Contact information |
| `search-results` | `search-results`, `search-listing` | 2 | Search result extraction |
| `price-scraping` | `price-tag`, `product-price` | 2 | Price and currency data |

### Visual Challenges (2 skills)

| Skill | Triggers | Pri | Description |
|-------|----------|-----|-------------|
| `chart-data-extraction` | `highcharts`, `chart-container`, `chartjs` | 3 | Extract chart/graph data |
| `drag-to-target` | `drop-zone`, `dropzone`, `drag-target` | 4 | Drag items to drop zones |

## Authoring New Skills

### As Markdown Files

Create a `.md` file in `skills/automation/` with YAML frontmatter:

```markdown
---
name: my-challenge
description: Solves a specific challenge type
triggers:
  - title_contains: "challenge keyword"
  - html_contains: "challenge-css-class"
  - url_contains: "/challenge/"
priority: 5
---

# Strategy

Step-by-step instructions for the LLM...
```

Then register it in `src/web_challenges.rs`:

```rust
pub fn add_my_challenge(registry: &mut SkillRegistry) {
    registry.add(
        Skill::new("my-challenge", "Solves a specific challenge type")
            .with_trigger(SkillTrigger::title_contains("challenge keyword"))
            .with_trigger(SkillTrigger::html_contains("challenge-css-class"))
            .with_priority(5)
            .with_content(include_str!("../skills/automation/my_challenge.md")),
    );
}
```

### Programmatically

```rust
let mut registry = spider_skills::new_registry();

registry.add(
    Skill::new("custom-solver", "My custom challenge solver")
        .with_trigger(SkillTrigger::title_contains("my challenge"))
        .with_trigger(SkillTrigger::html_contains("challenge-widget"))
        .with_content("Instructions for the LLM...")
        .with_priority(5),
);
```

### From Remote Sources

```rust
// From URL
spider_skills::fetch::fetch_skill(&mut registry, "https://example.com/skill.md").await?;

// From S3
let source = spider_skills::s3::S3SkillSource::new("bucket").await;
source.load_into(&mut registry, "skills/").await?;
```

## Best Practices

1. **Efficiency directives** — Always include round limits: "Solve in N rounds max"
2. **Specific triggers** — Avoid overly broad triggers like `html_contains("captcha")` which match unrelated pages. Use specific selectors.
3. **Real actions over JS clicks** — `el.click()` in Evaluate doesn't fire real browser events. Use Click/ClickPoint actions for interactions. `dispatchEvent` works for custom event handlers.
4. **Evaluate = read-only** — Use Evaluate to extract data, not to interact. Inject results into `document.title` for the model to read.
5. **Priority conflicts** — When skills overlap, use higher priority for the more specific skill. Example: `nested-grid` (pri 9) overrides `image-grid-selection` (pri 5).
6. **Pre-evaluate for games** — Time-sensitive or algorithmic challenges (TTT, word search, whack-a-mole) should use `pre_evaluate` to compute state before the LLM round.
