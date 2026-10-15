# Typography Pairing & Proportion Matrix (Robert Bringhurst Standard)

Based on Robert Bringhurst's *The Elements of Typographic Style*, typography on video canvases is vocal inflection and visual architecture.

---

## 1. The Typographic Scale (Musical Proportions)

Type sizes must never be chosen arbitrarily. They must follow a strict geometric harmonic ratio:

### Standard Video Scale (Minor Third: Ratio $r = 1.200$)
* Best for: Technical, Swiss Editorial, and dense data layouts.
* Sizes (1080p canvas):
  - **Micro Stamp**: 12px (Uppercase, tracking +0.12em)
  - **Body / Subtitle**: 16px (Regular/Medium, line-height 1.4)
  - **Subheadline**: 20px (SemiBold, line-height 1.3)
  - **H3 Section Header**: 24px (Bold, tracking -0.01em)
  - **H2 Major Title**: 29px (Bold, tracking -0.02em)
  - **H1 Hero Headline**: 35px (ExtraBold, tracking -0.03em)
  - **Hero Display**: 42px – 50px (Display weight)

### High-Impact Thumbnail Scale (Golden Ratio: Ratio $r = 1.618$)
* Best for: YouTube thumbnail titles (2–4 words max) where glanceability is paramount.
* Sizes (1280×720 canvas):
  - **Curiosity Badge / Stamp**: 24px (Uppercase, bold, pill container)
  - **Supporting Descriptor**: 38px (SemiBold)
  - **Dominant Impact Word**: 62px – 80px (Black / Ultra-Bold, tracking -0.03em)

---

## 2. Archetype Pairing Matrix

| Archetype | Primary / Hero Typeface | Secondary / Body Typeface | Technical / Stamp Monospace |
| :--- | :--- | :--- | :--- |
| **Documentary Noir** | **Fraunces** (Variable Optical Size 72, Weight 800) | **Inter** (Regular, 16px) | **JetBrains Mono** (Medium, 12px, Uppercase) |
| **Swiss Editorial** | **Neue Haas Grotesk** (Display 75 Bold) | **Merriweather** (Regular, 16px) | **Space Grotesk** / **Space Mono** (Medium) |
| **Technical Systems** | **JetBrains Mono** (ExtraBold, 36px) | **Inter** / **Geist** (Medium, 15px) | **Fira Code** (Regular, syntax-highlighted) |
| **Cinematic Essay** | **Cinzel** (SemiBold, tracking +0.08em) | **EB Garamond** (Regular/Italic, 18px) | *None* (Use small-caps Garamond) |
| **Minimalist Vector** | **Outfit** / **Plus Jakarta Sans** (ExtraBold) | **General Sans** (Medium, 16px) | **Space Grotesk** (Tabular numbers) |

---

## 3. Optical Tracking & Leading Rules

1. **The Inverse Tracking Law**:
   - As font size increases, tracking **must decrease**:
     - Large display titles (48px+): `-0.02em` to `-0.04em` (eliminates awkward gaps between glyphs).
     - Standard body text (16px–24px): `0.00em` (optical default).
     - Small stamps / all-caps tags (10px–14px): `+0.08em` to `+0.16em` (prevents glyph clustering and ensures legibility at low resolution).

2. **Line-Height (Leading) Ratios**:
   - **Thumbnails (1–2 lines)**: Strict line-height of `0.95` to `1.05`. Words must feel like a single cohesive graphic block.
   - **On-Screen Lower Thirds**: Line-height of `1.15` to `1.20`.
   - **Full-Screen Quotations**: Line-height of `1.35` to `1.45`.

3. **Case Sensitivity & Tone**:
   - **ALL-CAPS**: Reserved strictly for stamps, categories, status badges, and 1–2 word thumbnail urgency triggers.
   - **Title Case**: Reserved for documentary and editorial titles.
   - **Sentence Case**: Reserved for conversational explainers and intimate cinematic essays.

---

## 4. Legibility & Contrast Guardrails

* **Minimum Contrast Ratio**:
  - Text must achieve at least **4.5:1** against underlying footage or graphics (WCAG AA).
  - High-impact thumbnail text must achieve **7:1** against its local backing plate or shadow gradient.
* **Text Backing Methods (Anti-Clutter)**:
  1. *Subtle Directional Vignette*: Darken background video under text with an opacity ramp (0% to 50% black gradient).
  2. *Matte Pill Container*: Place text inside an archetype-colored pill box (e.g. newsprint yellow with black text, or terminal black with emerald text).
  3. *Zero Uncalibrated Outlines*: Avoid thick comic-book black outlines (stroke > 3px). Prefer soft contact drop shadows (`rgba(0,0,0,0.4)` blur 12px, offset Y 4px).
