---
name: yt-taste-aesthetic-direction
description: "Visual taste direction, aesthetic criteria, and anti-AI-slop design engine for YouTube channels. Synthesizes Josef Albers (Interaction of Color), Robert Bringhurst (The Elements of Typographic Style), Josef Müller-Brockmann (Grid Systems in Graphic Design), Edward Tufte (The Visual Display of Quantitative Information), and Neuroesthetics."
allowed-tools:
  - bash
  - read
  - edit
  - write
---

# YouTube Aesthetic Direction & Taste Engine (`yt-taste-aesthetic-direction`)

A rigorous visual taste and design curation skill for YouTube channels. Eliminates amateur "AI slop" (hyper-saturated neon glows, waxy textures, mismatched typefaces, and ungrounded chartjunk) by anchoring video packaging, B-roll grading, and visual prompts in time-tested principles of graphic design, color relativity, typographic harmony, and cognitive aesthetics.

---

## 1. Theoretical Foundations of Visual Taste

```
                     ┌────────────────────────────────────────┐
                     │         NEUROESTHETICS (Zeki)          │
                     │ Peak Shift • Perceptual Grouping • Rest│
                     └───────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┴───────────────────────────────┐
         ▼                               ▼                               ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│   JOSEF ALBERS   │           │ ROBERT BRINGHURST│           │ MÜLLER-BROCKMANN │
│Interaction of    │           │ The Elements of  │           │   Grid Systems   │
│Color Relativity  │           │Typographic Style │           │ Negative Space & │
│60-30-10 Balance  │           │ Scale & Cadence  │           │ Structural Order │
└────────┬─────────┘           └────────┬─────────┘           └────────┬─────────┘
         │                              │                              │
         └──────────────────────────────┼──────────────────────────────┘
                                        ▼
                     ┌────────────────────────────────────────┐
                     │         EDWARD R. TUFTE (1983)         │
                     │ High Data-Ink Ratio • Zero Chartjunk   │
                     │   Honest Evidence & Functional Beauty  │
                     └────────────────────────────────────────┘
```

1. **Color Relativity & Simultaneous Contrast (Josef Albers)**:
   - Colors never exist in isolation; a color's perceived hue, value, and temperature depend entirely on its ground.
   - Never use pure, uncalibrated primaries or full-saturation hex codes (`#FF0000`, `#0000FF`).
   - Standard 60-30-10 rule: 60% neutral ground (slate/matte obsidian/off-white), 30% structural secondary, 10% high-contrast emotional accent.

2. **Typographic Rhythm & Proportion (Robert Bringhurst)**:
   - Typography is frozen voice. Don't mix more than 2 typeface families.
   - Type scale must adhere to musical proportions (Major Second 1.125, Minor Third 1.2, or Golden Ratio 1.618).
   - High-contrast headlines require tightened tracking (-0.02em to -0.04em); small uppercase metadata stamps require open tracking (+0.08em to +0.15em).

3. **Modular Grid & Negative Space (Josef Müller-Brockmann)**:
   - Negative space is not empty void; it is an active structural counterweight.
   - Visual breathing room around subjects heightens authority and perceived production value.
   - Follow strict asymmetric tension over static center-aligned symmetry.

4. **Data-Ink Ratio & Anti-Chartjunk (Edward R. Tufte)**:
   - Maximize data-ink; eliminate gratuitous 3D badges, floating glossy coins, fake wireframe globes, and decorative neon geometric debris.
   - Treat charts, maps, and archival documents with museum-grade typography and realistic material textures.

5. **Visual Economy & Peak Shift (Semir Zeki / V.S. Ramachandran)**:
   - The brain craves clear figure-ground segregation and exaggerated essential attributes (peak shift), but recoils at unnatural plastic perfection (uncanny valley).

---

## 2. Five Curated Style Archetypes

Every channel and video must commit to exactly **one** coherent aesthetic archetype:

| Archetype | Tone & Genre | Color Palette (60-30-10) | Typography Pair | Reference Standard |
| :--- | :--- | :--- | :--- | :--- |
| **1. Documentary Noir** | Investigative, geopolitics, forensic mystery, economic corruption | Obsidian (`#0A0D14`)<br>Matte Charcoal (`#1E222B`)<br>Archive Amber (`#D4AF37`) | Headline: *Fraunces* or *Cormorant*<br>Stamp: *JetBrains Mono* | *Lemmino*, *MagnatesMedia* |
| **2. Swiss Editorial** | Vox-style data journalism, science, policy, cultural essays | Newsprint Cream (`#F7F5F0`)<br>Ink Slate (`#1E293B`)<br>Safety Yellow / Klein Blue (`#FACC15` / `#0047AB`) | Headline: *Neue Haas Grotesk* or *Inter Bold*<br>Body: *Merriweather* | *Vox*, *Johnny Harris*, *The Verge* |
| **3. Technical Systems** | Software, reverse-engineering, hardware, cybersecurity | Terminal Void (`#0B1120`)<br>Steel Grey (`#334155`)<br>Terminal Emerald / Laser Cyan (`#10B981` / `#06B6D4`) | Headline: *JetBrains Mono ExtraBold*<br>Secondary: *Inter* | *Low Level Learning*, *Fireship* |
| **4. Cinematic Essay** | Philosophical, existential, psychological portraits | Filmic Charcoal (`#121316`)<br>Muted Tungsten (`#948979`)<br>Alabaster Warm (`#FAF7F2`) | Headline: *Cinzel* or *Equestria*<br>Secondary: *EBGaramond* | *Aperture*, *Pursuit of Wonder* |
| **5. Minimalist Vector** | High-level explainers, macroeconomics, mental models | Rich Navy (`#0C1427`)<br>Slate Neutral (`#475569`)<br>Crimson / Solar Gold (`#EF4444` / `#F59E0B`) | Headline: *Outfit Bold* or *Plus Jakarta Sans*<br>Secondary: *Cabinet Grotesk* | *Kurzgesagt*, *Polymatter* |

*For deep implementation specs, see [`references/style_archetypes.md`](references/style_archetypes.md).*

---

## 3. The Anti-Slop Banned Aesthetics Matrix

The following visual patterns scream cheap amateur automated AI generation and destroy viewer trust. They are **strictly forbidden**:

| Category | Banned AI Slop Element | Tasteful Industry Alternative |
| :--- | :--- | :--- |
| **Color & Lighting** | Hyper-saturated Midjourney neon purple/cyan bloom; random chromatic aberration; oily plastic gloss. | Grounded 35mm film grain (3–5%), subtle directional tungsten key lighting, muted analog film stock color science (Kodak 5219 / Fuji Eterna emulation). |
| **Subjects & Skin** | Waxy airbrushed porcelain skin; 6-fingered hands; uncanny hyper-symmetric anime face rendering. | High-fidelity photographic texture, skin pores, natural ambient occlusion, realistic focal falloff with shallow depth of field. |
| **Graphics & 3D** | Floating shiny 3D gold coins; glowing wireframe brains; generic stock vector arrows curving upward. | Archival documents with fold lines, authentic satellite imagery with forensic crosshairs, typography-driven data callouts. |
| **Typography** | Default Arial/Impact with rainbow gradient fill and heavy 100% black hard drop shadow; 5+ mixed fonts. | Restrained 2-font system, solid fill, optical tracking, subtle gaussian blur drop-shadow (opacity ≤ 35%, blur 12px). |
| **Packaging Tone** | Screaming open-mouth hyper-exaggerated reaction faces on serious political or economic disasters. | Restrained, intense forensic gaze; subject in shadow; high-contrast environmental evidence; quiet dread. |

---

## 4. Visual Prompt De-Slopping Engine

When generating visual assets or AI art prompts for thumbnails, B-roll, or graphics, wrap and cleanse every prompt with the following prompt modifiers:

### Banned Negative Tokens (Inject into every negative prompt):
```text
oversaturated, neon purple cyan glow, plastic skin, airbrushed, cartoonish, 3d render gloss, 
floating coins, generic stock photo, watermark, blurry text, crooked eyes, extra limbs, 
distorted geometry, harsh flash lighting, cheap cgi, ungrounded reflections
```

### Approved Taste Aesthetic Directives (Append based on archetype):
* **Documentary Noir**: `"cinematic 35mm film still, shot on Arri Alexa with anamorphic lenses, subtle film grain, directional key light, deep shadows, Kodak Vision3 500T color grade, authentic documentary realism, 8k resolution, muted natural tones, forensic composition"`
* **Swiss Editorial**: `"editorial photography, tactile matte paper texture, natural studio softbox lighting, clean geometric negative space, archival newspaper scan aesthetic, Swiss typographic clarity"`
* **Technical Systems**: `"high-contrast minimalist technical macro photography, clean matte dark slate surface, precision engineering, subtle cyan illumination, laser-etched lines, industrial aesthetic"`

---

## 5. Ten-Axis Taste Scorecard (Automatic Criteria Gate)

Before finalizing any video packaging, thumbnail, or visual sequence, evaluate against this 10-axis deterministic gate:

| # | Aesthetic Axis | Requirement | Status |
| :-: | :--- | :--- | :-: |
| 1 | **Archetype Consistency** | Palette, typography, and lighting strictly conform to one single archetype throughout. | `PASS` / `FAIL` |
| 2 | **60-30-10 Color Discipline** | 60% dominant ground, 30% secondary structure, 10% emotional accent. No neon mush. | `PASS` / `FAIL` |
| 3 | **Luminance Contrast Ratio** | Key text/subject satisfies minimum **4.5:1** (WCAG AA) against local background. | `PASS` / `FAIL` |
| 4 | **Typographic Restraint** | Exactly 1 headline font and 1 metadata/body font. Correct tracking (-0.02em / +0.1em). | `PASS` / `FAIL` |
| 5 | **Negative Space Breathing Room** | At least 35% of thumbnail/graphic area is unoccupied by busy foreground objects. | `PASS` / `FAIL` |
| 6 | **Tufte Data-Ink Purity** | All on-screen charts, maps, or data have zero decorative 3D gloss or chartjunk. | `PASS` / `FAIL` |
| 7 | **Material Grounding** | Textures feel organic and physically grounded (grain, paper, matte slate, analog film). | `PASS` / `FAIL` |
| 8 | **Anti-Slop Cleanliness** | Zero banned elements (no plastic skin, no purple/cyan glow, no floating crypto coins). | `PASS` / `FAIL` |
| 9 | **Emotional Tone Calibration** | Visual posture matches subject matter gravity (no party faces on tragedy/crisis). | `PASS` / `FAIL` |
| 10 | **Mobile Scalability (160×90px)** | Key subject and text maintain immediate silhouette comprehension at mobile size. | `PASS` / `FAIL` |

---

## 6. Associated Reference Guides

- [`references/style_archetypes.md`](references/style_archetypes.md): In-depth styling guides, color codes, and visual signatures for each archetype.
- [`references/typography_pairing_matrix.md`](references/typography_pairing_matrix.md): Font pairings, Bringhurst proportions, and layout scales.
- [`references/color_grading_palettes.md`](references/color_grading_palettes.md): Color tokens, Albers relativity formulas, and LUT grading notes.
- [`references/anti_slop_checklist.md`](references/anti_slop_checklist.md): 12-point pre-flight checklist for thumbnail and video assets.
