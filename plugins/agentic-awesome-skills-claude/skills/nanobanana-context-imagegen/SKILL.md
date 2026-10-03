---
name: nanobanana-context-imagegen
description: "Generate spectacular, context-driven images for documents, books, and creative projects using Google Gemini Nano Banana & Imagen 3 models, with a strict zero-guessing clarification gate."
allowed-tools:
  - Read
  - Write
  - Bash
  - WebFetch
  - Grep
  - env
allowed-domains:
  - generativelanguage.googleapis.com
  - ai.google.dev
category: "media"
risk: "safe"
source: "official"
source_repo: "moneymakershorts7-bit/agentic-awesome-skills"
source_type: "official"
date_added: "2026-10-03"
author: "Antigravity & Google DeepMind"
license: "MIT"
license_source: "https://github.com/moneymakershorts7-bit/agentic-awesome-skills/blob/main/LICENSE"
tags:
  - image-generation
  - nanobanana
  - gemini-media
  - imagen-3
  - context-driven
  - book-illustrations
tools:
  - antigravity
  - claude-code
  - cursor
  - codex-cli
  - gemini
---

# Nanobanana Context ImageGen

> **Context-Aware Visual Generation with Google Nano Banana & Imagen 3 Models**  
> Formulate spectacular, narrative-grounded imagery from books, documents, and creative projects with a strict **Zero-Guessing Clarification Gate**.

---

## Overview

When illustrating manuscripts, technical documents, or creative literature, generic image prompts produce stock, disconnected visuals. **`nanobanana-context-imagegen`** solves this by analyzing the document's immediate textual context (historical setting, narrative tension, thematic metaphors, entity specifications, and spatial layout) and routing the generation to Google's premier media models:

- **Google Gemini Nano Banana Pro (`gemini-3-pro-image`):** Ultra-high fidelity, complex character consistency, photorealism, multi-object composition, and typography rendering in 1K/2K/4K.
- **Google Gemini Nano Banana 2 (`gemini-3.1-flash-image`):** Rapid, high-fidelity narrative vignettes and editorial illustrations.
- **Google Imagen 3 (`imagen-3.0-generate-002`):** Direct state-of-the-art text-to-image synthesis with painterly or cinematic photorealism.

### 🛑 The Zero-Guessing Rule (Zero-Hallucination Policy)
If the document context leaves visual style, framing, or focal subject open to multiple conflicting interpretations, **the agent MUST NOT guess or invent creative decisions**. It must pause and present **concise, direct multiple-choice questions** before invoking any generation model.

---

## When to Use This Skill

- **Book & Document Illustration:** Creating cover art, chapter frontispieces, in-text narrative vignettes, or scene visualizations based on active chapters or manuscripts.
- **Contextual Concept Art:** Generating assets that must honor exact textual descriptions (materials, architecture, garments, era, atmospheric lighting).
- **Multi-Asset Book Production:** Maintaining visual cohesion across an entire volume (consistent lighting palette, character likeness, or artistic medium).
- **Google Media Integration:** Generating images using Gemini API (`gemini-3-pro-image`, `gemini-3.1-flash-image`) or Google Imagen 3.

---

## When Not to Use

- Creating pure vector diagrams, flowchart schemas, or UI mockups that should be authored natively in SVG, HTML/CSS, or Mermaid.
- Generating images without contextual grounding when the user explicitly provides a complete, self-contained prompt string.
- Tasks requiring deterministic pixel editing on local vector or layered image assets.

---

## Core Workflow

```
┌────────────────────────────────┐
│  1. Context Extraction         │ ───► Extract setting, entities, mood, asset role
└────────────────┬───────────────┘
                 │
                 ▼
┌────────────────────────────────┐
│  2. Clarification Gate         │ ◄─── Is style, framing, or focal point ambiguous?
│     (Zero-Guessing)            │      YES: Ask concise, multi-choice question.
└────────────────┬───────────────┘      NO: Proceed to prompt synthesis.
                 │
                 ▼
┌────────────────────────────────┐
│  3. 7-Layer Master Prompt      │ ───► Subject, Setting, Lighting, Optics, Texture,
└────────────────┬───────────────┘      Palette, and Negative Constraints
                 │
                 ▼
┌────────────────────────────────┐
│  4. Google Model Routing       │ ───► Route to Nano Banana Pro / Flash / Imagen 3
└────────────────┬───────────────┘
                 │
                 ▼
┌────────────────────────────────┐
│  5. Execution & Verification   │ ───► Generate, verify integrity, write .json sidecar
└────────────────────────────────┘
```

### Phase 1: Context Extraction & Grounding
Analyze the active document or excerpt across 5 dimensions:
1. **Target Asset Role:** Book cover (vertical 2:3/3:4), chapter header (widescreen 16:9/21:9), scene plate (4:3), or character portrait (1:1/3:4).
2. **Historical / Thematic World:** Period architecture, authentic materials, cultural motifs (e.g. Neo-Babylonian glazed brick vs Cyberpunk neon).
3. **Focal Entities:** Characters, objects, or symbolic phenomena explicitly described in the text.
4. **Emotional & Atmospheric Tone:** Reverent, ominous, triumphant, serene, epic, or analytical.
5. **Spatial Composition:** Background environment, foreground depth, and negative space for typography.

### Phase 2: The Zero-Guessing Clarification Gate
If any key creative parameter is ambiguous, **stop immediately and ask**. Never invent an unstated style or subject.

**Rules for Concise Inquiries:**
- **Never ask open-ended questions** (e.g. *"What style do you want?"* or *"How should the image look?"*).
- **Provide 2 to 3 concise, concrete options** with brief rationales tied to the document.
- **Limit question scope** strictly to: Medium/Artistic Style, Focal Scene/Subject, or Aspect Ratio.

*Example Question:*
> *"For Daniel Chapter 10, the text presents both the celestial vision and Daniel's awe on the riverbank. Which scene should we illustrate?"*
> 1. **Option A (Celestial Focus):** Panoramic vision of the radiant messenger in beryl and lightning above the Tigris river (16:9 widescreen).
> 2. **Option B (Narrative Focus):** Intimate dramatic shot of Daniel prostrate on the riverbank in reverent awe (3:4 book plate).

### Phase 3: The 7-Layer Master Prompt Spec
Translate the grounded concept into a production-grade prompt:

```text
Subject: [Precise subject, anatomy, historical attire, authentic materials, posture]
Setting/Environment: [Specific architectural era, terrain, atmospheric density, depth]
Lighting & Atmosphere: [Lighting design: Caravaggio chiaroscuro, golden hour volumetric haze, ethereal divine luminescence]
Camera & Optics: [Focal length, 70mm anamorphic, Hasselblad medium format, shallow depth of field]
Artistic Medium: [Masterpiece oil on linen, hyperrealistic 35mm film still, fine line copperplate engraving]
Color Palette: [Dominant tones, contrasting accents, period pigments]
Constraints & Avoid: [No modern anachronisms, no distorted anatomy, no cartoonish exaggeration, no unrequested text]
```

### Phase 4: Google Media Routing
- **Nano Banana Pro (`gemini-3-pro-image`):** Recommended for book covers, primary narrative illustrations, multi-character interaction, and rich textures.
- **Nano Banana 2 (`gemini-3.1-flash-image`):** Recommended for fast section vignettes, blog banners, and iterative drafts.
- **Imagen 3 (`imagen-3.0-generate-002`):** Recommended for direct text-to-image studio photography and classical painterly aesthetics.

### Phase 5: Execution & Persistence
Run the generation via `scripts/generate_context_image.py` or the native `image-generator` subagent. Persist the image to the project folder (`images/` or `assets/`) and write an audit sidecar (`<name>.json`) documenting the prompt, model, and source passage.

---

## Script Usage (`scripts/generate_context_image.py`)

The skill includes a standalone, zero-dependency Python script:

```bash
# 1. Analyze text context and produce prompt + clarification check
python3 scripts/generate_context_image.py --context-file chapter10.md --analyze

# 2. Generate image using Google Nano Banana Pro
python3 scripts/generate_context_image.py \
  --prompt "A majestic vision of Daniel beside the Tigris river..." \
  --model gemini-3-pro-image \
  --aspect-ratio 16:9 \
  --output-dir images/daniel-ch10 \
  --filename scene_vision_tigris.png

# 3. Interactive mode with automatic context extraction
python3 scripts/generate_context_image.py --interactive
```

---

## Detailed References

- [`references/context-extraction.md`](references/context-extraction.md): Deep-dive rules for narrative and non-fiction text analysis.
- [`references/disambiguation-gates.md`](references/disambiguation-gates.md): Question formulation patterns, decision trees, and anti-patterns.
- [`references/prompt-engineering.md`](references/prompt-engineering.md): 7-layer visual specification formulas and lighting guides.
- [`references/google-media-models.md`](references/google-media-models.md): Complete technical specifications for Nano Banana Pro, Flash, and Imagen 3.

---

## Best Practices

- ✅ **Context First:** Always ground the prompt in verifiable text details (names, garments, environment) before introducing stylistic flair.
- ✅ **Respect Aspect Ratios:** Use `2:3` or `3:4` for book covers/plates; use `16:9` or `21:9` for section banners.
- ✅ **Ask Concisely:** When uncertain, ask with 2-3 structured choices. Never guess, and never ask open-ended questions.
- ✅ **Sidecar Logging:** Always keep the JSON sidecar alongside the generated image for reproducibility.
- ❌ **Do Not Hallucinate Details:** If a character's physical appearance is unstated in the text, offer explicit visual choices rather than defaulting blindly.
- ❌ **No Text in Image:** Avoid requesting embedded typography inside generated images unless specifically required for a sign or book spine.

---

## Limitations

- Generation requires an active Google AI Studio / Gemini API key (`GEMINI_API_KEY`) or access to Antigravity's native `image-generator` subagent.
- Model IDs and capabilities follow Google's lifecycle (`gemini-3-pro-image`, `gemini-3.1-flash-image`, `imagen-3.0-generate-002`).
- The script does not alter or re-encode existing vector assets; it produces raster images (`PNG`/`JPEG`).
- Generative models do not guarantee exact seed-level reproducibility between distinct sessions.

---

## Security & Safety Notes

- **Network:** Outbound API calls are restricted to Google's official endpoints (`generativelanguage.googleapis.com`). No external third-party proxies are used.
- **Secrets:** API keys (`GEMINI_API_KEY`) are read strictly from environment variables or local `.env` files; they are never written to disk, sidecars, or logs.
- **Filesystem Hygiene:** Generated outputs are strictly written into user-specified project directories (`assets/`, `images/`, or `generations/`). No system files are mutated.
