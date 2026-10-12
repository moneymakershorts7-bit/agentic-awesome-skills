---
name: higgsfield-director
description: Professional director skill for Higgsfield AI and Seedance 2.0/2.5. Converts narrative treatments, scripts, and scene breakdowns into numbered shotlists, copy-ready cinematographic prompts with FOV optic locks, asset checklists, and self-contained interactive HTML production boards. Supports multi-model conversion (Higgsfield Seedance, Kling, Wan, Sora, Veo, Mochi).
allowed-tools:
  - bash
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
---

# Higgsfield AI & Seedance Director

Professional cinema direction harness tailored for **Higgsfield AI** and its flagship models (**Seedance 2.0 / 2.5**, Soul Cinema, and Higgsfield Elements).

## Capabilities

1. **Script to HTML Production Board:** Generates a standalone, interactive HTML production board (`shotlist_{slug}.html`) with embedded Project Bible JSON, asset checklist, take logs, generation lengths, and risk ratings.
2. **Deterministic Cinematography Optics:** Locks camera behavior using field of view in degrees (e.g., `84°`, `63°`, `47°`, `29°`, `18°`, `12°`, `8°`) instead of drift-prone lens millimeters.
3. **Asset & Identity Locking:** Defines `@character`, `@location`, `@prop` element references matching Higgsfield's Elements panel to prevent identity drift across cuts.
4. **Clean Handoff Protocol:** Enforces `ENDS ON:` state definitions matching subsequent shot `CUT 1:` openings across different framing angles (preventing jump-cuts).
5. **Interactive WebGL & Real-Time Scrollytelling Integration:** Leverages code-to-video procedural pipelines inspired by `pear.no` and `a-long-expected-party` for combining Higgsfield-generated stills/video with WebGL canvas scrubbers.

---

## Directing Workflow

### Step 1: Asset Extraction & Elements Definition
Extract all characters, locations, and hero props before writing prompt blocks:
- `@character`: Facial close-up + full-body reference.
- `@location`: 3/4 angle reference with spatial depth.
- `@prop`: Multi-angle orthographic reference.

### Step 2: The Style Prefix
Each prompt prepends the CORE style contract and per-scene lighting design:
```text
Style: 8K IMAX. Photorealistic — no 3D render, no game engine.
Color: 60:30:10 — dominant / secondary / accent.
Camera: Physical cine lens. 180° shutter motion blur.
Skin: Pore-level realism — vellus hair, asymmetric moles, capillary flush.
Acting: Micro-pauses before reactions, living eyes with catch-lights.
Physics: Gravity and inertia respected — mass has real weight.
Composition: Rule of thirds + golden ratio.
Continuity: Characters, props, environment identical across every cut.
Technical: 24fps smooth motion. 8K detail. No jitter.
Audio: Diegetic dialogue and environmental SFX only.
Lighting: [Scene-specific lighting: e.g. 5600K overcast daylight, diffuse sky key]
```

### Step 3: Prompt Architecture (≤15 Seconds per Block)
```text
[STYLE CORE + LIGHTING]

Characters:
[Anchors with @references]

Scene:
[1-2 sentences spatial blocking and environment]

CUT 1 — [Shot size: e.g. MCU, FOV: e.g. 29°, Movement: slow tracking push-in]:
[Action beat, delivery, camera movement, diegetic audio]

CUT 2 — [Shot size: e.g. CU, FOV: e.g. 18°, Movement: static]:
[Reaction beat, micro-expression, eye-line shift]

ENDS ON: [Exact frozen final state of subject and frame]

SFX: [Diegetic sound arc]
```

---

## Validation

Validate any generated production board using the included script:
```bash
node scripts/validate.mjs shotlist_sample.html
```

## References & Kits
- `references/cinematography.md`: FOV optics, transitions, and first-frame image locking (i2v).
- `references/asset-prompts.md`: Image generation recipes to build Higgsfield reference assets.
- `references/board-spec.md`: HTML production board DOM and localStorage architecture.
- `templates/procedural-film-party.html`: Real-time WebGL cinematic player template.
