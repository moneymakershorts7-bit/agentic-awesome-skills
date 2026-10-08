---
name: ai-animation-workflow
description: Production-grade 5-stage AI Explainer Animation & Video-As-Code pipeline. Orchestrates script-to-voice narration, word-timed transcript alignment, visual cue storyboard, Remotion/Web scene composition, and verified multi-format MP4 export.
category: multimedia
risk: safe
source: cliefnotes
source_type: community
date_added: "2026-10-06"
author: Clief Notes
tags: [video-as-code, remotion, explainer-videos, animation-pipeline, tts, transcript-sync, motion-design, storytelling]
allowed-tools: [Bash, Read, Write]
---

# AI Explainer Animation & Video-as-Code Workflow

A deterministic, 5-stage pipeline for producing high-craft animated explainer videos from a single source idea using AI assistants, structured folders, and code-based rendering (Remotion / HTML Canvas / WebGL).

Based on the **Clief Notes Video-as-Code Architecture**, this workflow enforces strict stage boundaries, human review gates, and the rule: **"Change the stage that owns the problem."**

---

## When to Use

- Creating code-driven animated explainer videos (Remotion, HTML/CSS Canvas, WebGL).
- Turning raw text, meeting notes, customer FAQs, or documentation into punchy, narrated visual explainers.
- Synchronizing word-level spoken timestamps with kinetic typography and paired diagram highlights.
- Managing multi-stage video production where script, audio, transcript, storyboard, scene layout, and render stages must be decoupled and independently verified.

---

## The 5-Stage Controlled Pipeline

```
[01_voice] Script & Narration  ──(Approved Audio)──>  [02_transcript] Word Timings
                                                             │
                                                      (Timestamped JSON)
                                                             │
                                                             ▼
[05_render] Verified MP4 Export <──(Checked Scene)── [04_scene] ◄── [03_cues] Visual Storyboard
```

### Stage 1: Voice & Script (`01_voice/`)
- **Input:** Project brief + raw source material (e.g. note, concept, snippet).
- **Process:** Write a spoken explanation with natural cadence, conversational pauses, and concise sentence structures. Record or generate voice take (Edge-TTS / ElevenLabs / local TTS).
- **Review Gate:** Listen to the audio with the script in front of you. Check wording, pronunciation, pacing, and missing speech. **Freeze audio before moving forward.**

### Stage 2: Words & Timed Transcript (`02_transcript/`)
- **Input:** Approved audio file in `01_voice/`.
- **Process:** Generate word-level and phrase-level timestamps via Whisper (`faster-whisper` / OpenAI Whisper / timestamped TTS metadata).
- **Review Gate:** Check word accuracy and timestamp alignment against playback. Ensure cue boundaries match spoken inflection points.

### Stage 3: Cues & Visual Storyboard (`03_cues/`)
- **Input:** Timed transcript + project brief.
- **Process:** Build visual storyboard mapping each timestamped phrase to visual states:
  - **What appears:** Cards, text labels, UI captures, characters, callout shapes.
  - **Focus & Emphasis:** Paired highlights (source phrase to target card field).
  - **Safe Zones:** Dedicated areas reserved for subtitles and avatar/character elements.
- **Review Gate:** Review storyboard before writing any animation code. Verify logical progression and visual hierarchy.

### Stage 4: Scene & Composition (`04_scene/`)
- **Input:** Storyboard cues + compiled timeline + prepared SVG / design assets.
- **Process:** Write Remotion TSX components or Web Canvas/CSS animation code:
  - Separate layout geometry from timing logic.
  - Use Emil Kowalski motion curves (sub-300ms UI micro-transitions, `ease-out`, asymmetric press/release).
- **Review Gate:**
  1. **Still Frame Audit:** Pause on the busiest beat. Check legibility, text overlap, and safe zones.
  2. **Playback Audit:** Confirm that visual highlights and card reveals land in exact sync with spoken phrases.

### Stage 5: Render & Export Verification (`05_render/`)
- **Input:** Reviewed scene + approved audio.
- **Process:** Run headless render (e.g. `npx @remotion/cli@4.0.0 render` or Python pipeline):
  - 16:9 Landscape master ($1920 \times 1080$ @ 30/60 fps).
  - 9:16 Vertical / Mobile cut ($1080 \times 1920$).
- **Review Gate:** Open and watch the exported MP4 outside the browser/player. Check full audio muxing, zero frame drops, crisp vector scaling, and clean outro hold.

---

## Root-Cause Remediation Rule

> **"Change the stage that owns the problem."**

| Issue Observed | Wrong Reaction | Correct Remediation Stage |
| :--- | :--- | :--- |
| Wording is clumsy or speech is too fast | Speed up animation code in scene | **Stage 1 (`01_voice`)**: Rewrite script line and re-record take |
| Visual appears 500ms after the spoken word | Hardcode CSS delay offsets in scene | **Stage 2 (`02_transcript`) / Stage 3 (`03_cues`)**: Fix cue start timestamp |
| Text covers character or overflows card | Tweak timing keyframes | **Stage 4 (`04_scene`)**: Adjust layout, padding, font scale, or grid |
| MP4 color differs or audio crackles | Re-animate scene components | **Stage 5 (`05_render`)**: Check color space flags, bitrates, and FFmpeg muxing |

---

## Quickstart Commands

### 1. Initialize a New Animation Project
```bash
python3 scripts/init_project.py --name my-explainer --topic "Explain Git rebase vs merge"
```

### 2. Compile Cues into Remotion Timeline
```bash
python3 scripts/compile_cues.py --project my-explainer --fps 30
```

### 3. Audit Scene Frame Boundaries & Safe Zones
```bash
python3 scripts/audit_scene.py --project my-explainer
```

---

## Reference Guides

- [Five-Stage Pipeline In-Depth](references/five-stage-pipeline.md) - Deep architectural rules and stage handoffs.
- [Prompt Playbook](references/prompt-playbook.md) - Exact prompts for each stage to instruct AI assistants.
- [Remotion Video Patterns](references/remotion-patterns.md) - Production-ready React/TypeScript explainer templates.
- [SVG Asset & Motion Pipeline](references/svg-asset-pipeline.md) - Preparing Illustrator/Figma SVGs, layer naming, and path animation.
