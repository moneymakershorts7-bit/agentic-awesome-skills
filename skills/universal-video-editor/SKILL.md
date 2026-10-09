---
name: universal-video-editor
description: "Master multi-format film, documentary, and YouTube video editor. Directs timeline assembly, J/L cuts, rhythm pacing, sound design (-14 LUFS), and color grading."
category: media
risk: safe
author: Antigravity Editing Lab
version: "1.0.0"
source: "https://github.com/agentic-awesome-skills/universal-video-editor"
source_type: official
date_added: "2026-10-09"
license: MIT
tags: [video-editing, film-editor, documentary-editing, youtube-editor, nle, sound-design, color-grading, ffmpeg, davinci-resolve, premiere, remotion]
allowed-tools:
  - bash
  - read
  - edit
  - write
  - file_read
  - file_write
  - shell
---

# Universal Video Editor 🎬✂️🔊

The **Universal Video Editor** is an elite post-production and editing intelligence skill. It governs the rhythm, visual punctuation, emotional cadence, sonic architecture, and final mastering of motion picture content across all formats:
- **Feature Films & Narrative Shorts:** Scene continuity, montage theory, subtext pacing, dialogue rhythm.
- **Investigative & Historical Documentaries:** Archival montage, Ken Burns motion control, split-screen forensic breakdowns, A-roll/B-roll interleaving.
- **YouTube High-Retention Essays:** 3-second pattern interrupts, retention curves, visual spikes, kinetic text emphasis.
- **Vertical Short-Form (9:16 Shorts / Reels / TikTok):** Lightning-fast visual hooks, micro-pacing, dynamic word-level subtitles, looping transitions.

---

## When to Use This Skill

- Use when assembling, trimming, sequencing, or structuring multi-track video timelines.
- Use when designing soundscapes, Foley effects, sidechain audio ducking, and -14 LUFS loudness mastering.
- Use when applying film color grading, LUTs, contrast S-curves, and film grain emulation.
- Use when writing automated FFmpeg filter graphs, Remotion scripts, or NLE export configurations.

---

## 🎯 The 6 Golden Rules of Editing (Walter Murch's Hierarchy)

When executing any cut or timeline decision, prioritize criteria in this exact order:

1. **Emotion (51%):** Does the cut reflect the true emotional state of the story? (Never sacrifice emotion for mechanical continuity).
2. **Story (23%):** Does the cut advance the plot, argument, or thesis?
3. **Rhythm (10%):** Does the cut occur at a moment that feels musically and rhythmically satisfying?
4. **Eye-Trace (7%):** Does the viewer's gaze land smoothly where the next focal element appears?
5. **Two-Dimensional Plane of Screen (5%):** Does the cut respect the 180° line and vector directional flow?
6. **Three-Dimensional Space (4%):** Is physical spatial continuity preserved?

---

## 🛠️ Core Capabilities

### 1. Multi-Track Timeline Architecture
- **Track V1 (Narrative Spine / A-Roll):** Primary dialogue, anchor footage, or character action.
- **Track V2 (B-Roll & Context):** Environmental verité, macroscopic cutaways, reaction shots.
- **Track V3 (Graphics & Overlays):** Lower thirds, document callouts, spotlight masks, kinetic text.
- **Track A1 (Dialogue):** Clean voiceover, lavalier mic, leveled to -18 dBFS peak, -14 LUFS integrated.
- **Track A2 (Ambience & Room Tone):** Continuous environmental bed for seamless soundstage.
- **Track A3 (Foley & SFX):** Whooshes, paper rustles, camera shutters, mechanical clicks, sub-bass drops.
- **Track A4 (Music Score):** Dynamic background score ducked automatically (-18dB) during dialogue.

### 2. Transition & Pacing Grammar
- **J-Cut:** Audio of the upcoming scene precedes the video cut by 0.5s–1.5s. Creates anticipation and seamless scene shifts.
- **L-Cut:** Audio from the current scene carries over beneath the incoming video cut. Conveys lingering emotional resonance.
- **Match Cut:** Cutting between two visually or thematically similar objects (e.g., spinning fan to helicopter blade).
- **Jump Cut:** Deliberate forward temporal jump within the same framing to compress time and convey frantic velocity.
- **Smash Cut:** Abrupt transition from intense chaos to dead silence, or tranquil peace to explosive action.

### 3. Sound Design & Audio Engineering
- **Audio Ducking:** Smooth sidechain compression ducking music 12dB–18dB when speech is active.
- **Sub-Bass & Impact Architecture:** High-impact moments punctuated with 40Hz–60Hz sub-bass thump and atmospheric swoosh.
- **LUFS Broadcast Standards:**
  - YouTube / Streaming: **-14 LUFS** integrated, -1.0 dB true peak.
  - Broadcast TV: **-24 LUFS** (EBU R128 / ITU-R BS.1770).

### 4. Cinematic Color Grading & Looks
- **Log $\to$ Rec.709 Transformation:** Precise gamma mapping and highlight compression.
- **Look Emulation:** Kodak 2383 film print, Teal & Orange blockbuster, Bleach Bypass gritty doc, Clean Minimalist modern tech.
- **Film Grain & Halation:** 35mm organic grain overlay on midtones and highlights.

### 5. Empirical Broadcast Standards & 3D Vector Geometry (Lab-Verified)
- **Crown Color Harmonies:**
  - **Preset A (Imperial Compute):** Imperial Gold `rgb(212, 175, 55)` + Platinum White `rgb(226, 232, 240)` over dark slate `rgb(10, 10, 14)` ($\sigma = 42.9$).
  - **Preset B (Bio-Phosphor AGI):** Platinum White `rgb(226, 232, 240)` + Bio-Phosphor Teal `rgb(20, 240, 180)` over deep cyan-slate `rgb(6, 12, 14)` ($\sigma = 45.0$ all-time peak).
- **3D Wireframe Perspective Engine:** Compute rotating 3D polyhedra, cubes, and lattices in real-time with continuous rotation matrix transformations and perspective projection ($fov / (fov + z)$).
- **Zero-Clipping Dynamic Typography:** Always calculate headline and badge boundaries with `font.getbbox(text)` and apply $+40\text{px}$ dynamic horizontal padding.
- **Directorial Visual Critique:** Evaluate rendered frame contrast standard deviation ($\sigma \ge 35$ required, $\sigma \ge 40$ broadcast gold) and mean luminescence ($15 \le \mu \le 80$).
- **Audio Ducking Filtergraph:** Duck background ambient beds by $-18\text{dB}$ under voiceover with `amix` and normalize to `-14 LUFS` EBU R128 (`loudnorm=I=-14:TP=-1.0:LRA=11`).

---

## 🚀 Multi-Format Rendering & Production Pipelines

| Format | Resolution | Aspect | Frame Rate | Typical Pacing | Delivery Target |
|---|---|---|---|---|---|
| **Cinematic Widescreen** | 3840x1600 / 1920x800 | 2.39:1 | 24.0 fps | 3s–8s average shot length (ASL) | Film Festivals, Cinema, Theatrical |
| **Documentary / YouTube Long** | 3840x2160 / 1920x1080 | 16:9 | 30.0 / 24.0 fps | 2.5s–4.5s ASL + constant B-roll | YouTube, Netflix, Web Broadcast |
| **Vertical Short-Form** | 1080x1920 / 2160x3840 | 9:16 | 30.0 / 60.0 fps | 0.8s–2.0s ASL + kinetic subtitles | YouTube Shorts, TikTok, Instagram Reels |
| **Square / Social Feed** | 1080x1080 / 1440x1440 | 1:1 / 4:5 | 30.0 fps | 1.5s–3.0s ASL | LinkedIn, Facebook, X feeds |

---

## 📚 Technical References & Toolkits

- [Editing Grammar, Pacing & Montage Rules](references/editing-grammar.md)
- [Sound Design, Foley & Audio Mastering Standards](references/sound-design-audio-mastering.md)
- [Cinematic Color Grading & Film Look LUTs](references/color-grading-film-looks.md)
- [FFmpeg Master Scripting & Complex Filter Graphs](references/ffmpeg-editor-toolkit.md)
- [Documentary & YouTube Pacing Retention Science](references/documentary-and-youtube-pacing.md)
