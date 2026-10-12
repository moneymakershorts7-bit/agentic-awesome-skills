---
name: code-to-video
description: Deterministic code-to-video rendering master skill. Converts HTML, CSS, SVG, Canvas, and WebGL code into pristine 60fps MP4/WebM videos with sample-accurate virtual clock, zero dropped frames, neural TTS narration, and audio sidechain ducking.
license: Apache-2.0
allowed-tools:
  - run_command
  - view_file
  - write_to_file
  - replace_file_content
  - write
  - bash
  - env
author: "Antigravity Multi-Agent Research & Engineering"
version: "1.0.0"
date_added: "2026-10-12"
---

# 🎬 Code-to-Video Master Skill

A deterministic, production-grade engine and workflow to transform code (HTML5, CSS3, GSAP, Canvas, WebGL, SVG) into high-fidelity 60fps MP4 and WebM videos.

Formulated with adversarial stress-testing from **El Décimo Hombre**, this skill eliminates the flaws of naive screen-recording:
- **No Dropped Frames:** Uses a deterministic virtualized clock stepping mechanism (`__seekToFrame(frameIndex, fps)`) via Chrome DevTools Protocol (CDP) and Puppeteer, completely freezing wall-clock time until the frame is fully painted.
- **Sample-Accurate Audio-Visual Sync:** Synchronizes video frames to audio durations down to discrete frame bounds ($N = \text{round}(T \times \text{fps})$), avoiding PTS drift.
- **Headless GPU / Font Isolation:** Bypasses software rasterizer stutter and isolates typography to prevent missing glyphs or layout wrapping.

---

## 🚀 Quick Start & CLI Usage

The executable CLI `code-to-video` is installed in `~/.local/bin/code-to-video` and available in `PATH`.

### 1. Render an HTML file into MP4
```bash
code-to-video render \
  --input /path/to/animation.html \
  --output /path/to/output.mp4 \
  --duration 5 \
  --fps 60 \
  --width 1920 \
  --height 1080
```

### 2. Render with Voice Narration & BGM Ducking
```bash
code-to-video render \
  --input /path/to/animation.html \
  --output /path/to/output.mp4 \
  --duration 6.5 \
  --fps 60 \
  --audio /path/to/voiceover.m4a \
  --bgm /path/to/background.mp3
```

### 3. Generate Neural Narration (edge-tts)
```bash
code-to-video narrate \
  --text "This is a deterministic code-to-video presentation." \
  --voice "en-US-ChristopherNeural" \
  --output voiceover.mp3
```

---

## 🛠️ The Architecture

```
┌────────────────────────────────────────────────────────┐
│             User Input / Agent Storyboard              │
│    (Prompt, Article, Repo → Structured Content)        │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│          Hermetic HTML / CSS / Canvas Template         │
│  - Inlines layout, SVG assets, and typography          │
│  - Implements window.__seekToFrame(index, fps) hook    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│      Headless Chromium Frame-by-Frame Rasterizer       │
│  - CDP Virtual Time Progression                        │
│  - Pauses all CSS Animations & Web Animations API      │
│  - Steps GSAP timeline & RAF callbacks deterministically│
│  - Emits raw PNG/RGBA buffers to FFmpeg stdin pipe     │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│              FFmpeg Video & Audio Muxer                │
│  - libx264 CRF 18 YUV420P encoding                     │
│  - Audio PTS alignment & sidechain ducking             │
│  - Exports finalized 60fps MP4 container               │
└────────────────────────────────────────────────────────┘
```

---

## 📋 Best Practices for Code-to-Video Templates

1. **Fixed Dimensions:** Always specify explicit pixel dimensions on `body` (e.g., `width: 1920px; height: 1080px; overflow: hidden;`).
2. **Animation Clock Binding:**
   - For pure CSS animations: Rely on the built-in Web Animations API hook which pauses and scrubs `animation.currentTime`.
   - For custom `<canvas>` / WebGL: Define `window.__onFrameUpdate = (frameIndex, timeMs) => { ... }` to draw your scene directly as a pure mathematical function of time.
3. **Typography Hygiene:** Use bundled web fonts or system font stacks (`-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`) with explicit fallbacks to prevent font-metric reflow in headless containers.

---

## 🛡️ Kill Criteria & Hardening Directives (El Décimo Hombre)

1. **Max Frame Rasterization Ceiling:** Frame rasterization must complete within **1,200ms per frame**. If CPU limits are exceeded, switch to lower resolution (e.g., 720p) or GPU-accelerated workers.
2. **Hermetic Network Isolation:** Do not fetch external scripts or assets over CDN during rendering. All dependencies must be inlined or resolved locally via `file://`.
3. **Sample-Accurate PTS Alignment:** Always calculate frame count as $N = \text{Math.round}(\text{audioDuration} \times \text{fps})$ to prevent AV desynchronization.
