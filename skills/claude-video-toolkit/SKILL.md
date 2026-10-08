---
name: claude-video-toolkit
description: Architecture catalog and router for agentic video generation, Remotion composition, programmatic motion graphics, B-roll assembly, and automated subtitle sync.
category: multimedia
risk: safe
source: community
source_repo: zhuyansen/awesome-claude-video-skills
source_type: community
date_added: "2026-10-06"
author: zhuyansen
tags: [video-production, remotion, motion-design, video-skills, explainers, shorts, b-roll, subtitles]
tools: [Bash, Read, Write]
---

# Claude Video Toolkit: Agentic Video Production & Motion Architecture

## Overview

A structured knowledge base and architectural toolkit for programmatic video generation, Remotion animation, motion graphics design, and AI-driven automated video editing. It routes tasks to optimal rendering frameworks (Remotion, FFmpeg, HyperFrames, Canvas video capture) based on format and delivery requirements.

## When to Use
- Deciding architecture and rendering pipeline for automated video generation (Remotion vs FFmpeg vs Canvas vs WebGL).
- Creating code-based product launch films, SaaS feature demos, animated explainers, or viral shorts/reels.
- Designing motion design templates, kinetic typography, automated captions, and B-roll collage loops.
- Programmatic rendering of dynamic video variations from structured JSON datasets.

---

## Video Generation Framework Matrix

| Framework | Best For | Runtime / Stack | Performance |
| :--- | :--- | :--- | :--- |
| **Remotion** | React-based animations, typography, SaaS demos, complex UI timelines | Node.js + React + Chromium | High precision, frame-perfect SSR |
| **FFmpeg Filtergraph** | Fast concatenation, audio mixing, transcoding, LUT color grading | Native C / CLI | Ultra-fast, zero-overhead |
| **HyperFrames / HTML5 Canvas** | High-density WebGL procedural animations, particle effects | Headless Chrome / Puppeteer | Real-time WebGL rendering |
| **Whisper + ASS Subtitles** | Kinetic typography captions, word-level highlight animations | Python / libass | Native hardware text rendering |

---

## Recommended Pipelines

### 1. Programmatic React Explainer (5-Stage Video-as-Code Pipeline)

For structured explainer animations, use the dedicated **[`ai-animation-workflow`](../ai-animation-workflow/SKILL.md)** skill, which enforces a 5-stage decoupled pipeline (`01_voice` $\to$ `02_transcript` $\to$ `03_cues` $\to$ `04_scene` $\to$ `05_render`).

```tsx
import { Composition } from 'remotion'
import { ExplainerScene } from './ExplainerScene'

export const RemotionVideo = () => {
  return (
    <Composition
      id="Explainer"
      component={ExplainerScene}
      durationInFrames={30 * 15} // 15s at 30fps
      fps={30}
      width={1920}
      height={1080}
      defaultProps={{
        title: "Agentic AI Architecture",
        accentColor: "#6366f1"
      }}
    />
  )
}
```

### 2. Fast B-Roll Stitching & Audio Ducking (FFmpeg)

```bash
# Combine b-roll clips, overlay voiceover, and duck background music by -14dB
ffmpeg -i voiceover.wav -i bgm.mp3 -filter_complex \
  "[1:a]volume=0.15[bgm_ducked];[0:a][bgm_ducked]amix=inputs=2:duration=first[aout]" \
  -map 0:v -map "[aout]" output_mix.mp4
```

---

For complete framework catalogs, animation patterns, and asset specifications, see [video-frameworks.md](references/video-frameworks.md). For step-by-step explainer builds, load [`ai-animation-workflow`](../ai-animation-workflow/SKILL.md).

## Limitations
- Use this skill only when the task clearly matches the scope described above.
- Do not treat the output as a substitute for environment-specific validation, testing, or expert review.
- Stop and ask for clarification if required inputs, permissions, safety boundaries, or success criteria are missing.
