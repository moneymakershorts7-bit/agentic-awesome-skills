---
name: vox-director
description: "Turn ONE topic into a finished Vox-style paper-collage explainer / ad\
  \ video, end to end on the Atlas Cloud API + local ffmpeg \u2014 script, collage\
  \ keyframes, motion, voice-over, music, captions, all automated. Use this whenever\
  \ the user wants a \"Vox style\" video, a paper/torn-paper collage animation, a\
  \ \"motion collage\", a narrated explainer or short ad built from AI-generated collage\
  \ posters, a scrapbook-style tribute, or wants to turn a topic / product / person\
  \ into a punchy narrated collage video \u2014 even if they don't say the word \"\
  Vox\". Also use when reproducing Stav Zilber / rom1trs / Higgsfield-style collage\
  \ ad workflows.\n"
allowed-tools:
- bash
- read
- edit
- write
- file_read
- file_write
- shell
allowed-domains:
- api.atlascloud.ai
- cdn.atlascloud.ai
- atlascloud.ai
license: MIT
risk: safe
source: community
---
# Vox Director 🎬✂️

Turn a one-line topic into a finished **Vox-style paper-collage video**: a bold, punchy,
narrated explainer/ad where each beat is a torn-paper collage poster that comes alive, with
voice-over, music and captions. Runs on **Atlas Cloud API** / local generative engines + local **ffmpeg**.

The look is the modern editorial paper-collage popularized by Vox explainers and creators
like Stav Zilber / rom1trs: hand-cut paper cut-outs, torn edges, tape, halftone dots,
newspaper clippings, bold flat color per beat, big cut-out headlines.

---

## 🧠 The Core Idea

The Vox collage look and the collage motion are **two different steps**:

1. **The look is born in the IMAGE step:** Each beat is a finished collage *poster* made by a
   text-to-image model. All the collage DNA (torn paper, cut-outs, halftone, bold color,
   headline text) lives in that image.
2. **The motion is added after:** An AI video model or local keyframe motion engine animates the whole poster.

Everything hinges on the prompts. Before writing any image or video prompt, read
`references/prompt-guide.md` — it has the exact prompt structures that make the difference
between "a real Vox collage" and "a moving PowerPoint".

---

## 📋 Prerequisites

- `echo "${ATLASCLOUD_API_KEY:+set}"` — Atlas Cloud API key (for cloud-accelerated generation).
- `command -v ffmpeg ffprobe` — required for assembly.
- `python3 -c "import PIL"` — Pillow, for captions/watermark overlays.

---

## 🚀 Standard Workflow (Topic → Film)

1. **Topic → Beat Map:** Read `references/beat-layer.md` (the story layer) and pick a
   narrative `arc` that fits the topic (`timeline`, `how_it_works`, `man_in_hole`, etc.).
2. **Prompt Generation:** Follow `references/prompt-guide.md` for editorial paper-cutout prompts.
3. **Motion Graphics Assembly:** Run local FFmpeg / motion scripts with sound design and kinetic word-level captions.

---

## 📚 References

- `references/prompt-guide.md`: Prompt structures, vocabulary, and theme presets.
- `references/beat-layer.md`: Narrative arcs and pacing.
- `references/motion-layer.md`: Motion prompts and camera directions.
