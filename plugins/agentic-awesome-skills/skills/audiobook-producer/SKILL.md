---
name: audiobook-producer
description: "Produce engaging audiobooks from manuscripts with dynamic narrative tension, dialogue separation, and model-tailored emotional prosody across free and paid engines."
category: media
license: MIT
risk: safe
source: community
date_added: "2026-10-04"
tags: [audiobook, narration, tts, voice-acting, book-production, longform-audio, edge-tts, elevenlabs, kokoro]
allowed-tools: [Read, Write, Edit, Grep, Glob, Bash]
allowed-domains: []
---

# Audiobook Producer (Long-Form Book Direction & Voice Synthesis)

## Overview

**Audiobook Producer** transforms written manuscripts, Markdown documents, and long books into engaging, professional audiobooks. Rather than reading text in a flat, monotonic sequence, it acts as an **AI Voice Director**:
1. **Dramatic Tension & Cadence Shaping:** Analyzes each chapter's narrative arc (exposition, rising tension, dramatic climax, contemplative resolution) and modulates speaking rates, pause intervals, and emotional cues accordingly.
2. **Dialogue vs. Narration Separation:** Automatically isolates quoted dialogue from third-person narration, assigning distinct vocal styles or secondary character voices.
3. **Model-Specific Capability Tuning:** Translates the manuscript into the exact markup format and limits best suited for the target TTS engine:
   - **Microsoft Edge-TTS (Free):** Full W3C SSML with `<mstts:express-as>`, `<prosody>`, and multi-voice switching.
   - **Kokoro-82M (Open Source Local):** Spaced punctuation, normalized numerals, and vocoder breathing points.
   - **ElevenLabs (Commercial):** Per-block *Stability* guidelines, scene break tokens, and expressive formatting.
   - **ChatTTS (Conversational):** Spontaneous laughter tokens (`[laugh]`) and oral hesitation brackets (`[oral]`).
   - **OpenAI Audio (tts-1-hd):** Sentence-level flow optimization and voice persona mapping.
4. **End-to-End Chapter Audio Mastering:** Generates multi-segment chapter audio with standard ACX/Audible head (0.75s) and tail (2.5s) room tones, with zero external dependencies.

---

## When to Use This Skill

- When turning an entire book, dense document, or multi-chapter manuscript into an audiobook.
- When you want an audiobook that keeps the listener engaged across multiple hours without listening fatigue.
- When producing commercial audiobooks conforming to industry standards (ACX, Audible, Spotify).
- When producing free, zero-cost audiobooks using Edge-TTS or Kokoro-82M without paying for hosted API subscriptions.
- When generating production-ready scripts with character dialogue tags for voice actors or premium AI synthesis.

---

## Quick Reference Index

Detailed guides and specifications live in `references/`:

| Topic | File | Key Contents |
|---|---|---|
| **Audiobook Direction Guide** | [audiobook_direction_guide.md](references/audiobook_direction_guide.md) | Vocal fatigue prevention, tension curves, character contrast, ACX/Audible standards |
| **Engine Capability Matrix** | [engine_capability_matrix.md](references/engine_capability_matrix.md) | Model chunk limits, SSML support, emotion tags, cost calculations per 100k words |
| **Chunking & Dialogue Extraction** | [longform_chunking_and_dialogue.md](references/longform_chunking_and_dialogue.md) | Citation cleaning, quote detection heuristics, multi-speaker prosody tags |

---

## CLI Tool Usage (`scripts/audiobook_producer.py`)

The skill bundles an executable production CLI:

### 1. Estimate Production Runtime & Costs
Analyze a manuscript to get chapter counts, spoken duration (based on 140 WPM), and cost comparisons across all TTS engines:

```bash
python3 ~/.agents/skills/audiobook-producer/scripts/audiobook_producer.py estimate \
  --file path/to/manuscript.md
```

### 2. Direct a Book into Engine-Tailored Chapter Scripts
Processes the entire book, cleans non-verbal citations, applies emotional tension curves, and exports individual chapter production scripts alongside a `production_manifest.json`:

```bash
# Direct for 100% Free Edge-TTS (with SSML express-as and multi-voice dialogue):
python3 ~/.agents/skills/audiobook-producer/scripts/audiobook_producer.py direct \
  --file path/to/book.md \
  --engine edge-tts \
  --lang es \
  --output-dir ./audiobook_output

# Direct for ElevenLabs with dynamic stability tags and scene breaks:
python3 ~/.agents/skills/audiobook-producer/scripts/audiobook_producer.py direct \
  --file path/to/book.md \
  --engine elevenlabs \
  --lang en \
  --output-dir ./audiobook_elevenlabs
```

Supported engines: `edge-tts`, `kokoro`, `elevenlabs`, `chattts`, `openai`, `standard`.

### 3. Synthesize and Master Complete Chapter Audio
Synthesizes a full chapter script using free neural voices and seamlessly stitches segments with standard room tone:

```bash
python3 ~/.agents/skills/audiobook-producer/scripts/audiobook_producer.py synthesize-chapter \
  --script ./audiobook_output/chapter_01_introduccion.xml \
  --output ./audiobook_output/chapter_01_master.mp3 \
  --voice es-ES-AlvaroNeural
```

---

## Best Practices

- ✅ **Always sanitize citations:** Strip footnote markers (`[1]`, `[^2]`) and URLs before synthesis so they do not break vocal flow.
- ✅ **Respect chapter head & tail room:** Ensure 0.75s of silence at the start of each chapter and 2.5s at the end to provide mental breathing room.
- ✅ **Vary pace by narrative position:** Use slower, grounded pacing for expositions (-4%) and tighter, brisk pacing for action/tension (+4%).
- ✅ **Test with Edge-TTS first:** Validate chapter flow and pacing for free before submitting long manuscripts to paid APIs like ElevenLabs.
- ❌ **Avoid massive unchunked payloads:** Never send more than 2,000 characters in a single network socket request to avoid socket drops.

---

## Limitations

- Synthesis with `edge-tts` requires an active internet connection to communicate with the neural endpoint.
- Local inference for Kokoro-82M requires installing `kokoro` and `soundfile` in the Python runtime.
- For commercial distribution on Audible/ACX, audio files should be verified for loudness compliance (-19dB to -23dB RMS).
