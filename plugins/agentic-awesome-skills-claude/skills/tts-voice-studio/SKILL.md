---
name: tts-voice-studio
description: "Transform raw text into emotion-infused spoken scripts and synthesize lifelike audio with human cadence. Supports SSML, ChatTTS, Bark, Kokoro, and ElevenLabs markup using free/open-source tools (Edge-TTS, Kokoro-82M, ChatTTS, Piper) and paid engines (ElevenLabs, Cartesia, OpenAI)."
category: media
risk: safe
source: community
date_added: "2026-10-04"
tags: [tts, voice, speech-synthesis, audio, ssml, emotion, edge-tts, elevenlabs, kokoro]
allowed-tools: [Read, Grep, Glob, Bash]
allowed-domains: []
---

# TTS Voice Studio (Script Crafting & Multi-Engine Synthesis)

## Overview

**TTS Voice Studio** bridges the gap between lifeless, robotic text and natural, emotionally nuanced human speech. It provides both:
1. **Script Crafting & Orality Direction:** Automatically converts dry written copy into performative speech scripts with realistic breath pauses, prosody inflections, emotional styles, and engine-specific markup (SSML, ChatTTS brackets, Bark audio prompts, ElevenLabs punctuation pacing).
2. **Speech Synthesis Engine:** Bundles direct synthesis via **Edge-TTS** (100% free, zero-config, 400+ Microsoft neural voices in 100+ languages) and provides architectural integration blueprints for local open-source models (**Kokoro-82M**, **ChatTTS**, **Piper**) and premium commercial APIs (**ElevenLabs**, **Cartesia**, **OpenAI TTS**).

---

## When to Use This Skill

- When you need to turn raw text, articles, or notes into a script optimized for text-to-speech.
- When voices sound robotic, monotonic, or rushed, and need human cadence, emotional inflections, and natural breathing pauses.
- When generating voiceovers for videos, podcasts, YouTube narration, audiobooks, or AI avatars.
- When looking for **free, high-quality neural voice synthesis** without paying for subscriptions or configuring API keys.
- When comparing or migrating between free/open-source engines (Edge-TTS, Kokoro-82M, ChatTTS) and paid engines (ElevenLabs, Cartesia, OpenAI Audio).

---

## Quick Reference Index

Detailed deep dives live in `references/`:

| Topic | File | Key Contents |
|---|---|---|
| **Script Humanization** | [script_crafting_guide.md](references/script_crafting_guide.md) | Orality vs writing, breath points, emotional arquetypes, pacing transforms |
| **Free & Open-Source Tools** | [free_models_and_tools.md](references/free_models_and_tools.md) | Edge-TTS setup, Kokoro-82M on CPU, ChatTTS laughter tokens, Piper for IoT |
| **Paid & Hosted APIs** | [paid_tools_guide.md](references/paid_tools_guide.md) | ElevenLabs parameter tuning, Cartesia 90ms latency, OpenAI Audio tips |
| **Markup & Tags Cheatsheet** | [ssml_and_cues_cheatsheet.md](references/ssml_and_cues_cheatsheet.md) | W3C SSML syntax, `<express-as>`, `[laugh]`, `[sighs]`, break duration |

---

## CLI Tool Usage (`scripts/tts_studio.py`)

The skill bundles an executable CLI utility:

### 1. Format and Humanize a Script with Emotion
Transform plain text into an emotion-infused script ready for your target voice generator:

```bash
# Generate script for ElevenLabs with dramatic pauses:
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py format-script \
  --text "El avance de la tecnología no se detiene. Hoy cambiamos el rumbo de la historia." \
  --emotion dramatic \
  --target elevenlabs

# Generate SSML markup for Edge-TTS or Azure Speech:
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py format-script \
  --text "¡Bienvenidos al episodio de hoy! Tenemos noticias increíbles para compartir." \
  --emotion cheerful \
  --target ssml

# Generate ChatTTS conversational script with laughter and pause tokens:
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py format-script \
  --text "No me lo vas a creer. Resulta que el servidor se apagó solo." \
  --emotion conversational \
  --target chattts
```

Supported emotions: `cheerful`, `empathetic`, `dramatic`, `suspenseful`, `authoritative`, `whisper`, `excited`, `conversational`, `neutral`.

### 2. Synthesize Audio for Free (Edge-TTS)
Generate high-fidelity MP3 audio locally at zero cost:

```bash
# Spanish narration (es-ES-AlvaroNeural):
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py synthesize \
  --text "Hola a todos. Esta es una demostración de voz neuronal completamente humana y gratuita." \
  --voice es-ES-AlvaroNeural \
  --output voiceover_es.mp3

# English upbeat narration with speed adjustment:
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py synthesize \
  --text "Welcome to the future of AI speech. Clear, natural, and expressive." \
  --voice en-US-JennyNeural \
  --rate "+8%" \
  --output voiceover_en.mp3
```

### 3. List and Discover Curated Voices

```bash
# List curated high-quality voices in Spanish or English:
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py list-voices --lang es
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py list-voices --lang en

# Query all 400+ available neural voices:
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py list-voices --all --lang es
```

### 4. Compare Free vs Paid TTS Engines

```bash
python3 ~/.agents/skills/tts-voice-studio/scripts/tts_studio.py compare-engines
```

---

## Best Practices

- ✅ **Break compound sentences:** Never feed 40-word unbroken sentences. Humans take breath every 12-18 words.
- ✅ **Embrace micro-pauses:** Use ellipses (`...`) for thought pauses and em-dashes (`—`) for dramatic pivot points.
- ✅ **Start Free:** Use Edge-TTS or Kokoro-82M for testing, prototypes, and initial drafts before spending credits on paid platforms.
- ✅ **Match Voice Persona to Content:** Use baritone authoritative voices (`es-ES-AlvaroNeural`, `en-US-GuyNeural`) for documentaries and bright energetic voices (`es-MX-DaliaNeural`, `en-US-JennyNeural`) for tutorials and social media.
- ❌ **Avoid raw abbreviations:** Write numbers and acronyms as spoken words (e.g., "dos mil veintiséis" instead of "2026").

---

## Limitations

- External cloud synthesis with `edge-tts` requires an active internet connection.
- Local execution of heavyweight models like Bark or Parler-TTS requires GPU hardware for acceptable generation speed, whereas Kokoro-82M and Piper run smoothly on CPU.
- Standard usage limits and external API rate boundaries apply to commercial voice providers (ElevenLabs, Cartesia, OpenAI).
