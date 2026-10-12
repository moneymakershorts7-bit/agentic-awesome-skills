---
name: edge-tts-narrator
description: Transform raw video scripts into emotionally charged, broadcast-grade neural voiceovers using Edge-TTS with phonetic punctuation modeling, dynamic prosody curves (rate/pitch/volume), and multi-beat scene audio mastering.
allowed-tools:
  - bash
  - read
  - edit
  - write
  - file_read
  - file_write
  - shell
---

# Edge-TTS Expressive Narrator 🎙️🔥

A high-performance neural voiceover synthesis and audio engineering skill. It converts plain video scripts into gripping, emotionally nuanced narration by combining **acoustic punctuation heuristics**, **dynamic scene-by-scene prosody mapping** (`rate`, `pitch`, `volume`), and **EBU R128 loudness mastering (-14.0 LUFS)**.

---

## 🧠 Core Architecture & How Edge-TTS Expresses Emotion

Microsoft Edge's Neural Text-to-Speech models (`*Neural`) are deep generative transformer architectures trained on vast spoken datasets. While raw inline XML/SSML tags are escaped by `edge-tts`, emotional expression is unlocked through two powerful layers:

```
┌────────────────────────────────────────────────────────┐
│ 1. Acoustic Punctuation & Lexical Cadence              │
│    (Rising intonations, micro-pauses, punchy phrasing) │
└─────────────────────────┬──────────────────────────────┘
                          ▼
┌────────────────────────────────────────────────────────┐
│ 2. Segment-Level Dynamic Prosody Modulation            │
│    (Rate: -15% to +18%, Pitch: -4Hz to +8Hz)           │
└─────────────────────────┬──────────────────────────────┘
                          ▼
┌────────────────────────────────────────────────────────┐
│ 3. Multi-Beat Audio Concat & EBU R128 Mastering        │
│    (Seamless concatenation + -14.0 LUFS normalization)  │
└────────────────────────────────────────────────────────┘
```

---

## 🎭 The 6 Canonical Emotion Prosody Presets

| Emotion Preset | Rate | Pitch | Volume | Best For | Spanish Voice Recommendations |
|---|---|---|---|---|---|
| `HYPE` / `CLIMAX` | `+14%` | `+5Hz` | `+5%` | Major reveals, goal celebrations, viral hooks | `es-MX-JorgeNeural`, `es-AR-TomasNeural` |
| `SHOCK` / `COLD_PLUNGE` | `+10%` | `+6Hz` | `+6%` | Opening 3s hooks, breaking news, disbelief | `es-MX-JorgeNeural`, `es-ES-AlvaroNeural` |
| `SUSPENSE` / `MYSTERY` | `-10%` | `-3Hz` | `-2%` | Behind-the-scenes secrets, rumors, conspiracies | `es-ES-AlvaroNeural`, `es-MX-DaliaNeural` |
| `STORYTELLING` | `+2%` | `+0Hz` | `+0%` | Context delivery, background exposition | `es-CO-GonzaloNeural`, `es-MX-JorgeNeural` |
| `EMPATHY` / `SERIOUS` | `-6%` | `-2Hz` | `-3%` | Personal struggles, humble origins, drama | `es-ES-AlvaroNeural`, `es-MX-DaliaNeural` |
| `CTA` / `OUTRO` | `+6%` | `+2Hz` | `+4%` | Call-to-actions, community questions, loops | `es-MX-JorgeNeural`, `es-AR-TomasNeural` |

---

## ✍️ Acoustic Punctuation Rules (Neural Cadence Triggers)

Before synthesizing audio, scripts must be formatted using the following acoustic formatting rules:

1. **Inverted Exclamations & Questions (`¡!`, `¿?`):**
   - Mandatory in Spanish. Triggers the acoustic model's rising pitch contours and energetic attack.
   - *Example:* `¡Increíble pero cierto!` vs `Increíble pero cierto.`
2. **Dramatic Suspense Ellipses (`...`):**
   - Generates a natural 350–500ms suspense pause with a subtle downward vocal glide.
   - *Example:* `Nadie... absolutamente nadie... sabía lo que estaba por ocurrir.`
3. **Parenthetical Em-Dashes (`—`):**
   - Introduces a momentary 200–300ms shift in vocal timbre and cadence.
   - *Example:* `El contrato —con cifras nunca antes vistas— ya estaba sobre la mesa.`
4. **Stressed All-Caps Keywords:**
   - Words like `¡NO!`, `¡BRUTAL!`, `¡HISTÓRICO!`, `¡MILLONES!` produce acoustic stress peaks.
5. **Short Rhythmic Sentences (5–8 Words):**
   - Break long run-on sentences into rapid breath units to build viral tension.

---

## 🚀 Execution & Tooling

### Using the Python CLI Engine (`scripts/narrate.py`)

The skill includes a production-ready script to synthesize single-beat or multi-beat emotional audio:

```bash
/home/npirela/.agents/tools/youtube-venv/bin/python ~/.agents/skills/edge-tts-narrator/scripts/narrate.py \
  --input-script "my_script.txt" \
  --output-audio "voiceover.aac" \
  --voice "es-MX-JorgeNeural" \
  --lufs -14.0
```

### Script Tagging Format:
```text
[EMOTION: SHOCK]
¡TERREMOTO en el Real Madrid! ¿Mbappé y Vinícius no se soportan en el vestuario?

[EMOTION: SUSPENSE]
Detrás de cámaras... los gestos en los entrenamientos dicen otra cosa.

[EMOTION: HYPE]
¡Pero Florentino Pérez acaba de soltar una bomba que lo cambia TODO!

[EMOTION: CTA]
¿Tú qué opinas? ¡Déjalo en los comentarios y suscríbete!
```

### Automated Locution & Diction Compiler (`scripts/locution_processor.py`)
Converts raw, dry prose into spoken phonic breath groups with number expansion, acronym phonetization, and multi-engine export:

```bash
python3 ~/.agents/skills/edge-tts-narrator/scripts/locution_processor.py \
  --text "En 2026, el Dr. García reveló que el 45% de los fondos fueron transferidos al FBI." \
  --engine edge_tts \
  --emotion HYPE \
  --voice es-MX-JorgeNeural
```

---

## 📚 References & Deep Dives

- **Master Locution & Diction Handbook:** [locucion_diccion_master_guide.md](references/locucion_diccion_master_guide.md) — The vocal coach blueprint: breath phrasing (5–8 words), intonation arches (anticadence/suspension/cadence), and phonetic normalization.
- **Edge-TTS Deep Engine Spec:** [edge_tts_deep_engine_guide.md](references/edge_tts_deep_engine_guide.md) — Protocol internals, safe rate/pitch boundaries, curated elite voices, silence padding, and EBU R128 (-14.0 LUFS) mastering.
- **Kokoro-82M Local Neural Guide:** [model_guides/kokoro_tts_guide.md](references/model_guides/kokoro_tts_guide.md) — Real-time CPU inference, StyleTTS 2 architecture, IPA phonemes, and voice tensor blending.
- **ElevenLabs v2 & v3 Production Guide:** [model_guides/elevenlabs_v2_v3_guide.md](references/model_guides/elevenlabs_v2_v3_guide.md) — Stability vs. emotion trade-offs, similarity sliders, style exaggeration, and audio prompt tags.
- **Google Gemini 3.8 Flash TTS Guide:** [model_guides/gemini_3_8_tts_guide.md](references/model_guides/gemini_3_8_tts_guide.md) — Strict scope partitioning, `speech_metadata.style`, inline non-speech tags (`<gasp>`, `<sigh>`), and multi-speaker overlapping backchannels.
- **ChatTTS Conversational Disfluency Guide:** [model_guides/chattts_conversational_guide.md](references/model_guides/chattts_conversational_guide.md) — Conversational laughter tokens (`[laugh]`), micro-breaks (`[break]`), oral fillers, and seed stability.
- **Acoustic Cadence & Punctuation Rules:** [cadence_formatting_rules.md](references/cadence_formatting_rules.md) — Punctuation-as-acoustic-code triggers.
- **Prosody Modulation Matrix:** [prosody_matrix.md](references/prosody_matrix.md) — Exact numerical rate/pitch/volume presets.
