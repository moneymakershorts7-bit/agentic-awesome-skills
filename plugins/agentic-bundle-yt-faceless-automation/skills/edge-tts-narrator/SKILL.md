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

---

## 📚 References & Deep Dives

- [prosody_matrix.md](references/prosody_matrix.md): Complete voice catalog, rate/pitch coordinates, and international voice pairings.
- [cadence_formatting_rules.md](references/cadence_formatting_rules.md): In-depth linguistic and acoustic trigger guidelines for high-retention narration.
