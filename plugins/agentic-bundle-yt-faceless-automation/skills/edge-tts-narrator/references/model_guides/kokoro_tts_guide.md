# Kokoro-82M: Local High-Fidelity Neural Speech Guide ⚡

**Kokoro-82M** (by Hexgrad) is a state-of-the-art 82-million parameter open-weight TTS model that delivers quality rivaling commercial models while running faster than real-time entirely on CPU. It is built on StyleTTS 2 and ISTFTNet architectures, utilizing phonemic representation generated via `espeak-ng`.

---

## 1. Architectural Highlights

- **Parameter Size:** 82 Million parameters (lightweight, runs in ~300MB RAM).
- **Inference Speed:** Real-time factor (RTF) $< 0.1$ on modern CPUs (generates 10s of audio in $< 1$s).
- **Languages:** English (US, UK), Japanese, Mandarin Chinese, Spanish, French, Italian, Portuguese.
- **Audio Output:** 24 kHz mono waveform.

---

## 2. Voice Palette & Multi-Voice Blending

Kokoro introduces native **voice tensor blending**, allowing mathematical combination of speaker vectors:

```python
import torch

# Load voice style tensors
voice_a = torch.load("voices/af_bella.pt")
voice_b = torch.load("voices/af_sarah.pt")

# Create custom hybrid voice persona with 70/30 blend
custom_voice = 0.7 * voice_a + 0.3 * voice_b
```

### Curated Voice Roster:
- **`af_bella` / `af_sarah` (US Female):** Warm, crisp, broadcast narration.
- **`am_adam` / `am_michael` (US Male):** Deep, authoritative, documentary cadence.
- **`bf_emma` / `bm_george` (UK British):** Sophisticated, refined audiobooks.
- **`ef_dora` / `em_alex` (Spanish):** Clear Latin/European neutral diction.

---

## 3. Punctuation & Speed Modulation

Kokoro parses text into phonemes through `espeak-ng`. Punctuation timing directly influences the duration predictor:

- **Speed Parameter:** Default `speed=1.0`. For dramatic narration, use `speed=0.92` to allow vowels to breathe. For fast-paced tutorials, use `speed=1.08`.
- **Micro-pauses:** Use commas `,` for 180ms pauses and semicolons `;` or ellipses `...` for 400ms suspense pauses.
- **Phonemic Overrides:** Custom pronunciations can be passed via raw IPA phonemes in brackets to prevent mispronunciation of proper nouns or technical terms.

---

## 4. Production Execution Code

```python
from kokoro import KPipeline
import soundfile as sf

# Initialize pipeline for Spanish/English
pipeline = KPipeline(lang_code='a') # 'a' for American English, 'e' for Spanish

text = "Deep within orbital sector seven, the quantum consciousness began its initial boot sequence."
generator = pipeline(text, voice='am_adam', speed=0.95, split_pattern=r'\n+')

for i, (gs, ps, audio) in enumerate(generator):
    sf.write(f"kokoro_scene_{i:03d}.wav", audio, 24000)
```
