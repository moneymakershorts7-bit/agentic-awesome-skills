# Sound Design, Foley & Audio Mastering Standards 🎧🔊

Master guide for sound design, sonic punctuation, multi-track mixing, sidechain ducking, and broadcast loudness compliance.

---

## 1. The 4-Layer Sonic Architecture

A video without professional audio feels cheap regardless of visual quality. Every high-end edit must assemble four distinct audio layers:

```
┌────────────────────────────────────────────────────────┐
│ Layer 1: Dialogue / Voiceover (Spine)                 │ Leveled to -18 dBFS, crisp EQ, de-essed
├────────────────────────────────────────────────────────┤
│ Layer 2: Sound Effects & Foley (Punctuation)           │ Whooshes, paper tears, shutter clicks, impacts
├────────────────────────────────────────────────────────┤
│ Layer 3: Environmental Ambience (Glue)                 │ Room tone, wind, city rumble, fluorescent hum
├────────────────────────────────────────────────────────┤
│ Layer 4: Musical Score (Emotional Engine)              │ Dynamic energy, ducked -15dB to -20dB during speech
└────────────────────────────────────────────────────────┘
```

---

## 2. Sound Effects (SFX) Taxonomy & Use Cases

| SFX Category | Audio Signature | Placement Trigger |
|---|---|---|
| **Low-End Sub Thump / Boom** | 35Hz – 70Hz sine drop with quick decay | Shocking revelation, major scene transition, logo reveal |
| **Air Whoosh / Swish** | White/pink noise sweep, fast transient | Camera whip-pan, graphic fly-in, rapid cut |
| **Paper Rustle / Rips** | Crisp high-frequency organic friction | Document highlight, collage poster shift, card throw |
| **Mechanical / Shutter Clicks** | 2kHz – 5kHz transient snap | Archival photo appearance, bullet point check, UI click |
| **Cinematic Riser / Tension Swell** | Rising frequency pitch sweep over 2s–4s | Approaching climax, countdown, dramatic question |
| **Glitch / Distortion Hit** | Digital bitcrush + metallic scrape | Error state, conspiracy theory, sudden interruption |

---

## 3. Audio Ducking Math & Dynamics

When speech begins, the musical score must yield automatically:
- **Ducking Depth:** -14 dB to -18 dB relative to music peak.
- **Attack Time:** 80ms – 150ms (smooth descent without abrupt clipping).
- **Release / Recovery Time:** 600ms – 900ms (gradual swell back after last word).
- **Sidechain Setup (FFmpeg):**
  ```bash
  # Automatic sidechain compression ducking music (input 1) with speech (input 0)
  ffmpeg -i dialogue.wav -i music.wav -filter_complex \
  "[1:a][0:a]sidechaincompress=threshold=0.08:ratio=6:attack=100:release=700[ducked_music]; \
   [0:a][ducked_music]amix=inputs=2:duration=first[aout]" \
  -map 0:v -map "[aout]" output.mp4
  ```

---

## 4. Loudness & Broadcast Mastering Standards

| Target Platform | Target Integrated Loudness | Max True Peak | Dynamic Range (LRA) |
|---|---|---|---|
| **YouTube / Vimeo** | **-14 LUFS** (±1.0 LUFS) | -1.0 dBTP | 6 – 10 LU |
| **Apple Podcasts / Spotify** | **-16 LUFS** | -1.0 dBTP | 5 – 8 LU |
| **Broadcast Television (EBU R128)** | **-23 LUFS** (±0.5 LUFS) | -1.0 dBTP | 12 – 18 LU |
| **Cinema / Theatrical** | **-27 LUFS** | -0.1 dBTP | 20+ LU |

### Mastering Chain Order
1. **High-Pass Filter (HPF):** Cut everything below 75Hz on human voice to remove plosives and HVAC rumble.
2. **Parametric EQ:** +2dB boost at 3.5kHz–5kHz for vocal clarity, gentle notch at 500Hz for boxiness.
3. **De-Esser:** Tame harsh sibilance at 6kHz–8kHz.
4. **Compressor:** 3:1 ratio, 20ms attack, 100ms release, 3dB–5dB gain reduction for even vocal dynamics.
5. **Limiter:** Ceiling at -1.0 dBTP to prevent inter-sample clipping.
