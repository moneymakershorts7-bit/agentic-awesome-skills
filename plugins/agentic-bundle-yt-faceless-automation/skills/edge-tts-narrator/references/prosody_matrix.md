# Edge-TTS Prosody & Emotion Parameter Matrix 🎚️

This reference provides exact prosody coordinate settings (`rate`, `pitch`, `volume`) and recommended neural voices across Spanish and English for various emotional storytelling modes.

---

## 1. Emotion Prosody Presets Matrix

| Preset ID | Rate Parameter | Pitch Parameter | Volume Parameter | Acoustic Profile & Tone | Primary Use Cases |
|---|---|---|---|---|---|
| `HYPE` | `+14%` | `+5Hz` | `+5%` | Explosive energy, high tempo, peak excitement | Climax scenes, goals, game changers, breaking victories |
| `SHOCK` | `+10%` | `+6Hz` | `+6%` | Sharp attack, elevated pitch, incredulity | Cold plunge opening hooks, shocking stats, unexpected twists |
| `SUSPENSE` | `-10%` | `-3Hz` | `-2%` | Slowed cadence, lower register, conspiratorial | Rumors, locker room leaks, hidden clauses, conspiracy |
| `STORYTELLING` | `+2%` | `+0Hz` | `+0%` | Balanced, articulate, engaging journalism | Context setting, chronological transitions, career background |
| `EMPATHY` | `-6%` | `-2Hz` | `-3%` | Warm, solemn, grounded, introspective | Early childhood struggles, humble beginnings, emotional tributes |
| `CONTEMPLATIVE` | `-8%` | `-4Hz` | `-4%` | Deliberate, thought-provoking, measured | Moral dilemmas, philosophical reflections, strategic choices |
| `AGGRESSIVE_FAST` | `+18%` | `+4Hz` | `+6%` | Rapid-fire, breathless urgency | Rapid countdowns, rapid stats recap, tense deadlines |
| `CTA` | `+6%` | `+2Hz` | `+4%` | Upbeat, inviting, direct conversational call | Like/Subscribe prompts, comment questions, seamless loops |

---

## 2. Voice Tier & Persona Catalog

### 🇪🇸 Spanish (Latin American & European)

| Voice Identifier | Gender | Region | Persona & Best Genre |
|---|---|---|---|
| `es-MX-JorgeNeural` | Male | Mexico | **Tier 1:** High-energy sports commentator, tabloid gossip, viral shorts |
| `es-AR-TomasNeural` | Male | Argentina | **Tier 1:** Passionate South American football commentator, emotional storytelling |
| `es-ES-AlvaroNeural` | Male | Spain | **Tier 1:** Authoritative investigative journalist, serious documentary narrator |
| `es-MX-DaliaNeural` | Female | Mexico | **Tier 1:** Expressive drama narrator, tabloid gossip, storytelling |
| `es-ES-ElviraNeural` | Female | Spain | **Tier 2:** Professional news anchor, analytical documentaries |
| `es-CO-GonzaloNeural` | Male | Colombia | **Tier 2:** Smooth, warm, approachable long-form narrator |

### 🇺🇸 English

| Voice Identifier | Gender | Region | Persona & Best Genre |
|---|---|---|---|
| `en-US-ChristopherNeural` | Male | US | Authoritative, dynamic storytelling, tech and sports news |
| `en-US-GuyNeural` | Male | US | Casual, energetic, conversational YouTube creator |
| `en-US-JennyNeural` | Female | US | Engaging, crisp, modern digital video host |
| `en-GB-RyanNeural` | Male | UK | Sophisticated, documentary, dramatic sports analysis |

---

## 3. Mathematical Prosody Boundaries

To avoid unnatural robotic artifacts or frequency clipping, keep prosody within these empirical safety boundaries:

- **Rate Limits:** Minimum `-25%` (below this sounds slurred) to Maximum `+30%` (above this causes syllable skipping).
- **Pitch Limits:** Minimum `-10Hz` (excessive vocal fry) to Maximum `+15Hz` (excessive chipmunk distortion).
- **Volume Limits:** Minimum `-20%` to Maximum `+15%` (mastering should be handled via FFmpeg `loudnorm` rather than extreme TTS volume boosts).
