---
name: yt-viewer-retention-dynamics
description: Audience retention engineering and video pacing skill. Synthesizes Walter
  Murch (In the Blink of an Eye), Edward Dmytryk (On Film Editing), and Richard E.
  Mayer (Cognitive Load Theory in Multimedia Learning) for maximum Average View Duration
  (AVD).
allowed-tools:
- bash
- read
- edit
- write
risk: safe
source: community
---
# YouTube Viewer Retention & Pacing Engine (`yt-viewer-retention-dynamics`)

An algorithmic attention engineering skill designed to eliminate viewer churn and maintain >70% retention at 0:30 and >50% at midpoint through cognitive load regulation and auditory-visual synchrony.

---

## 1. Core Mental Models

1. **Attentional Habituation (3-Second Decay)**: The reticular activating system habituates to static visual stimuli within 3 seconds. The editor must execute calculated resets without cognitive overwhelm.
2. **Walter Murch's Rule of Six (YouTube Mapping)**:
   - 1. Emotion (51%): Cut matches narrator's emotional stakes.
   - 2. Story Advance (23%): Zero decorative filler; every shot advances premise.
   - 3. Rhythm (10%): Cuts align with vocal cadence and speech plosives.
   - 4. Eye-Trace (7%): Primary subject in Frame $N+1$ stays within 15° cone of Frame $N$.
   - 5. 2D Plane (5%): Vector momentum preserved across cuts.
   - 6. 3D Space (4%): Consistent spatial geography in diagrams and maps.
3. **Mayer's Signaling & Temporal Contiguity**: Spoken narration and visual animations must occur *simultaneously* on the exact stressed syllable. Delete non-functional visual noise (Coherence Principle).
4. **The Overlap Invariant (Zeigarnik Open Loops)**: Never close Loop A without planting Loop B 10–15 seconds earlier. Eliminating narrative tension invites the viewer to click away.

---

## 2. The 3-to-5 Second Pattern Interrupt Schedule

* **Micro-Interrupts (Every 2.5–3.5s)**:
  * Scale punch-in (1.0x to 1.15x snap on eye-trace point).
  * Angle shift / camera drift.
  * Tactile SFX (mechanical click, subtle whoosh, paper ruffle).
  * 1–2 word kinetic text pop.
* **Macro-Interrupts (Every 15–30s)**:
  * Background aesthetic / lighting shift.
  * Music bed evolution (stem drop, key change, or track transition).
  * High-production 2D/3D custom infographic or highlighted document.
  * Subtractive pause (audio mute + freeze frame for 0.5s).

---

## 3. The 4-Layer Auditory Pyramid

* **Layer 1: Vocal Narration (-14.0 LUFS, -1.0 dBTP)**: Dynamic vocal spine; cuts land on plosives and pauses.
* **Layer 2: Punctuation SFX (-18 to -22 dBFS)**: Whooshes, sub-bass hits, clicks, and risers.
* **Layer 3: Dynamic Music Bed**: Sidechain ducked by -4 dB during narration; swells to full volume during dramatic pauses. Rotated every 45–90s.
* **Layer 4: Textural Ambience (-30 to -36 dBFS)**: Low-level room tone/drone eliminating digital silence.

---

## 4. Retention Curve Diagnostic Playbook

* **Initial Cliff (<70% at 0:30)**: Packaging disconnect or slow intro. Fix: Cut first 10s; validate thumbnail visual at 0:01.
* **Linear Decay (>1.5%/min)**: Monotonous narration rhythm or missing open loops. Fix: Rotate music stems; inject nested micro-loops every 60s.
* **Sudden Step Drop (5–15% instant cliff)**: Boring tangent or intrusive ad. Fix: Delete tangent; integrate sponsors via open-loop hostage scripting.
* **Pre-Outro Cliff**: Announcing the conclusion. Fix: Never say "In summary"; maintain 100% pacing until the final 3 seconds.
