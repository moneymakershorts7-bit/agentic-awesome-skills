# 💬 Lettering, Balloon Placement, & Occlusion Rules

Lettering in comics is a primary storytelling element. This reference establishes rules derived from Will Eisner and adversarial stress testing.

---

## 1. The Speech Balloon Hierarchy

1. **Dialogue Balloon (Spoken):** Rounded oval or smooth rectangle with a clear pointer/tail directed toward the speaker's mouth.
2. **Thought Balloon:** Scalloped, cloud-like perimeter with 2–3 diminishing circular bubbles leading toward the character's head.
3. **Whisper Balloon:** Dashed or dotted line perimeter with smaller, lighter font weight.
4. **Shout / Alarm Balloon:** Spiky, jagged starburst outline, bold uppercase font, often with larger point size.
5. **Narrative Caption Box:** Sharp-cornered rectangle placed at top-left or bottom-right of the panel. Uses neutral font, italicized or distinct background color (e.g., pale yellow/parchment) to separate authorial voice from character speech.
6. **Onomatopoeia (SFX):** Integrated directly into the panel artwork as dynamic lettering (e.g., *CRACK!*, *HUMMM*, *CLICK*).

---

## 2. Hard Anti-Pattern Constraints (El Décimo Hombre Hardening)

* **Word Budget Invariant:**
  - Standard Panel: **Maximum 20 words per balloon**.
  - Dense Discussion Panel: **Maximum 2 balloons per panel**.
  - Total Panel Text: **Never exceed 35 total words per panel**.
  - *If a technical explanation exceeds 35 words*, it MUST be divided across successive panels using McCloud's *Aspect-to-Aspect* or Cohn's *Initial $\to$ Peak $\to$ Release* sequence.

* **Occlusion & Area Rule:**
  - Total area covered by balloons + captions MUST NOT exceed **25% of the total panel pixel area**.
  - Tails and balloons MUST NOT overlap the character's face or focal eyes.
  - Balloons must be docked against panel boundaries (top, left, or right corners) to preserve negative space for the illustration.

* **Reading Sequence Direction:**
  - In Left-to-Right reading, Balloon A (first speaker) MUST have a lower $Y$-coordinate (higher on the canvas) than Balloon B (second speaker).
  - Never route a balloon tail crossing over another speaker's body or another balloon.
