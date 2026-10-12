# 🎨 Visual Style Archetypes for Document Adaptation

Adapting a document requires selecting an artistic archetype that complements the conceptual tone of the source text.

---

## 1. Archetype Catalog

### A. European Ligne Claire (Hergé / Moebius style)
* **Best for:** Historical accounts, biographical books, philosophical treatises, travelogues.
* **Characteristics:** Strong, clear outline of equal width, flat colors, no crosshatching, realistic architectural backgrounds with clean expressive character lines.
* **Prompt Modifiers:** `ligne claire style, clean uniform ink contours, flat colors, clear architecture, vintage franco-belgian comic art, crisp details, Hergé aesthetic`.

### B. Vintage Technical Schematic / Educational Comic (1960s-1970s)
* **Best for:** Textbooks (Physics, Chemistry, Computer Science, Biology), manuals.
* **Characteristics:** Engraving textures, cross-sections, blueprint accents, muted pastel color palette, callout arrows, isometric cutaway perspectives.
* **Prompt Modifiers:** `vintage scientific illustration style, technical cross-section, diagrammatic comic, fine ink hatching, muted cyan and sepia palette, clean linework`.

### C. Cyberpunk / Sci-Fi Graphic Novel
* **Best for:** Modern technology, artificial intelligence, futuristic novels, cybersecurity.
* **Characteristics:** High contrast chiaroscuro, neon rim lighting, deep shadows, angular kinetic perspective, gritty screen-tones.
* **Prompt Modifiers:** `cyberpunk graphic novel style, high contrast, dramatic neon backlight, dark deep shadows, gritty mechanical textures, detailed ink art`.

### D. Classic Noir / High-Contrast Ink (Sin City / Eisner Spirit style)
* **Best for:** Crime, legal investigations, ethical dilemma essays, mystery novels.
* **Characteristics:** Stark black-and-white ink brushstrokes, dramatic venetian blind shadows, deep chiaroscuro, silhouette staging.
* **Prompt Modifiers:** `noir graphic novel, high contrast black and white ink, dramatic shadows, silhouetted characters, gritty atmospheric lighting, Will Eisner spirit style`.

### E. Seinen / Shonen Manga
* **Best for:** Action-oriented novels, epic historical narratives, high-intensity competition.
* **Characteristics:** Screen-tones, dynamic speed lines, exaggerated perspective (fish-eye, forced perspective), emotive facial closeups.
* **Prompt Modifiers:** `manga style, detailed screentone shading, dynamic perspective, fine Japanese ink lines, expressive emotional focal points`.

---

## 2. Character Anchor Protocol (Zero-Drift Invariant)

To maintain consistent character likeness across 10–100 panels without a fine-tuned LoRA:
1. **Name Anchor:** Designate a unique canonical token (e.g., `PROFESSOR_ELENA_01`).
2. **Fixed Visual Anchor String:** Define a mandatory token sequence appended to every panel prompt:
   ```
   "elderly woman in her late 60s, cropped silver hair, round silver spectacles, dark green woolen cardigan over white collared shirt, small mole beneath left eye"
   ```
3. **Negative Prompt Shield:**
   ```
   "photorealistic, 3d render, distorted anatomy, changing hairstyle, missing glasses, modern clothing, speech bubbles, text artifacts, watermark"
   ```
