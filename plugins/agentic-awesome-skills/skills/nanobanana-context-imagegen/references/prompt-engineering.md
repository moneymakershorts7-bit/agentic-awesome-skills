# Prompt Engineering for Google Nano Banana & Imagen 3

> Professional prompt composition patterns for Google's Gemini media models and Imagen 3 to achieve museum-grade, context-grounded imagery.

---

## 1. The 7-Layer Visual Specification Formula

Google's Gemini Nano Banana Pro (`gemini-3-pro-image`) and Imagen 3 models respond best to structured, descriptive visual specifications rather than keyword spam (e.g. avoid *"trending on artstation, masterpiece, 8k"*). Use this 7-layer architecture:

```text
Layer 1: [Core Subject & Posture]
Layer 2: [Historical & Architectural Environment]
Layer 3: [Lighting Design & Atmospheric Volume]
Layer 4: [Camera, Optics & Compositional Staging]
Layer 5: [Artistic Medium & Material Textures]
Layer 6: [Color Palette & Tonal Harmony]
Layer 7: [Negative Constraints & Preservation Bounds]
```

---

## 2. Layer Deep-Dive

### Layer 1: Core Subject & Posture
- Describe subjects with tangible physical grounding: age, expression, posture, hand gestures, and authentic clothing layers.
- *Example:* *"The prophet Daniel as an elderly, dignified statesman with a silver beard and weathered brow, wearing Persian-period woven linen robes with embroidered hems, kneeling with one hand resting against the muddy riverbank."*

### Layer 2: Historical & Architectural Environment
- Establish precise spatial geometry, architectural elements, and environmental context.
- *Example:* *"The wide, sluggish waters of the ancient Tigris (Hiddekel) river at twilight. In the far background, distant mudbrick ramparts and monumental ziggurat silhouettes of Babylon rise against the horizon beneath drifting atmospheric river mist."*

### Layer 3: Lighting Design & Atmospheric Volume
- Use lighting terminology from cinematography and classical painting.
- **Volumetric God-Rays:** Divine light piercing through dense clouds or atmospheric dust.
- **Caravaggio Chiaroscuro:** Deep velvet shadows punctuated by intense directional golden sidelight.
- **Ethereal Bioluminescence:** Self-illuminating celestial radiance casting soft ambient reflections across water and faces.

### Layer 4: Camera, Optics & Compositional Staging
- **Lens & Angle:** 70mm lens, eye-level cinematic shot, subtle wide-angle establishing perspective.
- **Depth of Field:** Shallow depth of field keeping the focal subject tack-sharp while softly blurring distant river reeds.
- **Rule of Thirds:** Position key visual weight along focal intersections to leave balanced negative space.

### Layer 5: Artistic Medium & Material Textures
- **Classical Fine Art:** *"Rich oil on heavy primed linen canvas, visible expressive impasto brushwork in highlights, fine craquelure texture, glaze techniques reminiscent of Rembrandt and Caravaggio."*
- **Cinematic Photorealism:** *"35mm Eastman color film still, organic grain, natural tactile fabric weave, authentic moisture and grit on skin and wet stones."*
- **Vintage Engraving:** *"Intricate copperplate etching, disciplined cross-hatching, warm sepia ink on aged rag paper."*

### Layer 6: Color Palette & Tonal Harmony
- Limit palette to 3-4 harmonious tones.
- *Biblical/Historical:* Deep lapis lazuli blue, burnished bronze, ochre dust, warm amber, and ivory.
- *Ethereal:* Radiant white-gold, electric beryl cyan, deep twilight indigo, and twilight violet.

### Layer 7: Negative Constraints (Avoid List)
- Always include an explicit negative constraint line in prompt formatting:
  * *"Avoid: cartoonish or anime distortion, modern 21st-century garments or architecture, extra fingers or malformed anatomy, blurry faces, unprompted text or signatures, plastic skin."*

---

## 3. Complete Production Example (Daniel 10 Vision)

```text
A breathtaking classical oil painting illustrating the visionary encounter from Daniel 10 beside the great river Tigris.

In the center-right of the composition, a radiant celestial messenger appears suspended above the water, robed in luminous white linen with a belt of fine gold from Uphaz across his chest. His countenance shines like brilliant lightning, eyes like flaming torches, arms and feet gleaming like burnished bronze, with an otherworldly electric beryl luminescence illuminating the surrounding reeds and misty air.

On the left riverbank in the foreground, the elderly prophet Daniel is seen prostrated in awe and humility, draped in layered dark ochre and slate garments, his face turned towards the earth with hands trembling upon the pebble-strewn bank.

The background reveals the vast, tranquil expanse of the ancient Tigris river at dusk, with soft twilight haze and the distant low silhouette of ancient Mesopotamian river bluffs.

Lighting: Dramatic chiaroscuro with intense divine luminescence from the celestial figure casting warm golden and cyan specular highlights across the dark reflective river water and Daniel's robes.
Medium: Masterpiece oil painting on canvas, classical European baroque fine-art tradition, expressive textural brushstrokes, rich physical depth.
Aspect Ratio: 16:9 widescreen composition.
Avoid: Modern clothing, cartoon styles, low detail, neon modern lighting, garbled watermarks.
```
