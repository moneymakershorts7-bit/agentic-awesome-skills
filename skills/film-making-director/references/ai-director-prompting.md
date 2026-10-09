# AI Video Generation Prompt Directing 🤖🎬

Translating directorial intent into deterministic, high-yield generative prompts for modern text-to-video and image-to-video AI models (Runway Gen-3, Kling, Wan, LTX Video, Seedance, Sora, Veo, Midjourney v6, Flux.1).

---

## 1. The Directorial Prompt Formula

Every shot prompt must be structured using the **Directorial Sequence Architecture**:

```
[Framing + Lens + Rig Move] of [Subject with Locked Continuity Descriptors] 
[Performing ONE Deterministic Action, Present Tense], in [Environment / Atmosphere]. 
[Lighting Scheme + Key Angle + Shadow Ratio]. [Color Grade / Film Emulation]. [4K, Cinematic, Photorealistic].
```

---

## 2. Directorial Prompting Vocabulary

### Camera Movements
- `Slow dramatic dolly push-in` / `Smooth steadycam forward track`
- `Subtle handheld breathing motion with natural micro-jitter`
- `Slow crane pedestal down reveal` / `360-degree orbital rotation around subject`
- `Fast whip-pan transition right to left` / `Locked-off tripod static shot with moving foreground`

### Lenses & Optics
- `Shot on 35mm anamorphic lens, 2.39:1 aspect ratio, subtle blue horizontal lens flare`
- `85mm f/1.4 prime lens, ultra-shallow depth of field, creamy bokeh background`
- `24mm ultra-wide cine lens, sharp foreground focus, dramatic environmental perspective`
- `Macro probe lens moving past intricate circuitry / microscopic water droplets`

### Lighting & Atmosphere
- `Chiaroscuro lighting, hard key light from 45-degree angle, deep velvety shadows`
- `Volumetric god rays streaming through dusty warehouse windows, atmospheric haze`
- `Golden hour warm rim light backlighting hair, soft natural fill`
- `Neon cyber-noir lighting, dual-tone magenta and cyan reflections on wet asphalt`
- `Overcast diffuse softbox illumination, gentle highlight roll-off`

### Film Stocks & Color
- `Kodak Vision3 500T 35mm film stock, organic fine grain, rich warm skin tones`
- `Bleach bypass desaturated silver look, high contrast, crushed blacks`
- `Technicolor three-strip vibrant palette, saturated primary colors`
- `Arri Alexa Mini LF, Log-C converted to Rec.709, smooth neutral color rendition`

---

## 3. The 5 Cardinal Sins of AI Video Prompting

1. ❌ **Describing Two Actions in One Clip:** *"Man enters room, walks to desk, sits down, and opens laptop."* (The model will morph limbs and glitch).
   - ✅ **Fix:** Split into two distinct shots: Shot 1 (Dolly tracking man walking across room) $\to$ Shot 2 (Close-up of hands opening glowing laptop).
2. ❌ **Prompting Emotional Subtext Instead of Physical Action:** *"The detective feels heartbroken and betrayed."*
   - ✅ **Fix:** *"Medium close-up of tired detective looking down, slowly exhaling a cloud of cigarette smoke, tears welling in eyes, hands shaking slightly."*
3. ❌ **Varying Character Descriptors:** (Model generates a different face each shot).
   - ✅ **Fix:** Define a locked continuity descriptor string and paste it verbatim into every prompt.
4. ❌ **Neglecting Negative Prompts:**
   - Always include standard negative guards: `deformed limbs, extra fingers, cartoonish, oversaturated, morphing, low resolution, watermark, jerky camera shake, text overlay, multiple heads.`
5. ❌ **Over-prompting Background Clutter:**
   - Keep focal hierarchy clean: 1 Primary Subject + 1 Primary Motion + 1 Unified Lighting Scheme.
