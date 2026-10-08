# The Five-Stage Animation Pipeline Architecture

The **Clief Notes Video-as-Code** method organizes explainer animations into 5 strictly decoupled directories within each project folder.

```
my-explainer/
├── docs/
│   ├── brief.md              # Target audience, core lesson, approved source text
│   └── prd.md                # Component inventory, color tokens, layout constraints
├── 01_voice/
│   ├── script.md             # Spoken narration with stage direction
│   └── narration.wav         # Approved, clean voice master take
├── 02_transcript/
│   ├── transcript.json       # Word-level timestamps from Whisper or TTS engine
│   └── words.csv             # Human-readable timing review table
├── 03_cues/
│   ├── cues.md               # Visual storyboard linked to timestamp cues
│   └── timeline.json         # Compiled frame-indexed beat triggers
├── 04_scene/
│   ├── assets/               # SVGs, icons, logos, characters
│   ├── components/           # Reusable UI primitives (Card, Highlight, Callout)
│   └── Scene.tsx             # Remotion scene composition or Web preview HTML
└── 05_render/
    ├── preview.mp4           # Fast draft export for validation
    └── master_1080p.mp4      # Final high-bitrate verified video export
```

---

## Detailed Stage Specifications

### Stage 1: Script & Narration (`01_voice/`)
1. **Word Economy:** Keep sentences under 15 words. Avoid passive structures.
2. **Punctuation as Prosody:** Commas create 200–300ms breath pauses; periods create 500–700ms topic beats.
3. **No Visual References in Script:** Narration should stand alone as audio without awkward "as you can see here" phrasing.
4. **Approval Gate:**
   - Listen to the audio once in isolation (eyes closed).
   - Listen a second time while reading `script.md`.
   - Ensure names, acronyms, and technical terms are pronounced with 100% clarity.

### Stage 2: Timed Transcript (`02_transcript/`)
1. Extract word and phrase bounding boxes `(start_sec, end_sec)`.
2. Group words into natural cadence chunks (3–7 words per phrase).
3. Record duration in milliseconds and frame units:
   $$\text{Frame} = \text{round}(\text{seconds} \times \text{FPS})$$

### Stage 3: Visual Storyboard & Cues (`03_cues/`)
1. **The 3-Second Rule:** Never leave a screen static for more than 3 seconds without a focal shift, highlight pulse, or layout progression.
2. **Paired Highlights:** When explaining relationships (e.g. source note $\to$ action card), highlight the source phrase simultaneously with the created element.
3. **Layout Safe Margins:**
   - Subtitle safe zone: bottom 180px reserved.
   - Presenter/avatar safe zone: bottom-right or top-right $320 \times 320\text{px}$.

### Stage 4: Scene & Composition (`04_scene/`)
1. **Motion Design Rules (Emil Kowalski Standards):**
   - Micro-interactions (card reveals, hover, popover): 180–240ms `ease-out`.
   - State transformations (resizing, repositioning): 300–450ms custom bezier (`cubic-bezier(0.16, 1, 0.3, 1)`).
   - Entrance scale: Always enter from `scale(0.94)` + `opacity: 0`, never `scale(0)`.
2. **Layout & Component Decoupling:**
   - Visual styling lives in React / CSS components.
   - Animation progress is driven deterministically by `useCurrentFrame()` and `interpolate()`.

### Stage 5: Render & Multi-Platform Delivery (`05_render/`)
1. **Master Render (16:9 Landscape):** $1920 \times 1080$ @ 30fps (H.264, AAC 320kbps).
2. **Social Cut (9:16 Vertical):** $1080 \times 1920$ with centered focus cards and top/bottom content framing.
3. **Quality Verification Checklist:**
   - [ ] Audio plays fully with zero clipping or early cutoffs at the end.
   - [ ] No text overlap on any frame.
   - [ ] Color matches original design tokens.
   - [ ] Video ends on a stable hold of 1.5–2.0 seconds before black.
