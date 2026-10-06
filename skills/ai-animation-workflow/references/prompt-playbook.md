# AI Animation Workflow: Prompt Playbook

Use these tested prompt templates to guide AI assistants through each stage of the video-as-code animation process.

---

## 1. Stage 01: Script Generation Prompt

```markdown
Read `docs/brief.md` and the source text in `source.txt`.
Write a spoken voiceover script in `01_voice/script.md`.

Requirements:
1. Target length: ~45–60 seconds (approx. 110–140 words).
2. Tone: Calm, clear, explanatory, direct.
3. Sentence structure: Short, active sentences. Use commas for natural breath pauses.
4. Mark distinct beats with [Beat 1], [Beat 2] headers.
5. Do NOT include visual directions inside the spoken text itself.
6. Provide phonetic guides for any technical terms or unusual names.

Stop for review. Do not generate audio or proceed to scenes until I approve this script.
```

---

## 2. Stage 03: Visual Cue Plan / Storyboard Prompt

```markdown
Read the approved voice audio in `01_voice/narration.wav` and the timestamped transcript in `02_transcript/transcript.json`.
Draft the visual storyboard in `03_cues/cues.md`.

For each spoken phrase / beat, define:
1. `Timestamp`: [MM:SS.ms] - [MM:SS.ms] and frame range at 30fps.
2. `Spoken Words`: The exact phrase spoken during this window.
3. `Visual State`: What appears on screen (Source Note, Action Card, Tag, Diagram).
4. `Focus & Emphasis`: Which words/elements receive paired color highlights.
5. `Motion Intent`: Entrance style (fade+slide up), camera focus, or state change.
6. `Safe Zone Check`: Verify that bottom 180px and character zone remain free of vital text.

Stop for human review of `cues.md`. Do not write animation code yet.
```

---

## 3. Stage 04: Scene Generation Prompt (Remotion / Web)

```markdown
Read `03_cues/cues.md`, `03_cues/timeline.json`, and design tokens in `docs/prd.md`.
Build the Remotion animation scene in `04_scene/Scene.tsx`.

Requirements:
1. Separate layout components (`04_scene/components/`) from timeline orchestration (`04_scene/Scene.tsx`).
2. Use `useCurrentFrame()` and `interpolate()` with `extrapolateRight: 'clamp'` for all transitions.
3. Implement Emil Kowalski easing: snappy `ease-out` (duration 180–240ms) for card reveals; no `scale(0)` entrances.
4. Add paired highlight synchronization: when the voice mentions an attribute (e.g. "Friday"), both the source snippet and the card badge illuminate with `--accent-highlight`.
5. Capture still previews at each major beat and output a preview video for review.
```

---

## 4. Stage 05: Scene Review & Fix Prompt

```markdown
Review the rendered preview in `05_render/` against `03_cues/cues.md`.
At timestamp [MM:SS.ms] / frame [X]:
- Issue: [Describe what is covered, late, or unreadable].
- Cause Category: [Layout overlap / Cue timing / Typography scale].
- Requested Fix: [Specific change, e.g. move footer tag 40px down and delay highlight by 6 frames].

Apply only this fix. Re-render a 5-second slice around this beat and verify before full render.
```
