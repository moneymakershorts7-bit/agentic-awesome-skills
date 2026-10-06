# SVG Asset & Vector Motion Pipeline

How to prepare, export, and animate vector artwork from Illustrator, Figma, or AI vector generators for code-based video pipelines.

---

## 1. Vector Hierarchy & Naming Standards

When exporting vector assets for animation, every animatable element must have a distinct semantic ID / layer name:

### Character Naming Convention:
- `char_head` (Root group for facial features)
- `char_eye_left`, `char_eye_right` (Pupil + eyelid paths)
- `char_eyebrow_left`, `char_eyebrow_right` (Expression tilt/lift)
- `char_mouth` (Phoneme/expression paths)
- `char_body`, `char_arm_left`, `char_arm_right` (Pointers and gesture limbs)

### Scene & Prop Naming Convention:
- `bg_surface` (Base container/canvas)
- `node_source_doc` (Source document vector)
- `node_action_card` (Target structured card)
- `arrow_connector_01` (Directional flow arrows)
- `badge_due_date` (Pill / status badge)

---

## 2. Illustrator / Figma Export Settings

### Adobe Illustrator Export:
1. `File` $\to$ `Export` $\to$ `Export As...` $\to$ Format: **SVG**.
2. **Object IDs:** Set to **Layer Names** (preserves semantic IDs).
3. **Styling:** Internal CSS or Inline Styles.
4. **Minify:** OFF during development and animation binding.
5. **Responsive:** Checked (removes hardcoded `width`/`height`, retains `viewBox`).
6. **Decimal Precision:** 2–3 places.

### Figma Export:
1. Name layers cleanly in the Figma layer tree before exporting.
2. Select Frame/Group $\to$ Export SVG $\to$ Check **Include "id" Attribute**.

---

## 3. SVG Path Animation in Remotion / CSS

### 1. Animated Path Drawing (`strokeDashoffset`):
```tsx
import React from 'react'
import { interpolate, useCurrentFrame } from 'remotion'

export const AnimatedPath: React.FC<{ d: string; pathLength: number; startFrame: number }> = ({
  d,
  pathLength,
  startFrame
}) => {
  const frame = useCurrentFrame()
  const offset = interpolate(frame, [startFrame, startFrame + 30], [pathLength, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp'
  })

  return (
    <path
      d={d}
      stroke="#6366f1"
      strokeWidth={3}
      fill="none"
      strokeDasharray={pathLength}
      strokeDashoffset={offset}
    />
  )
}
```

### 2. Natural Blink Animation:
```tsx
import React from 'react'
import { interpolate, useCurrentFrame } from 'remotion'

export const BlinkingEye: React.FC<{ eyeId: string; frameCycle?: number }> = ({
  eyeId,
  frameCycle = 90
}) => {
  const frame = useCurrentFrame()
  const cycleFrame = frame % frameCycle

  // Quick blink over 6 frames
  const scaleY = interpolate(cycleFrame, [0, 2, 4, 6], [1, 0.1, 0.1, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp'
  })

  return (
    <g id={eyeId} style={{ transformOrigin: 'center', transform: `scaleY(${scaleY})` }}>
      {/* Eye shape / paths */}
    </g>
  )
}
```
