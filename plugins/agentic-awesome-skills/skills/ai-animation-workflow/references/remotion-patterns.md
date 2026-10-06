# Remotion Video Patterns for AI Explainers

Reference patterns for constructing deterministic explainer scenes in Remotion.

---

## 1. Frame-Synced Cue Engine

Drive animations dynamically from compiled cue timestamps:

```typescript
import { interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';

export interface CueItem {
  id: string;
  startFrame: number;
  endFrame: number;
  label: string;
}

export function useCueProgress(startFrame: number) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const progress = spring({
    frame: frame - startFrame,
    fps: fps,
    config: { damping: 14, mass: 0.6, stiffness: 120 }
  });

  const opacity = interpolate(frame, [startFrame, startFrame + 6], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp'
  });

  const scale = interpolate(progress, [0, 1], [0.94, 1.0]);
  const translateY = interpolate(progress, [0, 1], [16, 0]);

  return { progress, opacity, scale, translateY };
}
```

---

## 2. Paired Highlight Component

Illuminate source text and extracted cards in sync:

```typescript
import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';

interface HighlightProps {
  children: React.ReactNode;
  startFrame: number;
  duration?: number;
  color?: string;
}

export const PairedHighlight: React.FC<HighlightProps> = ({
  children,
  startFrame,
  duration = 45,
  color = '#f59e0b'
}) => {
  const frame = useCurrentFrame();
  const progress = interpolate(
    frame,
    [startFrame, startFrame + 8, startFrame + duration - 8, startFrame + duration],
    [0, 1, 1, 0.2],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }
  );

  return (
    <span
      style={{
        backgroundColor: 'rgba(245, 158, 11, 0.25)',
        borderBottomWidth: 2,
        borderBottomStyle: 'solid',
        borderBottomColor: color,
        borderRadius: 4,
        padding: '2px 6px'
      }}
    >
      {children}
    </span>
  );
};
```

---

## 3. Explainer Split-Scene Composition

```typescript
import React from 'react';
import { AbsoluteFill, Audio, staticFile } from 'remotion';
import { useCueProgress } from './useCueProgress';
import { PairedHighlight } from './PairedHighlight';

export const ExplainerScene: React.FC = () => {
  const sourceCue = useCueProgress(15);
  const cardCue = useCueProgress(75);

  return (
    <AbsoluteFill style={{ backgroundColor: '#0f172a', color: '#f8fafc', padding: 64 }}>
      <Audio src={staticFile('narration.wav')} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 48, alignItems: 'center' }}>
        <div style={{ opacity: sourceCue.opacity, transform: 'scale(' + sourceCue.scale + ')' }}>
          <h3>Source Note</h3>
          <p>
            <PairedHighlight startFrame={80}>Sam</PairedHighlight> will send the draft on Friday.
          </p>
        </div>
        <div style={{ opacity: cardCue.opacity, transform: 'scale(' + cardCue.scale + ')' }}>
          <h3>Action Item</h3>
          <div>Owner: Sam</div>
          <div>Due: Friday</div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
```
