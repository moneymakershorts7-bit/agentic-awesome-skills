# p5.brush Complete API Reference

## 1. Standalone WebGL2 Implementation

For projects without p5.js:

```js
import * as brush from 'p5.brush/standalone'

const canvas = brush.createCanvas(800, 800)
document.body.appendChild(canvas)

brush.scaleBrushes(3)
brush.clear("#fefcf0")

// Draw stroke
brush.set("charcoal", "#1e1e1e", 2)
brush.line(50, 50, 750, 750)

// Watercolor fill
brush.fill("#10b981", 120)
brush.bleed(0.3, "both")
brush.rect(200, 200, 400, 400)

// CRITICAL: Standalone mode requires explicit frame flush
brush.render()
```

## 2. Hatch Patterns

- `brush.hatch(type, spacing, angle)`:
  - `type`: `"cross"`, `"parallel"`, `"stipple"`, `"dots"`, `"scribble"`
  - `spacing`: Pixel distance between hatch lines
  - `angle`: Hatch angle in degrees (or radians if `angleMode(RADIANS)`)
- `brush.setHatch(brushName, color, weight)`: Configures the brush style used for hatching.
- `brush.noHatch()`: Disables hatch patterns on subsequent shapes.

## 3. Watercolor Bleed & Granulation

- `brush.bleed(intensity, direction)`:
  - `intensity`: Float between `0.0` (sharp edges) and `1.0` (diffuse wet-on-wet wash).
  - `direction`: `"in"`, `"out"`, or `"both"`.
- `brush.granulation(level)`: Controls paper pigment texture clustering (0.0 to 1.0).

## 4. Custom Brush Creation

```js
brush.createCustomBrush("felt-marker", {
  texture: "noise",       // 'noise', 'grain', 'smooth', 'splatter'
  bristleCount: 18,       // Number of sub-strokes
  spread: 4.5,            // Jitter radius
  pressureDynamics: true, // Modulate weight with velocity/pressure
  blendMode: "multiply"   // WebGL blend equation
})
```
