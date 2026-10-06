---
name: p5-brush
description: Natural drawing, watercolor fills, charcoal, marker textures, hatch patterns, and vector fields engine for p5.js (WebGL mode) and standalone WebGL2 canvas.
category: creative
risk: safe
source: community
source_repo: acamposuribe/p5.brush
source_type: community
date_added: "2026-10-06"
author: acamposuribe
tags: [p5js, generative-art, brush, watercolor, canvas, webgl2, vector-field, shaders]
tools: [Bash, Read, Write]
---

# p5.brush: Natural Drawing & Generative Painting Engine

## Overview

`p5.brush` is a WebGL-powered drawing engine providing natural media simulation (pencils, charcoal, markers, watercolor bleeding, cross-hatching, and vector flow fields). It runs both as a p5.js WebGL plugin and as a zero-dependency standalone WebGL2 library.

## When to Use

- Building procedural, organic, or hand-drawn generative art in p5.js or WebGL2.
- Rendering realistic watercolor washes with edge bleeding, granulation, and layering.
- Creating cross-hatching, stippling, and textured brush strokes (HB pencil, 2B, marker, charcoal, spray).
- Guiding brush strokes and textures along vector flow fields or curl noise.
- Creating standalone WebGL2 canvas visualizations without loading p5.js.

---

## Critical Architecture: Two Distinct Builds

| Feature | p5.js Build (`dist/p5.brush.js`) | Standalone Build (`p5.brush/standalone`) |
| :--- | :--- | :--- |
| **Import** | `import * as brush from 'p5.brush'` | `import * as brush from 'p5.brush/standalone'` |
| **Dependencies** | p5.js 2.x (WebGL mode) | Zero dependencies (Browser WebGL2) |
| **Canvas Init** | `createCanvas(w, h, WEBGL)` | `brush.createCanvas(w, h)` |
| **Transform Matrix**| Native p5 `push()`, `pop()`, `translate()` | `brush.push()`, `brush.pop()`, `brush.translate()` |
| **Coordinate Origin**| Center `(0, 0)` → shift via `translate(-W/2, -H/2)` | Top-left `(0, 0)` |
| **Frame Flush** | Automatic p5 draw loop flush | **Mandatory `brush.render()`** at frame end |
| **Clearing** | Native p5 `background(color)` | `brush.clear(color?)` |
| **Random Seeding** | `randomSeed(n)` / `noiseSeed(n)` | `brush.seed(n)` / `brush.noiseSeed(n)` |

> [!WARNING]
> Never mix builds. Standalone builds require explicit `brush.render()` calls per frame. p5 WebGL mode requires shifting coordinates by `translate(-width/2, -height/2)` to use standard `(0,0)` top-left coordinates.

---

## Core API & Patterns

### 1. p5.js WebGL Setup & Basic Stroke

```js
import * as brush from 'p5.brush'

function setup() {
  createCanvas(800, 800, WEBGL)
  angleMode(DEGREES)
  brush.scaleBrushes(3) // Scale brush stroke geometry to canvas resolution
}

function draw() {
  background("#fffceb")
  translate(-width / 2, -height / 2) // Re-align to top-left origin

  // Select brush: name, color, weight
  brush.set("HB", "#1a1a1a", 1.5)
  brush.line(100, 100, 700, 700)

  // Spline / Flowing Curve
  brush.beginStroke("charcoal", "#2b2b2b")
  brush.spline([[100, 200], [300, 450], [500, 300], [700, 600]], 0.5)
  brush.endStroke()
}
```

### 2. Watercolor Bleed & Wash Fills

```js
// Configure watercolor fill: color, opacity (0-255), bleed passes
brush.fill("#3b82f6", 140)
brush.bleed(0.25, "out") // Bleed intensity and direction ('in', 'out', 'both')

// Draw organic watercolor polygon
brush.beginShape()
brush.vertex(200, 200)
brush.vertex(500, 180)
brush.vertex(450, 480)
brush.vertex(180, 420)
brush.endShape(CLOSE)
```

### 3. Hatch Patterns & Textures

```js
// Cross-hatching with custom spacing, angle, and brush
brush.hatch("cross", 8, 45) // type ('cross', 'parallel', 'stipple'), spacing, angle
brush.setHatch("2B", "#4b5563", 0.8)
brush.rect(150, 150, 300, 300)
```

### 4. Vector Flow Field Guidance

```js
// Guide strokes along vector field
brush.field("curl") // Use built-in curl or custom flow field grid
brush.flow({
  brush: "marker",
  color: "#ef4444",
  steps: 60,
  stepSize: 4,
  seeds: [[100, 100], [200, 150], [300, 200]]
})
```

---

## Built-in Brush Presets

- **Pencils**: `"HB"`, `"2B"`, `"cpencil"` (colored pencil with grain).
- **Inks & Markers**: `"marker"`, `"pen"`, `"fine-liner"`, `"brush-pen"`.
- **Media**: `"charcoal"`, `"spray"`, `"oil-pastel"`, `"watercolor"`.

For complete API signatures, custom shader brush authoring, and standalone mode examples, see [api-reference.md](references/api-reference.md).
