---
name: p5-web-editor
description: Scaffolding, live preview, and sandboxed browser development for p5.js sketches, creative coding shaders, canvas animations, and WebGL interactive art.
category: creative
risk: safe
source: community
source_repo: processing/p5.js-web-editor
source_type: community
date_added: "2026-10-06"
author: processing
tags: [p5js, processing, creative-coding, web-editor, generative-art, canvas, live-preview, shaders]
tools: [Bash, Read, Write]
---

# p5.js Web Editor & Sketch Sandbox

## Overview

The p5.js Web Editor environment enables rapid scaffolding, testing, live previewing, and asset bundling for creative coding sketches. It supports 2D canvas, WebGL rendering, custom GLSL shaders, sound synthesis (`p5.sound`), and generative drawing libraries.

## When to Use

- Quickly scaffolding and previewing interactive p5.js sketches in a local dev server.
- Creating self-contained HTML/JS generative art demos with audio and interactive controls.
- Porting sketches to and from the official p5.js web editor format.
- Debugging WebGL shaders, instance-mode sketches, and responsive canvas sizing.

---

## Standard Project Scaffolding

### 1. Zero-Config Local Preview Server

Create `index.html` and `sketch.js`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>p5.js Generative Sketch</title>
  <script src="https://cdn.jsdelivr.net/npm/p5@2.2/lib/p5.min.js"></script>
  <style>
    body { margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #0f172a; overflow: hidden; }
    canvas { box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); border-radius: 8px; }
  </style>
</head>
<body>
  <script src="sketch.js"></script>
</body>
</html>
```

### 2. Standard Responsive Sketch (`sketch.js`)

```js
let particles = []
const COUNT = 120

function setup() {
  createCanvas(windowWidth * 0.9, windowHeight * 0.9)
  for (let i = 0; i < COUNT; i++) {
    particles.push({
      x: random(width),
      y: random(height),
      vx: random(-1, 1),
      vy: random(-1, 1),
      r: random(2, 6)
    })
  }
}

function draw() {
  background(15, 23, 42, 35) // Trailing alpha fade
  noStroke()
  fill(99, 102, 241, 200)

  for (let p of particles) {
    p.x = (p.x + p.vx + width) % width
    p.y = (p.y + p.vy + height) % height
    circle(p.x, p.y, p.r * 2)
  }
}

function windowResized() {
  resizeCanvas(windowWidth * 0.9, windowHeight * 0.9)
}
```

---

For GLSL shader templates, sound synthesis, and instance-mode bundling, see [sketch-templates.md](references/sketch-templates.md).
