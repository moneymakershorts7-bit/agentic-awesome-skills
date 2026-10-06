# Thinking Orbs Technical Specifications

## Vanilla Canvas Implementation

```js
class OrbRenderer {
  constructor(canvas, state = "working", size = 64) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.state = state;
    this.size = size;
    this.canvas.width = size * window.devicePixelRatio;
    this.canvas.height = size * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  render(t) {
    const { ctx, size, state } = this;
    ctx.clearRect(0, 0, size, size);
    // Draw procedural particle lattice according to state math function
  }
}
```

## React Native Compatibility

Use the `@thinking-orbs/react-native` package with `react-native-svg` or Skia canvas backend for 60fps native thread execution.
