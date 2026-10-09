# Cinematic Color Grading & Film Looks 🎨🎞️

Technical guide for color science, Look Up Tables (LUTs), contrast curves, color harmony, and film stock emulation.

---

## 1. The Color Grading Pipeline

```
[Camera Raw / Log Footage]
        │
        ▼ 1. Normalization & Rec.709 Space Conversion
[Balanced Neutral Linear Image]
        │
        ▼ 2. Primary Correction (Exposure, White Balance, Contrast Pivot)
[Shot-to-Shot Color Matched Sequence]
        │
        ▼ 3. Secondary Correction (Skin-tone isolation, Sky luminance, Shadow tint)
[Harmonized Scene Palette]
        │
        ▼ 4. Creative Look / Film Print Emulation (LUT, Film Grain, Halation)
[Master Cinematic Export]
```

---

## 2. Signature Film Looks & Grading Recipes

### A. The Blockbuster Teal & Orange
- **Shadows:** Tinted cyan/teal (`RGB: 0, 140, 160`) at -10% luminance.
- **Highlights & Midtones:** Warm amber/golden (`RGB: 255, 175, 75`) specifically mapped to skin tones (the vectorscope skin-tone line).
- **Effect:** Maximum color contrast; human faces instantly pop off the background.

### B. Kodak Vision3 2383 Film Emulation
- **Toe & Shoulder:** Soft highlight roll-off with compressed highlight detail; velvety lifted blacks.
- **Color Crosstalk:** Subtly warmed reds and rich organic greens.
- **Halation:** Gentle warm glow along high-contrast edges (e.g. bright light against dark hair).
- **Grain:** Fine organic 35mm silver halide grain added to luminance midtones.

### C. The Gritty Documentary / Bleach Bypass
- **Luminance:** High contrast with crushed deep blacks and stark blown-out highlights.
- **Saturation:** Desaturated 30%–50% across all hues except warning colors (blood red, hazard yellow).
- **Vibe:** Forensic tension, geopolitical threat, raw uncompromising reality.

---

## 3. FFmpeg Color Grading Filters

```bash
# Kodak Film Look Simulation with curves, saturation, and subtle warm lift
ffmpeg -i input.mp4 -vf "eq=contrast=1.12:brightness=0.01:saturation=1.08, \
curves=r='0/0 0.25/0.24 0.75/0.82 1/1':b='0/0.04 0.25/0.22 0.75/0.72 1/0.95', \
unsharp=3:3:0.8:3:3:0.0" -c:v libx264 -crf 18 -preset slow output_cinematic.mp4
```
