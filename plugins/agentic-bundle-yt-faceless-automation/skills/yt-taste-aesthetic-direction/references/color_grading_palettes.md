# Color Grading & Palette Harmony (Josef Albers Standard)

Grounded in Josef Albers' *Interaction of Color*, color is the most relative medium in art. A color is never seen as it really is physically; it is seen in constant relation to its neighbors.

---

## 1. The Three Laws of Albersian Color in Video

1. **Law of Simultaneous Contrast**:
   - A neutral gray placed on a deep cool navy background will appear warm and golden; placed on a warm amber background, it will appear cold and slate-blue.
   - Never pick accent colors in isolation on a white artboard. Always evaluate accents directly overlaid on the actual 60% ground.

2. **The 60-30-10 Distribution Rule**:
   - **60% Dominant Ground**: Sets the overall luminosity and mood (e.g., Obsidian Dark, Newsprint Warm Cream).
   - **30% Structural Secondary**: Shapes layout containers, lower thirds, typography boxes, and midground assets.
   - **10% Emotional Accent**: Reserved exclusively for the curiosity trigger, key metric, or dramatic focal point. Using more than 10% destroys visual hierarchy.

3. **Subtractive Value Hierarchy (Value > Hue)**:
   - Human vision detects value (light vs dark) before hue (color).
   - If a thumbnail or frame converted to greyscale loses its focal point, the color palette has failed.

---

## 2. Palette Tokens by Archetype

### Archetype 1: Documentary Noir (Investigative / Forensic)
* **60% Ground**: `#0A0D14` (Obsidian Void)
* **30% Structure**: `#1E222B` (Cold Slate Charcoal) & `#282D37` (Muted Steel)
* **10% Accent**: `#D4AF37` (Archive Gold) or `#991B1B` (Forensic Crimson)
* **Luminance Contrast**: Accent on Ground = `8.2:1` (WCAG AAA Pass)
* **LUT / Color Science**: Kodak Vision3 500T (5219), low saturation (70%), crushed blacks (RGB 10,12,18), lifted highlights with gentle roll-off.

### Archetype 2: Swiss Editorial (Data Journalism / Science)
* **60% Ground**: `#F7F5F0` (Newsprint Warm Ivory) or `#14171F` (Dark Editorial Slate)
* **30% Structure**: `#1E293B` (Deep Navy Slate) or `#E2E8F0` (Light Structure Border)
* **10% Accent**: `#0047AB` (Klein Blue) or `#FACC15` (Highway Safety Yellow)
* **Luminance Contrast**: Black Text on Ivory Ground = `16.4:1` (WCAG AAA Pass)
* **LUT / Color Science**: Rec.709 neutral, 5400K daylight white balance, zero tint, crisp geometric micro-contrast.

### Archetype 3: Technical Systems (Code / Systems Architecture)
* **60% Ground**: `#0B1120` (Deep Terminal Void)
* **30% Structure**: `#1E293B` (Graphite Navy) & `#334155` (Border Slate)
* **10% Accent**: `#10B981` (Terminal Emerald) or `#06B6D4` (Laser Cyan)
* **Luminance Contrast**: Emerald on Void = `9.1:1` (WCAG AAA Pass)
* **LUT / Color Science**: Cool blue bias (6200K), matte black shadows, clean linear gamma.

### Archetype 4: Cinematic Essay (Philosophical / Biographical)
* **60% Ground**: `#121316` (Filmic Charcoal)
* **30% Structure**: `#44403C` (Warm Stone) & `#78716C` (Taupe Midground)
* **10% Accent**: `#FAF7F2` (Alabaster White) or `#D97706` (Muted Amber)
* **Luminance Contrast**: Alabaster on Charcoal = `14.8:1` (WCAG AAA Pass)
* **LUT / Color Science**: Kodak 2383 Print Film stock emulation, subtle yellow-green shadows, warm skin tones, gentle highlight roll-off.

### Archetype 5: Minimalist Vector (Broad Educational)
* **60% Ground**: `#0C1427` (Midnight Royal Navy)
* **30% Structure**: `#1E293B` (Vector Indigo Slate) & `#475569` (Sub-element Slate)
* **10% Accent**: `#F59E0B` (Solar Amber) or `#EF4444` (Vibrant Coral)
* **Luminance Contrast**: Solar Amber on Midnight Navy = `9.4:1` (WCAG AAA Pass)
* **LUT / Color Science**: Clean digital sRGB, uniform saturation curve, no film grain.

---

## 3. Luminance Calculation & WCAG Formula

To calculate the relative luminance $L$ of any sRGB color:
$$R_s = R / 255, \quad G_s = G / 255, \quad B_s = B / 255$$
For each channel $C \in \{R_s, G_s, B_s\}$:
$$C_{\text{linear}} = \begin{cases} C / 12.92 & \text{if } C \le 0.04045 \\ \left(\frac{C + 0.055}{1.055}\right)^{2.4} & \text{if } C > 0.04045 \end{cases}$$
$$L = 0.2126 \cdot R_{\text{linear}} + 0.7152 \cdot G_{\text{linear}} + 0.0722 \cdot B_{\text{linear}}$$
Contrast Ratio $CR$:
$$CR = \frac{L_1 + 0.05}{L_2 + 0.05} \quad (L_1 > L_2)$$

* **Required Thresholds**:
  - Hero Text against backing: $CR \ge 4.5:1$ (AA minimum, AAA preferred $> 7:1$).
  - Thumbnail subject silhouette against backdrop: $CR \ge 3.0:1$.
