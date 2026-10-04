---
name: book-designer-typesetter
description: "Professional book layout, typographic design, and PDF compilation engine from Markdown manuscripts."
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Grep
permissions:
  - shell
  - file_read
  - file_write
  - network
category: "documents-presentations"
risk: "safe"
source: "official"
source_repo: "moneymakershorts7-bit/agentic-awesome-skills"
source_type: "official"
date_added: "2026-10-04"
author: "Antigravity & Nolberto Pirela"
license: "MIT"
tags:
  - books
  - pdf
  - typography
  - publishing
---

# Book Designer & Typesetter

Engine for professional book design, typographic typesetting, and publication-ready PDF generation from Markdown manuscripts.

---

## When to Use

Use this skill when:
- Transforming a raw or edited Markdown manuscript (`.md`) into a polished, print-ready or digital distribution PDF book (`.pdf`).
- Designing book aesthetics: selecting font pairings, color palettes, margins, line heights, running headers/footers, and chapter openers.
- Formatting book anatomy: Cover, Half-Title, Full Title, Colophon/Copyright, Table of Contents, Chapters, Figures, and Academic Bibliography.
- Ensuring strict print standards: preventing widows and orphans, setting gutter margins, and handling high-resolution image embeds.

---

## Core Pillars & Design Matrix

### 1. Typography Pairings
Choose a typographic pairing matching the genre (see [typography_pairings.md](references/typography_pairings.md)):
- **Sacred History / Theological Epic (`sacred-history`):** *Cinzel* (Headings) + *EB Garamond* (Body).
- **Academic Monograph (`academic-oxford`):** *Playfair Display* + *Source Serif 4*.
- **Editorial Minimalist (`editorial-minimalist`):** *Cinzel / Inter* + *Lora*.
- **Renaissance Classic (`renaissance-earth`):** *Cormorant Garamond* + *EB Garamond*.

### 2. Editorial Color Palettes
Harmonious color schemes designed for readability and contrast (see [color_palettes.md](references/color_palettes.md)):
- **Sacred History:** Deep Imperial Burgundy (`#6E1A24`), Antique Gold (`#C5A059`), Soft Parchment (`#FDFCF7`).
- **Academic Oxford:** Oxford Navy (`#0A2540`), Slate (`#205493`), Crisp White (`#FFFFFF`).
- **Minimalist:** Charcoal (`#111111`), Ochre (`#C07D38`), Off-White (`#FAFAFA`).

### 3. Book Anatomy & CSS Paged Media
Adheres to traditional book structure (see [book_anatomy_and_css.md](references/book_anatomy_and_css.md)):
- **Front Matter:** Full-bleed cover, half-title, title page, colophon, interactive table of contents.
- **Body Matter:** Forced page breaks on chapters (`h1`), callout cards (`> 📖` Scripture, `> 📜` Historical, `> 🏛️` Fact-Check), editorial tables with zebra striping, centered figures with captions.
- **Back Matter:** Epilogue, acknowledgments, bibliography with hanging indents (`text-indent: -2em`).

---

## Quick Start CLI Workflow

Use the bundled CLI typesetter [`scripts/book_typesetter.py`](scripts/book_typesetter.py):

```bash
# Basic compilation with default theme (Sacred History, A4)
python3 scripts/book_typesetter.py \
  --input /path/to/manuscript.md \
  --output /path/to/book.pdf

# Full publication command with cover, custom metadata and theme
python3 scripts/book_typesetter.py \
  --input /path/to/manuscript.md \
  --output /path/to/book.pdf \
  --cover /path/to/cover.png \
  --theme sacred-history \
  --size A4 \
  --title "Título del Libro" \
  --subtitle "Subtítulo de la Obra" \
  --author "Nombre del Autor"
```

### CLI Options

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-i`, `--input` | Path to the source Markdown manuscript (`.md`) | *Required* |
| `-o`, `--output` | Destination path for the generated PDF | `<input_name>.pdf` |
| `-t`, `--theme` | Theme (`sacred-history`, `academic-oxford`, `editorial-minimalist`, `renaissance-earth`) | `sacred-history` |
| `-s`, `--size` | Trim size (`A4`, `trade-6x9`, `letter`) | `A4` |
| `--cover` | Path to front cover image (`.png`, `.jpg`) | `None` |
| `--title` | Book title override | Extracted from H1 |
| `--subtitle` | Book subtitle | Generic subtitle |
| `--author` | Author or compiler name | `Nolberto Pirela` |
| `--keep-html` | Preserve intermediate HTML file for inspection | `False` |

---

## References & Documentation
- [Typography Pairings Guide](references/typography_pairings.md): Detailed modular scales, leading, and kerning rules.
- [Color Palettes Reference](references/color_palettes.md): Hex codes, contrast ratios, and callout styling.
- [Book Anatomy & CSS Paged Media](references/book_anatomy_and_css.md): Formal structure and CSS layout rules.
- [Master CSS Stylesheet](templates/themes.css): Complete CSS Paged Media stylesheet.

---

## Limitations

- **Chromium / CDP Runtime Dependency**: Requires a headless Chromium or Chrome installation to execute CSS Paged Media layout and PDF generation via CDP.
- **Complex Floating Figures**: Multi-page wrapping around non-rectangular floating elements is constrained by browser CSS print layout capabilities.
- **Color Space**: Compiles primarily in sRGB / RGB colour profiles; prepress CMYK conversions require external tools like Ghostscript.

