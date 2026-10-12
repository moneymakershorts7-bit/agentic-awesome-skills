---
name: doc-to-comic
description: "Converts text books, literary novels, and technical documents into episodic, fully-illustrated historietas (comics). Implements Eisner layout principles, McCloud transitions, Neil Cohn Visual Narrative Grammar, character identity anchoring, and automated multi-panel compositing."
allowed-tools:
  - bash
  - read
  - edit
  - write
  - python
permissions:
  - file_read
  - file_write
metadata:
  version: "1.0.0"
  framework: "sequential-visual-grammar"
  author: "community"
---

# 📖 Doc-to-Comic (Historieta Generator)

Transform raw text (textbooks, literature, technical papers, corporate documentation) into structured, sequentially cohesive **historietas (comics & graphic novels)**.

Comics are an autonomous visual-linguistic system, not merely illustrations with text pasted over them. This skill unifies:
- **Will Eisner (*Comics and Sequential Art*)**: The comic page as a staged canvas, lettering typography as art, reader gaze choreography, and independent text layers.
- **Scott McCloud (*Understanding Comics*)**: Panel gutter closure mechanics, aspect ratios, and the 6 panel-to-panel transitions (action-to-action, scene-to-scene, aspect-to-aspect for environmental explanations).
- **Dr. Neil Cohn (*The Visual Language of Comics*)**: Hierarchical Visual Narrative Grammar (VNG) assigning syntactic roles: **Establisher ($E$) $\to$ Initial ($I$) $\to$ Peak ($P$) $\to$ Release ($R$)**.
- **Adversarial Hardening (`el-decimo-hombre`)**: Strict limits on word budgets (max 20 words per balloon), face occlusion guards (<25% area coverage), and visual token anchoring to avoid character drift.

---

## 🛠️ The 5-Stage Agentic Pipeline

```
Raw Document / Book 
       │
       ▼
[Stage 1: Script Adapter & Lore Master] 
  → Cohn VNG syntactic breakdown (E → I → P → R)
  → Word count budgeting (<20 words/balloon)
       │
       ▼
[Stage 2: Visual Layout & Gutter Director]
  → McCloud transitions & Eisner page staging
  → Grid allocation (4-koma, 6-panel, dynamic splash)
       │
       ▼
[Stage 3: Character & Aesthetic Anchor]
  → Style selection (Ligne Claire, Retro Sci-Fi, Dark Noir, Manga)
  → Freeze character identifiers & negative prompt seeds
       │
       ▼
[Stage 4: Clean Panel Image Generation]
  → Dispatches to image diffusion engine (Flux, SDXL, Imagen, Midjourney)
  → Strictly outputs text-free, raw clean visuals
       │
       ▼
[Stage 5: Python Compositor & Letterer Engine]
  → Programmatic SVG/Pillow speech balloon and caption rendering
  → Generates Cover Page, Story Pages, and Credit Back-Cover into PDF / CBZ
```

---

## 🚀 Usage Commands & Workflows

### 1. Generate Script from Text or Book
To analyze and adapt a text passage into a structured comic blueprint:
```bash
python3 scripts/comic_pipeline.py adapt --input "<path_to_book_or_text>" --style "ligne_claire" --output "comic_spec.json"
```

### 2. Validate Specification
Audit the script against `el-decimo-hombre` constraints (word budget, panel counts, anchor tokens):
```bash
python3 scripts/comic_pipeline.py validate --spec "comic_spec.json"
```

### 3. Composite Final Comic Page / Book
Render the visual panels, speech balloons, title cover, and credits into a high-resolution PDF or CBZ:
```bash
python3 scripts/comic_pipeline.py render --spec "comic_spec.json" --output "dist/comic_issue_1.pdf"
```

---

## 📐 Detailed References
- [Visual Narrative Grammar & Transitions](references/visual_narrative_grammar.md)
- [Style & Aesthetic Archetypes](references/style_archetypes.md)
- [Lettering & Balloon Occlusion Guidelines](references/lettering_rules.md)
