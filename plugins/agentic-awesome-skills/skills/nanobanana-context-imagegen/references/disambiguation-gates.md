# The Zero-Guessing Clarification Gate

> Concrete guidelines, decision trees, and question templates to ensure agents never hallucinate or invent creative choices when text context is underspecified.

---

## 1. The Zero-Guessing Mandate

> [!IMPORTANT]
> **Core Principle:** An agent must NEVER imagine, guess, or hallucinate visual details when working from user documents. If an essential stylistic, compositional, or subject decision is ambiguous or has multiple valid interpretations, the agent MUST stop and ask a concise, direct question before generating.

### When to Trigger the Clarification Gate
Trigger the gate if **ANY** of the following conditions are met:
1. **Multiple Diverging Subjects:** The chapter describes two equally important dramatic scenes (e.g., Vision of the Celestial Messenger vs Daniel falling to the ground in awe).
2. **Unspecified Visual Medium / Style:** The context doesn't specify whether the book needs classical oil painting, hyperrealistic cinematic photography, digital editorial art, or vintage woodcut engraving.
3. **Ambiguous Asset Role / Ratio:** Unclear whether the image is meant as a vertical book cover (`3:4` / `2:3`) or a widescreen section header (`16:9`).
4. **Historical vs Symbolic Treatment:** Unclear whether to render literal historical realism (Babylonian garments, ancient landscape) or symbolic allegorical representation (ethereal heavenly realm).

---

## 2. Formulating Concise Questions (Golden Rules)

### ❌ Anti-Patterns (What NEVER to do)
- **Do not ask open-ended, lazy questions:**
  - *"What image do you want?"*
  - *"How should the illustration look?"*
  - *"What style do you prefer?"*
- **Do not ask multi-part interrogations:**
  - *"What style, what color palette, what characters, what lighting, and what resolution do you need?"*
- **Do not make unconfirmed assumptions:**
  - Proceeding with an assumed art style without obtaining user confirmation when context lacks explicit visual direction.

### ✅ Golden Patterns (What ALWAYS to do)
1. **State the exact context fork:** Explain why the question is being asked in one sentence.
2. **Present 2 to 3 concise, numbered options:** Each option must be distinct, self-contained, and ready to pick with a single keystroke.
3. **Recommend a default:** Clearly label one option as `(Recommended)` based on document genre conventions.

---

## 3. Question Templates

### Template A: Artistic Medium & Style Selection
```markdown
For the illustrations of **[Document / Chapter Title]**, which artistic medium best matches your book design?

1. **(Recommended) Classical Oil Painting:** Dramatic Rembrandt/Caravaggio chiaroscuro, rich earth and lapis pigments, timeless fine-art aesthetic.
2. **Cinematic Photorealism:** 35mm film still, natural directional lighting, authentic tactile fabric and architectural textures.
3. **Antique Woodcut / Engraving:** Vintage monochrome line-art with fine cross-hatching, suitable for classic printed book margins.
```

### Template B: Scene & Focal Subject Selection
```markdown
Chapter **[X]** contains two key visual moments. Which scene would you like to illustrate?

1. **(Recommended) The Heavenly Vision:** A panoramic scene of the radiant celestial messenger standing above the Tigris river, with lightning and beryl glow (16:9 widescreen).
2. **Daniel's Reverence:** An intimate dramatic shot focusing on Daniel on the riverbank, overwhelmed in awe, with the vision reflected in the water (3:4 book plate).
```

### Template C: Asset Role & Aspect Ratio
```markdown
Where will this image be placed in **[Document / Book Title]**?

1. **(Recommended) Chapter Frontispiece / Plate:** Full vertical page (3:4 aspect ratio).
2. **Section Header / Banner:** Wide horizontal banner at the chapter start (16:9 widescreen).
3. **Book Cover:** Dramatic vertical composition with generous negative space for title typography (2:3 aspect ratio).
```

---

## 4. Interactive Ask Tool Integration

When running inside an interactive agent harness supporting `ask_question`:
```python
ask_question(questions=[{
    "question": "Which visual style should be applied to the chapter illustrations?",
    "options": [
        "(Recommended) Classical Oil Painting (dramatic lighting, rich museum fine-art aesthetic)",
        "Cinematic Historical Photorealism (natural lighting, authentic period textures)",
        "Vintage Copperplate Engraving (monochrome line-art with cross-hatching)"
    ],
    "is_multi_select": False
}])
```
If the tool is unavailable, output the question directly as concise Markdown text in the assistant's turn and await user selection.
