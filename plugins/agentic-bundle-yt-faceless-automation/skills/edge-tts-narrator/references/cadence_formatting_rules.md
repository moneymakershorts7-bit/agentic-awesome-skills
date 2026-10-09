# Acoustic Cadence & Punctuation Formatting Rules 🖋️🔊

Edge-TTS neural acoustic models infer intonation curves, micro-pauses, pitch reset points, and vocal stress directly from textual punctuation and lexical syntax. This guide outlines how to transform regular written prose into high-impact spoken acoustic scripts.

---

## 1. Spanish Punctuation Acoustic Dynamics

### A. Inverted Question and Exclamation Marks (`¿?`, `¡!`)
- **Neural Behavior:** In Spanish models (`es-MX`, `es-ES`, `es-AR`), the presence of the opening mark (`¡` or `¿`) immediately pre-conditions the pitch generator at the start of the sentence rather than waiting for the end mark.
- **Rule:** Never omit the opening `¡` or `¿`.
- **Bad:** `Increíble lo que pasó en el vestuario!`
- **Good:** `¡Increíble lo que pasó en el vestuario!`

### B. The Suspense Ellipsis (`...`)
- **Neural Behavior:** Generates an acoustic decay and a 350ms–500ms silence gap.
- **Rule:** Use ellipses after critical setup phrases before revealing a name, number, or secret.
- **Example:** `Y el club que pagó la cláusula fue... el París Saint-Germain.`

### C. The Em-Dash for Parenthetical Aside (`—`)
- **Neural Behavior:** Creates a brief tone drop and a 200ms pause, signaling secondary commentary.
- **Example:** `Vinícius —que no había dicho una sola palabra— sonrió ante las cámaras.`

### D. Colons (`:`) for Dramatic Reveal
- **Neural Behavior:** Triggers a focused 250ms cadence pause and resets the intonation ceiling.
- **Example:** `Solo había una condición innegociable: ser el capitán indiscutible.`

---

## 2. Word Emphasis & Capitalization

- **Short Single-Word Emphasis:** Capitalize high-impact monosyllabic or short punchy words to trigger sharp stress (`¡NO!`, `¡YA!`, `¡NUNCA!`, `¡TODO!`, `¡CRACK!`).
- **Caution with Multi-Word All-Caps:** Avoid capitalizing entire full sentences (e.g. `¡NO PUEDE SER POSIBLE ESTO!`), as some neural models may attempt acronym letter-by-letter spelling. Keep capitalization to 1–2 key words per phrase.

---

## 3. Rhythmic Phrasing & Breath Groups

- **Short Chunk Rule (5–8 Words):** Keep spoken phrases between 5 and 8 words per breath group.
- **Conjunction Elimination:** Replace weak connective tissue (*"y entonces", "porque resulta que", "además de esto"*) with strong punctuation marks:
  - *Weak:* `El jugador llegó tarde y el entrenador se molestó mucho y lo mandó a la banca.`
  - *Punchy:* `El jugador llegó tarde. El entrenador no lo perdonó... ¡y lo mandó directo a la banca!`

---

## 4. Emotional Transformation Checklist

Before feeding a script to Edge-TTS:
1. [ ] Did you add opening `¡` and `¿` to all emotive and inquisitive sentences?
2. [ ] Are key dramatic reveals preceded by `...` or `:`?
3. [ ] Are sentences divided into bite-sized 5–8 word breath chunks?
4. [ ] Are high-impact emphasis words highlighted in uppercase?
5. [ ] Is each scene assigned an appropriate emotional prosody tag (`[EMOTION: HYPE]`, `[EMOTION: SUSPENSE]`, etc.)?
