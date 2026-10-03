# Editorial Workflow & Chapter-by-Chapter Production Checklist

This checklist guides the end-to-end execution of a book editing and writing project, maintaining quality control across each milestone.

---

## Pre-Production (Phase 0 & 1)

### Phase 0: Intake & Audit
- [ ] Source files gathered (.pdf, .md, .docx, .txt).
- [ ] Automated scan executed with `book_inspector.py` to identify word count, chapters, and missing citations.
- [ ] Core thesis and target audience established.
- [ ] Primary genre designated (Narrative, Technical, Essay, Biography, Business, Popular Science).

### Phase 1: Architectural Blueprint
- [ ] Book title and working subtitle formulated.
- [ ] Book-level Table of Contents generated with:
  - Working title per chapter.
  - 2–3 sentence narrative or thematic arc per chapter.
  - Anticipated key data points, figures, or case studies.
- [ ] Preliminary Fact-Checking Register created for suspect claims in the source notes.
- [ ] **Gate Check:** User explicit review and approval of the Table of Contents.

---

## Chapter Execution Loop (Phase 2)

Execute for Chapter 1 through Chapter N:

### Step 1: Pre-Draft Fact Alignment
- [ ] Review source notes allocated to this chapter.
- [ ] Verify core claims, dates, and names before drafting prose.
- [ ] Determine primary hook and ending cliffhanger or summary takeaway.

### Step 2: Prose Crafting
- [ ] Apply genre tone, syntactic rhythm, and narrative devices.
- [ ] Insert standardized callouts:
  - `> 📖` for primary/canonical texts.
  - `> 📜` for historical sources and verbatim letters.
  - `> 💡` for core mental models and principles.
- [ ] Construct clear Markdown tables for comparative data or chronologies.
- [ ] Ensure smooth internal transitions between subsections.

### Step 3: Footnoting & Citation Registry
- [ ] Insert inline numbered footnotes (`[^1]`).
- [ ] Append the chapter's verified bibliography section at the bottom.
- [ ] Document any corrections made to errors found in the source notes.

### Step 4: User Approval Gate
- [ ] Present completed chapter to the user.
- [ ] Collect feedback or revision requests.
- [ ] Perform requested line edits.
- [ ] Obtain explicit sign-off before commencing the next chapter.

---

## Post-Production & Publishing Apparatus (Phase 3)

### Global Integrity Check
- [ ] Verify cross-chapter anchor links and internal references.
- [ ] Audit character names, terminology, and recurring themes for absolute consistency across chapters.
- [ ] Run `book_inspector.py` to ensure zero leftover `[TODO]`, `[CITAR]`, or placeholder strings.

### Front & Back Matter Assembly
- [ ] Title Page & Copyright Notice.
- [ ] Dedication and Epigraph (if requested).
- [ ] Foreword / Preface / Introduction.
- [ ] Hyperlinked Interactive Table of Contents.
- [ ] Consolidated Master Bibliography.
- [ ] Subject & Name Index (or Analytical Appendix).
- [ ] Formal Colophon with publication credits and theological/editorial review acknowledgment.
