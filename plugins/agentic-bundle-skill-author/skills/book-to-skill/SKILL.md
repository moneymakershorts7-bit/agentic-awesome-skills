---
name: book-to-skill
description: "Converts books and documents (PDF, EPUB, DOCX, HTML, Markdown, plain text, RTF, MOBI/AZW) into structured, on-demand agent skills. Extracts mental models, frameworks, principles, and techniques with progressive disclosure."
allowed-tools:
  - bash
  - read
  - edit
  - env
  - fetch
permissions:
  - shell
  - file_read
  - file_write
  - env
  - network
---

# Book-to-Skill Converter

Transform written knowledge (books, manuals, academic papers, documentation) into actionable agent skills by extracting structure rather than producing passive summaries.

## Core Philosophy

- **Extract Structure, Not Summaries**: Capture named frameworks, decision rules, step-by-step techniques, and anti-patterns that agents can execute repeatedly.
- **Preserve Author Precision**: Retain exact terminology, mental models, and formulations.
- **Progressive Disclosure**: Keep root instructions concise, organizing depth into modular reference files across chapters, glossary, patterns, and cheatsheets.

---

## Modes of Operation

1. **Full Conversion (Default)**: Complete end-to-end extraction and generation of skill files.
2. **Analyze Only**: Extract source text, analyze key frameworks, and produce an inspection report without generating skill files.
3. **Generate from Prior Analysis**: Build structured skill files from an approved analysis report.
4. **Update / Fold-in**: Incrementally add chapters, errata, or companion volumes to an existing skill. See [update_foldin.md](references/update_foldin.md).

---

## Execution Workflow

### Step 0: Input Validation and Destination Scope
- Identify target document paths (.pdf, .epub, .docx, .html, .md, .txt, .rtf).
- Resolve destination root: defaults to personal cross-agent root.
- For detailed host discovery roots, consult [cross_agent_compatibility.md](references/cross_agent_compatibility.md).

### Step 1: Content Type Calibration
Classify source type to select the optimal extractor:
- **Technical**: Rich in code blocks, formulas, tables, architecture diagrams. Uses structure-aware parsing.
- **Text-heavy**: Narrative, business, or prose. Uses fast text extraction.

### Step 2: Document Extraction
Execute the bundled extraction script from the skill root:
```bash
python3 scripts/extract.py "<source-path>"
```
The extractor outputs:
- Extracted corpus text in a temporary working directory.
- Extracted structural metadata with token counts, chapter counts, and document structure.

### Step 3: Structural Inspection
- Inspect the initial 8,000 characters and table of contents.
- Identify the author's voice, key frameworks, and central thesis.
- Determine chapter boundaries and section splits.

### Step 4: Skill Scaffolding
Create the target skill directory hierarchy under the chosen destination directory:
- Root instructions file
- chapters directory
- references directory
- glossary index
- patterns catalog
- cheatsheet reference

### Step 5: Chapter & Artifact Generation
- Generate individual modular chapters under the chapters directory following the structured specification.
- Follow the templates and guidelines in [chapter_templates.md](references/chapter_templates.md).
- Compile the glossary index (alphabetical index of frameworks and concepts).
- Compile the patterns catalog (actionable patterns catalog).
- Compile the cheatsheet reference (high-density decision tables and matrices).

### Step 6: Security Verification
Run the bundled security scanner on the newly generated skill:
```bash
python3 tools/scan_generated_skill.py "$SKILLS_HOME/<skill-name>"
```
Ensure no prompt injections, unauthorized instructions, or unpinned dependencies exist before activation.

### Step 7: Host Registration & Discovery
Register the skill with local agents:
- Cross-agent hosts (Copilot, Amp, OpenCode) discover skills natively.
- For host-specific configuration and Claude Code linking, consult [cross_agent_compatibility.md](references/cross_agent_compatibility.md).

---

## References

- [Chapter & Artifact Templates](references/chapter_templates.md)
- [Cross-Agent Compatibility & Discovery](references/cross_agent_compatibility.md)
- [Update and Fold-in Workflow](references/update_foldin.md)
