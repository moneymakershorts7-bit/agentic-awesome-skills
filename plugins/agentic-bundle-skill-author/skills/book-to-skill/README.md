# book-to-skill

Convert books and documents into structured, on-demand agent skills.

## Overview

`book-to-skill` extracts crystallized knowledge from documents (PDF, EPUB, DOCX, HTML, Markdown, plain text, RTF, MOBI/AZW) into actionable agent skills. Instead of generating passive summaries, it extracts named frameworks, mental models, actionable principles, and step-by-step techniques.

## Features

- **Structure over Summaries**: Captures executable models and principles.
- **Multi-Format Extraction**: Parses PDFs (text and technical), EPUBs, Word documents, HTML, and Markdown.
- **Progressive Disclosure**: Generates modular chapters, glossary, and cheatsheets to minimize LLM token overhead (24x–51x savings).
- **Cross-Agent Compatible**: Works across GitHub Copilot CLI, Claude Code, Amp, Hermes Agent, OpenCode, and OpenClaw.

## Installation & Usage

Run extraction directly:
```bash
python3 scripts/extract.py "<path-to-document>"
```

Or invoke via `book-to-skill` CLI:
```bash
book-to-skill "<path-to-document>"
```

## Security

Audited and verified with SkillSpector (Risk Score: 2/100, LOW).
Declared capabilities: `shell`, `file_read`, `file_write`, `env`, `network`.
Suppression baseline tracked in `.skillspector-baseline.json`.

## License

MIT
