---
name: skill-seekers
description: Automatically detect source types and build AI skills from documentation websites, GitHub repositories, PDFs, or local codebases using Skill Seekers CLI and MCP.
allowed-tools:
  - bash
  - read_file
  - write_to_file
risk: safe
source: community
date_added: "2026-10-03"
---

# Skill Seekers

Convert documentation websites, GitHub repositories, PDFs, and local codebases into production-ready AI agent skills with conflict detection, structural enhancement, and multiple packaging formats.

## When to Use This Skill

Use this skill when the user:
- Wants to create an AI skill from a documentation site, GitHub repo, PDF, video, or codebase.
- Needs to convert documentation into clean Markdown suitable for LLM context.
- Wants to update or sync existing skills with their upstream documentation.
- Needs to export skills to vector databases (Weaviate, Chroma, FAISS, Qdrant).
- Asks to scrape, convert, validate, or package skills for Claude, Codex, Cursor, or Antigravity.

## Source Type Detection

Automatically detect the source type from user input:

| Input Pattern | Source Type | CLI Command / Tool |
|---|---|---|
| `https://...` (not GitHub/YouTube) | Documentation Site | `skill-seekers-create --url <url>` / `scrape_docs` |
| `owner/repo` or `github.com/...` | GitHub Repository | `skill-seekers-create --github <repo>` / `scrape_github` |
| `*.pdf` | PDF Document | `skill-seekers-create --pdf <file>` / `scrape_pdf` |
| YouTube/Vimeo URL or video file | Video Transcript | `scrape_video` |
| Local directory path | Codebase / Local Source | `skill-seekers-create --codebase <path>` / `scrape_codebase` |
| `*.ipynb`, `*.html`, OpenAPI `*.yaml` | Generic Structured Docs | `scrape_generic` |

## Core Workflows

### 1. Diagnose Environment
Verify installed parsers, dependencies, and execution mode:
```bash
skill-seekers-doctor
```

### 2. Create Skill from Source
```bash
# From documentation website
skill-seekers create --url https://docs.example.com --name example-skill

# From GitHub repository
skill-seekers create --github owner/repo --name repo-skill

# From local codebase
skill-seekers create --codebase ./my-project --name codebase-skill
```

### 3. Estimate Scope Before Scraping
```bash
skill-seekers-estimate --url https://docs.example.com
```

### 4. Enhance and Package
```bash
# Enhance extracted content with structure and examples
skill-seekers-enhance --skill-dir ./output/example-skill

# Package for target agent framework
skill-seekers-package --skill-dir ./output/example-skill --format markdown
```

## Available MCP Tools

When connected via MCP (`Skill_Seekers` server):
- `generate_config` / `list_configs` / `validate_config`: Scraping configuration management.
- `scrape_docs`, `scrape_github`, `scrape_pdf`, `scrape_video`, `scrape_codebase`: Multi-source ingest.
- `enhance_skill`, `package_skill`, `upload_skill`, `install_skill`: Post-processing and packaging.
- `detect_patterns`, `extract_test_examples`, `build_how_to_guides`: Test-driven knowledge extraction.
- `export_to_weaviate`, `export_to_chroma`, `export_to_faiss`, `export_to_qdrant`: Vector database sync.

## Limitations

- Heavy single-page JavaScript applications (SPAs) without static HTML rendering may require headless browser extraction fallback.
- Large documentation sites with >1,000 pages require bounded depth or path filtering to prevent rate limits.
- Video transcription extraction requires local audio dependencies or external transcription API keys.
- Scraping authenticated private repositories requires `GITHUB_TOKEN` configured in the environment.
