---
name: spider-cli-extraction
description: Use Spider Rust CLI for crawling, scraping, and extraction tasks from the terminal. Trigger this skill when a user asks to run or compose `spider` CLI commands, tune crawl/scrape options, export links or HTML, or control runtime browser mode with `--headless` or `--http`.
---

# Spider CLI Extraction

## Overview

Use this skill to run Spider CLI workflows with explicit runtime mode control.

Canonical source for cross-agent behavior: `skills/core/spider-cli-extraction.md`

Load `references/cli-workflows.md` when you need exact command patterns or mode-selection rules.

## Workflow

1. Confirm CLI availability.
- Prefer `cargo run -p spider_cli -- ...` from the Spider repo root.
- If `spider` is globally installed, use `spider ...` for quick checks.

2. Choose the task mode.
- Use `crawl` to collect links.
- Use `scrape` to emit per-page JSON records and optionally include HTML.
- Use `download` to persist page markup to disk.

3. Select runtime execution mode.
- Use `--headless` for browser-rendered mode.
- Use `--http` to force HTTP-only mode.
- Omit both for default HTTP behavior.

4. Add scope controls.
- Set `--limit`, `--depth`, `--budget`, and `--blacklist-url`.
- Add `--respect-robots-txt` when policy compliance is required.

## Quick Commands

```bash
# Crawl links (default HTTP mode)
cargo run -p spider_cli -- --url https://example.com crawl --output-links

# Browser mode on demand
cargo run -p spider_cli -- --url https://example.com --headless crawl --output-links

# Scrape with HTML output
cargo run -p spider_cli -- --url https://example.com scrape --output-html
```

## Script

Use `scripts/spider_cli_helper.sh` for wrappers:

```bash
./scripts/spider_cli_helper.sh verify-headless
./scripts/spider_cli_helper.sh crawl https://example.com --limit 20 --depth 2
./scripts/spider_cli_helper.sh scrape https://example.com --output-html --output-links
```
