# Spider CLI Extraction (Core Skill Spec)

## Purpose

Provide consistent, tool-agnostic guidance for using Spider OSS CLI for crawling, scraping, and extraction workflows.

## Trigger Conditions

Use this skill when users ask to:
- run or compose `spider` CLI commands,
- tune crawl/scrape behavior,
- export links/HTML,
- control runtime browser mode.

## Canonical Runtime Mode Rules

- Default mode: HTTP (no browser rendering).
- Browser mode: add `--headless`.
- Force HTTP mode explicitly: add `--http`.

## Canonical Commands

```bash
# Crawl links (default HTTP mode)
cargo run -p spider_cli -- --url https://example.com crawl --output-links

# Browser mode on demand
cargo run -p spider_cli -- --url https://example.com --headless crawl --output-links

# Scrape with HTML output
cargo run -p spider_cli -- --url https://example.com scrape --output-html
```

## Guardrails

- Apply `--limit`, `--depth`, `--budget`, and `--blacklist-url` when scanning unknown domains.
- Use `--respect-robots-txt` where policy compliance is required.
- Treat `--headless`/`--http` as runtime switches; do not model them as separate binaries.

## Platform Adapters

- Codex adapter: `skills/codex/spider-cli-extraction/`
- Claude adapter: `skills/claude/spider-cli-extraction.md`
