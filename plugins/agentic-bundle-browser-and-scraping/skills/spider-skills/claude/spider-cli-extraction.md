---
name: spider-cli-extraction
summary: Spider OSS CLI crawl/scrape workflows with runtime mode control.
---

Reference core spec: `../core/spider-cli-extraction.md`

## Claude Usage Notes

- Use the core spec as source of truth.
- Prefer exact commands from core spec when generating shell steps.
- Respect runtime mode model:
  - default HTTP
  - `--headless` enables browser rendering
  - `--http` explicitly forces HTTP

## Quick Commands

```bash
cargo run -p spider_cli -- --url https://example.com crawl --output-links
cargo run -p spider_cli -- --url https://example.com --headless crawl --output-links
cargo run -p spider_cli -- --url https://example.com scrape --output-html
```
