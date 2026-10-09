# Spider CLI Workflows

## Repository and Binary

- Repo path: your local `spider` checkout
- Package: `spider_cli`
- Binary name: `spider`

Preferred invocation during development:

```bash
cargo run -p spider_cli -- <ARGS>
```

## Core Commands

```bash
# Crawl links
cargo run -p spider_cli -- --url https://example.com crawl --output-links

# Scrape pages (JSON per page)
cargo run -p spider_cli -- --url https://example.com scrape --output-links

# Scrape and include HTML
cargo run -p spider_cli -- --url https://example.com scrape --output-html

# Download HTML files
cargo run -p spider_cli -- --url https://example.com download --target-destination ./_temp_spider_downloads
```

## Useful Global Options

- `--limit <N>`: max pages
- `--depth <N>`: depth limit
- `--budget "*,100,/blog/,10"`: path budgets
- `--blacklist-url "..."`: skip URLs
- `--respect-robots-txt`: robots policy
- `--full-resources`: include CSS/JS/resources
- `--proxy-url <URL>`: proxy route
- `--accept-invalid-certs`: allow invalid certs

## Runtime Mode Control

Observed behavior in this repo:

- CLI exposes runtime mode switches:
  - `--headless`: browser rendering mode
  - `--http`: force HTTP-only mode
- Default behavior is HTTP mode when neither flag is passed.

Verification commands:

```bash
# Check runtime flags
cargo run -p spider_cli -- --help

# Browser mode crawl
cargo run -p spider_cli -- --url https://example.com --headless crawl --output-links

# Explicit HTTP mode crawl
cargo run -p spider_cli -- --url https://example.com --http crawl --output-links
```

## Output Handling

- Stream scrape output to a file:

```bash
cargo run -p spider_cli -- --url https://example.com scrape --output-html > scrape.jsonl
```

- Stream crawl links to a file:

```bash
cargo run -p spider_cli -- --url https://example.com crawl --output-links > links.txt
```
