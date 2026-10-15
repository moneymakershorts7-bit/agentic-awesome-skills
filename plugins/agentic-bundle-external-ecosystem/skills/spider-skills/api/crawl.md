---
name: spider-api-crawl
description: Crawl websites using the spider.cloud API
triggers:
  - url_contains: "api.spider.cloud/crawl"
priority: 3
---

# Spider API — Crawl

**POST** `https://api.spider.cloud/crawl`

Crawl a website and collect pages. Follows links across the site up to configured depth and limit.

AI-guided crawl prompts use **POST** `https://api.spider.cloud/ai/crawl` and require an AI subscription plan: <https://spider.cloud/ai/pricing>

## Authentication

```
Authorization: Bearer $SPIDER_API_KEY
Content-Type: application/json
```


Full parameter matrix: `skills/api/parameters.md`

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URI to crawl (comma-separated for multiple) |

## Common Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | number | 0 (all) | Max pages per site |
| `depth` | number | 25 | Max crawl depth |
| `request` | string | `"smart"` | `"http"`, `"chrome"`, or `"smart"` |
| `return_format` | string | | `"markdown"`, `"text"`, `"raw"`, `"html2text"`, `"xml"`, `"bytes"`, `"empty"` |
| `metadata` | boolean | false | Include page title, description, keywords |
| `readability` | boolean | false | Apply readability preprocessing |
| `cache` | boolean/object | false | Enable HTTP caching |
| `proxy_enabled` | boolean | false | Enable premium proxy (1.5x cost) |
| `proxy` | string | | Pool: `"residential"`, `"mobile"`, `"isp"` |

## Filtering & Scope

| Parameter | Type | Description |
|-----------|------|-------------|
| `subdomains` | boolean | Include subdomains |
| `tld` | boolean | Include TLD variants |
| `external_domains` | string[] | Domains as same origin (`"*"` for all) |
| `blacklist` | string[] | Regex patterns for excluded URL paths |
| `whitelist` | string[] | Regex patterns for included URL paths |
| `budget` | object | Path-based page limits: `{"/docs/": 100}` |
| `sitemap` | boolean | Include sitemap results |

## Content Processing

| Parameter | Type | Description |
|-----------|------|-------------|
| `css_extraction_map` | object | CSS/XPath selectors for structured scraping |
| `root_selector` | string | CSS selector for content root |
| `exclude_selector` | string | CSS selector for exclusion |
| `filter_main_only` | boolean | Exclude nav/footer/aside (default: true) |
| `clean_html` | boolean | Strip unwanted attributes |
| `chunking_alg` | object | Segment: `"ByWords"`, `"ByLines"`, `"ByCharacterLength"`, `"BySentence"` |

## Browser Control

| Parameter | Type | Description |
|-----------|------|-------------|
| `viewport` | object | `{width, height}` |
| `wait_for` | object | `{idle_network, selector, dom, delay, page_navigations}` |
| `scroll` | number | Infinite scroll duration (ms) |
| `stealth` | boolean | Headless stealth mode (default: true) |
| `fingerprint` | boolean | Fingerprint evasion (default: true) |
| `automation_scripts` | object | Custom browser automation |

## Example

```json
{
  "url": "https://example.com",
  "limit": 25,
  "return_format": "markdown",
  "metadata": true,
  "request": "smart"
}
```
