---
name: spider-api-parameters
description: Full shared parameter reference for spider.cloud API route skills
triggers:
  - url_contains: "api.spider.cloud"
priority: 2
---

# Spider API — Full Parameters Reference

Use this reference for full parameter coverage across API route skills.

## Base Route Inheritance

These routes use base request parameters from `RequestParams` and route-specific additions:

- `/crawl`
- `/scrape`
- `/links`
- `/search` (uses `SearchRequestParams` + base)
- `/screenshot` (uses `ScreenshotRequestParams` + base)
- `/transform`

## Common Base Parameters (High-Use)

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL |
| `request` | string | `http`, `chrome`, or `smart` |
| `return_format` | string/array | Output format selection |
| `limit` | integer | Max pages (crawl-like routes) |
| `depth` | integer | Max crawl depth |
| `budget` | object | Path-level page limits |
| `readability` | boolean | Readability preprocessing |
| `metadata` | boolean | Include metadata |
| `proxy_enabled` | boolean | Enable premium proxy mode |
| `proxy` | string | Proxy pool selection |
| `cookies` | string | Cookie header string |
| `headers` | object | HTTP headers |
| `viewport` | object | Browser viewport |
| `wait_for` | object | Page wait controls |
| `subdomains` | boolean | Include subdomains |
| `tld` | boolean | Include TLD variants |
| `blacklist` | string[] | Excluded URL path patterns |
| `whitelist` | string[] | Included URL path patterns |
| `full_resources` | boolean | Include non-HTML assets |
| `respect_robots` | boolean | Respect robots policy |
| `concurrency_limit` | integer | Concurrency cap |
| `delay` | integer | Delay between crawls (ms) |

## Route-Specific Notes

- `/search`: adds `search`, `search_limit`, `fetch_page_content`, `country`, `location`, `language`, `num`, `page`
- `/screenshot`: adds `binary`, `full_page`, `block_images`, `omit_background`, `cdp_params`
- `/transform`: uses `data` payload for input conversion

## AI Routes (/ai/*)

AI routes require subscription: <https://spider.cloud/ai/pricing>

Exact AI routes:

- `/ai/crawl`
- `/ai/scrape`
- `/ai/search`
- `/ai/browser`
- `/ai/links`

AI routes inherit base route params and add only:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `prompt` | string | Yes | Natural-language extraction/action instructions |
| `extraction_schema` | object | No | Structured output schema for typed extraction |
| `cleaning_intent` | string | No | `extraction`, `action`, or `general` |
