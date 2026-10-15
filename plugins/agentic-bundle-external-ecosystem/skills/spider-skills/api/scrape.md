---
name: spider-api-scrape
description: Scrape a single page using the spider.cloud API
triggers:
  - url_contains: "api.spider.cloud/scrape"
priority: 3
---

# Spider API — Scrape

**POST** `https://api.spider.cloud/scrape`

Scrape a single page for targeted data extraction. Does NOT follow links.

AI-guided scrape prompts use **POST** `https://api.spider.cloud/ai/scrape` and require an AI subscription plan: <https://spider.cloud/ai/pricing>

## Authentication

```
Authorization: Bearer $SPIDER_API_KEY
Content-Type: application/json
```


Full parameter matrix: `skills/api/parameters.md`

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to scrape |

## Common Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `request` | string | `"smart"` | `"http"`, `"chrome"`, or `"smart"` |
| `return_format` | string | | `"markdown"`, `"text"`, `"raw"`, `"html2text"`, `"xml"`, `"bytes"` |
| `metadata` | boolean | false | Include page metadata |
| `readability` | boolean | false | Apply readability preprocessing |
| `proxy_enabled` | boolean | false | Premium proxy routing |
| `stealth` | boolean | | Headless stealth mode for bot-protected pages |

## Screenshot Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `full_page` | boolean | true | Capture full-page screenshot |
| `binary` | boolean | false | Return as binary instead of base64 |
| `omit_background` | boolean | false | Transparent background |
| `block_images` | boolean | false | Block images for faster rendering |
| `cdp_params` | object | | Chrome DevTools Protocol: `{clip, format, quality}` |

## Example

```json
{
  "url": "https://example.com/page",
  "return_format": "markdown",
  "metadata": true,
  "css_extraction_map": {
    "title": "h1",
    "price": ".product-price",
    "description": ".product-desc"
  }
}
```

## Bot-protected pages

For pages that block ordinary requests, set `stealth` and turn on premium proxies:

```json
{
  "url": "https://protected-site.com",
  "return_format": "markdown",
  "stealth": true,
  "proxy_enabled": true
}
```
