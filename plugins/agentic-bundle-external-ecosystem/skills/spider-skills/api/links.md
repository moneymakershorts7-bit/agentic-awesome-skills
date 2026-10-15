---
name: spider-api-links
description: Extract links from a page using the spider.cloud API
triggers:
  - url_contains: "api.spider.cloud/links"
priority: 3
---

# Spider API — Links

**POST** `https://api.spider.cloud/links`

Extract all discoverable links from target page(s). Returns URLs without fetching their content. Supports streaming.

AI link extraction prompts use **POST** `https://api.spider.cloud/ai/links` and require an AI subscription plan: <https://spider.cloud/ai/pricing>

## Authentication

```
Authorization: Bearer $SPIDER_API_KEY
Content-Type: application/json
```


Full parameter matrix: `skills/api/parameters.md`

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to extract links from |

## Optional Parameters

Supports general page-loading parameters: `request`, `proxy`, `viewport`, `headers`, `cookies`, `user_agent`, `wait_for`, `stealth`, etc.

## Example

```json
{
  "url": "https://example.com",
  "request": "smart"
}
```
