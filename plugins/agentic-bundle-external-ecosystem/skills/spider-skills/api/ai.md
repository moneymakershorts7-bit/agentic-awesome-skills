---
name: spider-api-ai
description: AI-powered endpoints on the spider.cloud API
triggers:
  - url_contains: "api.spider.cloud/ai"
priority: 3
---

# Spider API — AI Studio

AI-powered endpoints that accept natural language prompts. Requires a subscription — see [spider.cloud/ai/pricing](https://spider.cloud/ai/pricing) for plans.

## Authentication

```
Authorization: Bearer $SPIDER_API_KEY
Content-Type: application/json
```


Full parameter matrix: `skills/api/parameters.md`

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ai/crawl` | AI-powered crawling with natural language instructions |
| POST | `/ai/scrape` | AI-powered scraping |
| POST | `/ai/search` | AI-powered search |
| POST | `/ai/browser` | AI-powered browser automation |
| POST | `/ai/links` | AI-powered link extraction |

## Parameters

All AI endpoints inherit standard parameters from their non-AI counterparts:

- `/ai/crawl` inherits from `/crawl`
- `/ai/scrape` inherits from `/scrape`
- `/ai/search` inherits from `/search`
- `/ai/links` inherits from `/links`
- `/ai/browser` follows AI browser route semantics

AI-specific additions:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `prompt` | string | Yes | Natural language instructions for the AI |
| `extraction_schema` | object | No | JSON schema object for typed structured extraction output |
| `cleaning_intent` | string | No | HTML cleaning mode: `extraction`, `action`, or `general` |

## Example — AI Crawl

```json
{
  "url": "https://example.com",
  "prompt": "Extract all product names and prices from the catalog pages",
  "limit": 50,
  "return_format": "markdown"
}
```

## Example — AI Browser

```json
{
  "url": "https://example.com/login",
  "prompt": "Log in with the test credentials and navigate to the dashboard"
}
```
