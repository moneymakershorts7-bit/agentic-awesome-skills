---
name: spider-api-screenshot
description: Capture website screenshots using the spider.cloud API
triggers:
  - url_contains: "api.spider.cloud/screenshot"
priority: 3
---

# Spider API — Screenshot

**POST** `https://api.spider.cloud/screenshot`

Capture a visual screenshot of a webpage. Returns base64-encoded or binary image data.

## Authentication

```
Authorization: Bearer $SPIDER_API_KEY
Content-Type: application/json
```


Full parameter matrix: `skills/api/parameters.md`

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | Target URL to screenshot |

## Screenshot Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `full_page` | boolean | true | Capture full-page screenshot |
| `omit_background` | boolean | false | Transparent background |
| `block_images` | boolean | false | Block images for faster rendering |
| `binary` | boolean | false | Return as binary instead of base64 |
| `cdp_params` | object | | `{clip, format, quality}` |
| `viewport` | object | | `{width, height}` |

## Example

```json
{
  "url": "https://example.com",
  "full_page": true,
  "viewport": {"width": 1440, "height": 900}
}
```
