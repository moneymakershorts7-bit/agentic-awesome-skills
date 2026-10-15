---
name: spider-api-transform
description: Transform HTML content between formats using the spider.cloud API
triggers:
  - url_contains: "api.spider.cloud/transform"
priority: 3
---

# Spider API — Transform

**POST** `https://api.spider.cloud/transform`

Convert raw HTML or content between formats without re-fetching from the web. Useful for post-processing previously collected data.

## Authentication

```
Authorization: Bearer $SPIDER_API_KEY
Content-Type: application/json
```


Full parameter matrix: `skills/api/parameters.md`

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | Resource[] | Array of resources: `{html?, content?, url?, lang?}` |

## Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `return_format` | string | | `"markdown"`, `"commonmark"`, `"text"`, `"html2text"`, `"raw"`, `"xml"`, `"bytes"` |
| `readability` | boolean | false | Apply readability preprocessing |
| `clean` | boolean | false | Clean markdown/text for AI |
| `clean_full` | boolean | false | Advanced cleaning (removes nav/footer) |

## Example

```json
{
  "data": [
    {
      "html": "<html><body><h1>Hello</h1><p>World</p></body></html>",
      "url": "https://example.com"
    }
  ],
  "return_format": "markdown",
  "readability": true
}
```
