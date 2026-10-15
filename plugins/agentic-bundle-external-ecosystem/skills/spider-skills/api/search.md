---
name: spider-api-search
description: Search the web using the spider.cloud SERP API
triggers:
  - url_contains: "api.spider.cloud/search"
priority: 3
---

# Spider API — Search

**POST** `https://api.spider.cloud/search`

Real-time search engine results (SERP). Optionally fetch and crawl result pages. Supports up to 50,000 search requests per minute.

AI-enhanced search prompts use **POST** `https://api.spider.cloud/ai/search` and require an AI subscription plan: <https://spider.cloud/ai/pricing>

## Authentication

```
Authorization: Bearer $SPIDER_API_KEY
Content-Type: application/json
```


Full parameter matrix: `skills/api/parameters.md`

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | The search query |

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search_limit` | number | | Number of top results to return |
| `fetch_page_content` | boolean | false | Crawl each result page (additional cost) |
| `page` | number | 1 | Results page number |
| `country` | string | | Country code: `"us"`, `"fr"`, etc. |
| `location` | string | | Geographic location |
| `language` | string | | Language code preference |
| `num` | number | | Number of search results |

When `fetch_page_content` is true, standard crawl parameters (return_format, metadata, etc.) apply to fetched pages.

## Example — Search Only

```json
{
  "search": "web scraping best practices",
  "search_limit": 10
}
```

## Example — Search + Fetch Content

```json
{
  "search": "rust async programming",
  "search_limit": 5,
  "fetch_page_content": true,
  "return_format": "markdown"
}
```

## Response (Search Only)

```json
[
  {
    "title": "Page Title",
    "description": "Page description...",
    "url": "https://example.com"
  }
]
```
