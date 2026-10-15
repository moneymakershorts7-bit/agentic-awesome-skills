# Platform Trends APIs & Scraping Architecture

This document details the technical endpoints, data structures, and scraping mechanics used by the `trends` skill and fallback integrations.

---

## 1. Google Trends (Official RSS Feed)

### Endpoint
```http
GET https://trends.google.com/trending/rss?geo={GEO_CODE}
```

### Properties
- **Authentication**: None required (Zero API Key / Public XML RSS 2.0).
- **Latency**: ~150ms - 400ms.
- **Refresh Frequency**: Continuously updated throughout the day.
- **Payload Schema**:
  - `channel/item/title`: The exact query phrase trending in search.
  - `channel/item/ht:approx_traffic`: Estimated search volume (e.g. `50,000+`, `100,000+`).
  - `channel/item/pubDate`: RFC 822 publication date.
  - `channel/item/ht:news_item`: Array of top news articles matching the trend:
    - `ht:news_item_title`: Headline.
    - `ht:news_item_url`: Source URL.
    - `ht:news_item_source`: Publisher name (e.g., ESPN, BBC, Reuters).

### Python Request Pattern
```python
import urllib.request
import xml.etree.ElementTree as ET

url = "https://trends.google.com/trending/rss?geo=US"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 ..."})
with urllib.request.urlopen(req, timeout=10) as resp:
    tree = ET.fromstring(resp.read())
```

---

## 2. X / Twitter Trends (Real-Time Hashtags)

### Scraper Provider: `getdaytrends.com`
Official Twitter/X API v2 requires a $100+/mo Basic or Pro tier to access trends. `trends_scout.py` utilizes the public aggregator `getdaytrends.com/{country_slug}/` for zero-cost, real-time hashtag tracking.

### Extracted Data Points
- **Rank**: 1 through 50.
- **Hashtag/Topic**: e.g., `#LoveIsBlind`, `ChampionsLeague`.
- **Volume**: Formatted tweet count (e.g., `42.5K Tweets`, `110K Tweets`).

---

## 3. TikTok & Meta Trends Integration (Future MCP Fallbacks)

### TikTok Creative Center
- **Endpoint**: `https://ads.tiktok.com/business/creativecenter/inspiration/popular/hashtag/pc/en`
- **Authentication**: Requires session token (`msToken` / cookies) when queried directly.
- **Alternative**: Use Apify Actor `clockworks/free-tiktok-scraper` or Composio TikTok tool if deep demographic audience data is required.

### Meta / Instagram Graph API
- **Endpoint**: `https://graph.facebook.com/v19.0/ig_hashtag_search?q={query}&access_token={token}`
- **Requirement**: Requires Meta Developer App credentials and Instagram Business account connection.
