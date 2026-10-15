#!/usr/bin/env python3
"""
Multi-Platform Trends Scout (Google Trends, X/Twitter, and Social Platforms)
Fetches real-time trending topics, search volumes, news headlines, and hashtags
without requiring paid API keys or OAuth subscriptions.
"""

import re
import sys
import json
import argparse
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

COUNTRY_GEO_MAP = {
    "us": {"code": "US", "name": "United States", "slug": "united-states"},
    "es": {"code": "ES", "name": "Spain", "slug": "spain"},
    "mx": {"code": "MX", "name": "Mexico", "slug": "mexico"},
    "ar": {"code": "AR", "name": "Argentina", "slug": "argentina"},
    "co": {"code": "CO", "name": "Colombia", "slug": "colombia"},
    "cl": {"code": "CL", "name": "Chile", "slug": "chile"},
    "gb": {"code": "GB", "name": "United Kingdom", "slug": "united-kingdom"},
    "uk": {"code": "GB", "name": "United Kingdom", "slug": "united-kingdom"},
    "ca": {"code": "CA", "name": "Canada", "slug": "canada"},
    "br": {"code": "BR", "name": "Brazil", "slug": "brazil"},
    "de": {"code": "DE", "name": "Germany", "slug": "germany"},
    "fr": {"code": "FR", "name": "France", "slug": "france"},
    "it": {"code": "IT", "name": "Italy", "slug": "italy"}
}

class TrendsScout:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _fetch_url(self, url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def fetch_google_trends(self, country: str = "us", limit: int = 15) -> List[Dict[str, Any]]:
        """Fetches daily search trends from official Google Trends RSS."""
        country_info = COUNTRY_GEO_MAP.get(country.lower(), COUNTRY_GEO_MAP["us"])
        geo_code = country_info["code"]
        url = f"https://trends.google.com/trending/rss?geo={geo_code}"

        results = []
        try:
            content = self._fetch_url(url)
            tree = ET.fromstring(content)
            items = tree.findall(".//item")

            ns = {"ht": "https://trends.google.com/trending/rss"}
            for item in items[:limit]:
                title_elem = item.find("title")
                traffic_elem = item.find("ht:approx_traffic", ns)
                pub_elem = item.find("pubDate")
                news_items = item.findall("ht:news_item", ns)

                title = title_elem.text.strip() if title_elem is not None and title_elem.text else "N/A"
                traffic = traffic_elem.text.strip() if traffic_elem is not None and traffic_elem.text else "N/A"
                pub_date = pub_elem.text.strip() if pub_elem is not None and pub_elem.text else ""

                articles = []
                for n in news_items[:3]:
                    nt = n.find("ht:news_item_title", ns)
                    nu = n.find("ht:news_item_url", ns)
                    nsource = n.find("ht:news_item_source", ns)
                    if nt is not None and nt.text:
                        articles.append({
                            "title": nt.text.replace("&apos;", "'").replace("&quot;", '"'),
                            "url": nu.text if nu is not None and nu.text else "",
                            "source": nsource.text if nsource is not None and nsource.text else ""
                        })

                results.append({
                    "platform": "Google Trends",
                    "topic": title,
                    "traffic": traffic,
                    "published_at": pub_date,
                    "related_news": articles
                })
        except Exception as e:
            results.append({
                "platform": "Google Trends",
                "error": f"Failed to fetch Google Trends for {geo_code}: {str(e)}"
            })
        return results

    def fetch_twitter_trends(self, country: str = "us", limit: int = 15) -> List[Dict[str, Any]]:
        """Fetches real-time X/Twitter trending hashtags and topics."""
        country_info = COUNTRY_GEO_MAP.get(country.lower(), COUNTRY_GEO_MAP["us"])
        country_slug = country_info["slug"]
        url = f"https://getdaytrends.com/{country_slug}/"

        results = []
        try:
            html = self._fetch_url(url)
            # Match trend links and volume snippets
            pattern = re.compile(
                r'<a href="[^"]*trend/[^"]*">([^<]+)</a>(?:[\s\S]*?<span class="desc">([^<]+)</span>)?',
                re.IGNORECASE
            )
            matches = pattern.findall(html)
            
            seen = set()
            rank = 1
            for match in matches:
                name, vol = match
                name = name.strip()
                vol = vol.strip() if vol else "Trending"
                if not name or name in seen:
                    continue
                seen.add(name)
                results.append({
                    "platform": "X / Twitter",
                    "rank": rank,
                    "hashtag_or_topic": name,
                    "volume": vol
                })
                rank += 1
                if len(results) >= limit:
                    break
        except Exception as e:
            results.append({
                "platform": "X / Twitter",
                "error": f"Failed to fetch Twitter trends for {country_slug}: {str(e)}"
            })
        return results

    def fetch_all(self, country: str = "us", limit: int = 10) -> Dict[str, Any]:
        """Fetches multi-platform trend report."""
        return {
            "country": COUNTRY_GEO_MAP.get(country.lower(), {"name": country.upper()})["name"],
            "google_trends": self.fetch_google_trends(country, limit),
            "twitter_trends": self.fetch_twitter_trends(country, limit)
        }

def format_terminal_report(report: Dict[str, Any]):
    print("=" * 70)
    print(f" 📈 MULTI-PLATFORM TRENDS REPORT: {report.get('country', 'GLOBAL').upper()}")
    print("=" * 70)
    
    # 1. Google Trends
    print("\n🔍 GOOGLE SEARCH TRENDS (Real-Time Search Volume):")
    g_trends = report.get("google_trends", [])
    if g_trends and "error" in g_trends[0]:
        print(f"   ⚠️ {g_trends[0]['error']}")
    else:
        for idx, item in enumerate(g_trends, 1):
            print(f"   {idx:2d}. {item['topic']} [{item['traffic']} searches]")
            for art in item.get("related_news", [])[:1]:
                print(f"       📰 {art['title']} ({art['source']})")

    # 2. X / Twitter Trends
    print("\n🐦 X / TWITTER TRENDS (Viral Conversations & Hashtags):")
    tw_trends = report.get("twitter_trends", [])
    if tw_trends and "error" in tw_trends[0]:
        print(f"   ⚠️ {tw_trends[0]['error']}")
    else:
        for item in tw_trends:
            print(f"   #{item['rank']:<2d} {item['hashtag_or_topic']:<30} ({item['volume']})")

    print("\n" + "=" * 70)

def main():
    parser = argparse.ArgumentParser(description="Multi-Platform Trends Scout CLI")
    parser.add_argument("--platform", choices=["google", "twitter", "x", "all"], default="all",
                        help="Target platform (google, twitter, all)")
    parser.add_argument("--country", type=str, default="us",
                        help="Country code (us, es, mx, ar, co, gb, etc.)")
    parser.add_argument("--limit", type=int, default=10,
                        help="Max number of trends to retrieve (default: 10)")
    parser.add_argument("--json", action="store_true",
                        help="Output pure JSON format")
    args = parser.parse_args()

    scout = TrendsScout()
    
    if args.platform == "google":
        data = {"country": args.country.upper(), "google_trends": scout.fetch_google_trends(args.country, args.limit)}
    elif args.platform in ("twitter", "x"):
        data = {"country": args.country.upper(), "twitter_trends": scout.fetch_twitter_trends(args.country, args.limit)}
    else:
        data = scout.fetch_all(args.country, args.limit)

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        format_terminal_report(data)

if __name__ == "__main__":
    main()
