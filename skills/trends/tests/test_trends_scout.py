#!/usr/bin/env python3
"""
Unit tests for TrendsScout
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add scripts directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from trends_scout import TrendsScout, COUNTRY_GEO_MAP

MOCK_GOOGLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss xmlns:ht="https://trends.google.com/trending/rss" version="2.0">
  <channel>
    <title>Daily Search Trends</title>
    <item>
      <title>SpaceX Starship</title>
      <ht:approx_traffic>100,000+</ht:approx_traffic>
      <pubDate>Thu, 15 Oct 2026 00:00:00 +0000</pubDate>
      <ht:news_item>
        <ht:news_item_title>SpaceX Starship Completes Orbital Flight</ht:news_item_title>
        <ht:news_item_url>https://example.com/spacex</ht:news_item_url>
        <ht:news_item_source>Tech News</ht:news_item_source>
      </ht:news_item>
    </item>
  </channel>
</rss>
"""

MOCK_TWITTER_HTML = """
<!DOCTYPE html>
<html>
<body>
  <div class="trend-card">
    <a href="/united-states/trend/%23Starship/">#Starship</a>
    <span class="desc">150K Tweets</span>
  </div>
  <div class="trend-card">
    <a href="/united-states/trend/%23AIRevolution/">#AIRevolution</a>
    <span class="desc">85.4K Tweets</span>
  </div>
</body>
</html>
"""

class TestTrendsScout(unittest.TestCase):
    def setUp(self):
        self.scout = TrendsScout(timeout=5)

    def test_country_mapping(self):
        self.assertIn("us", COUNTRY_GEO_MAP)
        self.assertEqual(COUNTRY_GEO_MAP["us"]["code"], "US")
        self.assertEqual(COUNTRY_GEO_MAP["es"]["code"], "ES")
        self.assertEqual(COUNTRY_GEO_MAP["mx"]["slug"], "mexico")

    @patch.object(TrendsScout, "_fetch_url")
    def test_fetch_google_trends(self, mock_fetch):
        mock_fetch.return_value = MOCK_GOOGLE_RSS
        trends = self.scout.fetch_google_trends("us", limit=5)
        self.assertEqual(len(trends), 1)
        item = trends[0]
        self.assertEqual(item["platform"], "Google Trends")
        self.assertEqual(item["topic"], "SpaceX Starship")
        self.assertEqual(item["traffic"], "100,000+")
        self.assertEqual(len(item["related_news"]), 1)
        self.assertEqual(item["related_news"][0]["source"], "Tech News")

    @patch.object(TrendsScout, "_fetch_url")
    def test_fetch_twitter_trends(self, mock_fetch):
        mock_fetch.return_value = MOCK_TWITTER_HTML
        trends = self.scout.fetch_twitter_trends("us", limit=5)
        self.assertEqual(len(trends), 2)
        self.assertEqual(trends[0]["hashtag_or_topic"], "#Starship")
        self.assertEqual(trends[0]["volume"], "150K Tweets")
        self.assertEqual(trends[1]["hashtag_or_topic"], "#AIRevolution")
        self.assertEqual(trends[1]["volume"], "85.4K Tweets")

    @patch.object(TrendsScout, "_fetch_url")
    def test_fetch_all(self, mock_fetch):
        mock_fetch.side_effect = [MOCK_GOOGLE_RSS, MOCK_TWITTER_HTML]
        report = self.scout.fetch_all("us", limit=5)
        self.assertEqual(report["country"], "United States")
        self.assertEqual(len(report["google_trends"]), 1)
        self.assertEqual(len(report["twitter_trends"]), 2)

if __name__ == "__main__":
    unittest.main()
