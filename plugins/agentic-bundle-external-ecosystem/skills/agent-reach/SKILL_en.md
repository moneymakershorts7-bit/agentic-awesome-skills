---
name: agent-reach
description: Multi-platform internet research, search, and content retrieval across 16 platforms with intelligent multi-backend routing.
allowed-tools:
  - run_command
  - view_file
  - read_url_content
  - search_web
allowed-domains:
  - github.com
  - api.bilibili.com
  - bilibili.com
  - v2ex.com
  - r.jina.ai
  - exa.ai
  - xiaoyuzhoufm.com
  - api.groq.com
  - raw.githubusercontent.com
metadata:
  homepage: https://github.com/Panniantong/Agent-Reach
---

# Agent Reach — Internet Capability Router

Multi-platform internet research and retrieval across 16 platforms with automated backend routing.

## Routing Table

| Category | Platforms / Intent | Documentation |
| :--- | :--- | :--- |
| **search** | Web search / Code search (Exa, Google) | [references/search.md](references/search.md) |
| **social** | XiaoHongShu, Twitter/X, Bilibili, V2EX, Reddit, Facebook, Instagram | [references/social.md](references/social.md) |
| **career** | Job search / Candidate profiles (LinkedIn, Boss Zhipin) | [references/career.md](references/career.md) |
| **dev** | GitHub search, repository intelligence | [references/dev.md](references/dev.md) |
| **web** | Clean markdown article reading, RSS feeds | [references/web.md](references/web.md) |
| **video** | YouTube, Bilibili subtitles, Podcasts | [references/video.md](references/video.md) |
| **finance** | Xueqiu market quotes, stock discussions | [references/finance.md](references/finance.md) |

## Quick Commands (Zero Configuration)

```bash
# Exa AI Web Search
mcporter call exa.web_search_exa query="query" numResults=5

# Universal Web Article Reader
curl -s "https://r.jina.ai/https://example.com"

# GitHub Repo Search
gh search repos "query" --sort stars --limit 10

# YouTube Subtitle Extraction
yt-dlp --write-sub --write-auto-sub --skip-download -o "/tmp/%(id)s" "URL"

# V2EX Hot Topics
curl -s "https://www.v2ex.com/api/topics/hot.json" -H "User-Agent: agent-reach/1.0"

# Bilibili Video Search
bili search "query" --type video -n 5
```

## Platform Authentication Boundaries

- **Twitter/X**: Provide `TWITTER_AUTH_TOKEN` and `TWITTER_CT0` securely in process environment variables or via `agent-reach configure twitter-cookies`.
- **XiaoHongShu / Reddit / Meta**: Use existing user-controlled browser sessions or OpenCLI adapters. Do not automate login or bypass verification steps.
- **Boss Zhipin / LinkedIn**: When verification challenges or security checks appear on screen, prompt the user for interactive manual completion.

```bash
# Twitter Search
twitter search "query" -n 10

# Reddit Search via OpenCLI
opencli reddit search "query" -f yaml

# XiaoHongShu Search via OpenCLI
opencli xiaohongshu search "query" -f yaml
```

## System Health & Diagnostics

```bash
# Check platform channels and active backends
agent-reach doctor --json
```

## Workspace Guidelines

All temporary output files should be written to `/tmp/` and persistent configuration to `~/.agent-reach/`. Do not pollute project workspaces.
