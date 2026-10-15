---
name: trends
description: "Real-time Google Trends and social media trending topic discovery across Google Search, X/Twitter, and viral platforms with zero API key dependencies."
allowed-tools:
  - run_command
  - view_file
  - write_to_file
permissions:
  - network
---

# Multi-Platform Trends Skill (`trends`)

The `trends` skill provides real-time access to trending search terms, viral hashtags, and public interest spikes across Google Trends, X (Twitter), and social networks. It serves as the primary radar for viral video scripting, clipping candidate selection, SEO optimization, and breaking news tracking.

---

## 🚀 Quick Start & CLI Invocation

The skill includes a zero-dependency Python CLI engine located in `scripts/trends_scout.py`.

### 1. Fetch Multi-Platform Trends (Google + X/Twitter)
```bash
python3 scripts/trends_scout.py --country us --limit 10
```

### 2. Fetch Pure JSON (for Agent Pipelines & Ingestion)
```bash
python3 scripts/trends_scout.py --country us --limit 15 --json
```

### 3. Filter by Platform
```bash
# Google Trends only
python3 scripts/trends_scout.py --platform google --country es

# Twitter / X trending hashtags only
python3 scripts/trends_scout.py --platform twitter --country mx
```

### Supported Country Codes
`us` (United States), `es` (Spain), `mx` (Mexico), `ar` (Argentina), `co` (Colombia), `cl` (Chile), `gb` / `uk` (United Kingdom), `ca` (Canada), `br` (Brazil), `de` (Germany), `fr` (France), `it` (Italy).

---

## 🛠️ Architecture & Integration Methods

### Method 1: Autonomous Agent Skill (Recommended & Active)
Whenever an agent prompt inquires about:
- *"What is trending right now?"*
- *"Find trending topics for a video about [topic]"*
- *"What are the current viral hashtags in [country]?"*

The agent executes `python3 scripts/trends_scout.py --country <country> --json` and ingests the top items directly into the scriptwriting or clipping pipeline.

### Method 2: MCP (Model Context Protocol) Remote Server
If exposing Google Trends and social analytics via an external MCP bridge (such as Composio or an HTTP/SSE server):

1. Open your MCP configuration file (`mcp_config.json`).
2. Add the provider under `mcpServers`:
   ```json
   {
     "mcpServers": {
       "google-trends-provider": {
         "serverUrl": "https://mcp.composio.dev/google-trends",
         "headers": {
           "Authorization": "Bearer YOUR_API_KEY"
         }
       }
     }
   }
   ```
3. Refresh MCP servers in the agent panel or restart the session.

---

## 🎬 Integration with Clipping & Virality Pipelines

To connect live trends to video clipping and content generation:
1. **Radar Hook**: Identifies top trending terms (e.g., `#LoveIsBlind` or `NBA Playoffs`).
2. **Virality Scoring**: Evaluates high-arousal emotional triggers (STEPPS framework) and curiosity gap strength.
3. **Clip Selection**: Matches long-form video transcripts or live podcasts against trending entities to automatically extract and publish timely clips within the 2-to-6 hour news cycle peak.

See [platform_apis.md](references/platform_apis.md) for endpoint details and API fallback behaviors.
