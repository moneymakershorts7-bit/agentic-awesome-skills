---
name: cost-guardian
description: Real-time LLM token cost tracking, daily budget enforcement, and SQLite usage analytics for AI agent coding sessions and model API calls.
category: devops
risk: safe
source: community
source_repo: bifrost-mcp/cost-guardian
source_type: community
date_added: "2026-10-06"
author: bifrost-mcp
tags: [cost-tracking, token-monitoring, budget-guard, sqlite, claude-code, observability, tokens]
tools: [Bash, Read, Write]
---

# Cost Guardian: Real-time Token Cost Tracking & Budget Enforcement

## Overview

Cost Guardian monitors and enforces token budgets for AI agent sessions in real time. It calculates exact USD costs across input tokens, output tokens, cache creation, and prompt cache reads (Opus, Sonnet, Haiku, Gemini, GPT-4o), stores telemetry in a local SQLite database (`~/.cost-guardian/usage.db`), and provides warnings at 80% and safety blocks at 95% budget utilization.

## When to Use
- Tracking API spending and token consumption across active coding sessions.
- Generating daily, weekly, or model-specific usage reports with SQL breakdown.
- Setting hard or soft budget limits on automated agent loops to prevent runaway spend.
- Investigating the most expensive sessions, prompt cache hit rates, or token anomalies.

---

## Core Usage & Queries

### 1. Generating Cost Analysis Report

Query the local Cost Guardian database via `sqlite3`:

```bash
sqlite3 ~/.cost-guardian/usage.db "
SELECT 
  session_id,
  model,
  sum(input_tokens) as total_input,
  sum(output_tokens) as total_output,
  sum(cache_read_tokens) as cache_hits,
  printf('$%.4f', sum(cost_usd)) as session_cost,
  datetime(min(created_at), 'unixepoch') as started_at
FROM api_calls
GROUP BY session_id
ORDER BY sum(cost_usd) DESC
LIMIT 5;
"
```

### 2. Today's Spend & Model Breakdown

```bash
sqlite3 ~/.cost-guardian/usage.db "
SELECT 
  model,
  count(*) as api_calls,
  sum(input_tokens + output_tokens) as total_tokens,
  printf('$%.2f', sum(cost_usd)) as total_cost
FROM api_calls
WHERE date(created_at, 'unixepoch') = date('now')
GROUP BY model;
"
```

### 3. Hook Configuration (`~/.claude/settings.json` or Agent Harness)

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": ".*",
        "hooks": [{ "type": "command", "command": "node ~/.cost-guardian/lib/hooks/session-start.js" }]
      }
    ],
    "PostToolExecution": [
      {
        "matcher": ".*",
        "hooks": [{ "type": "command", "command": "node ~/.cost-guardian/lib/hooks/post-tool.js" }]
      }
    ]
  }
}
```

### 4. Configuration & Budget Thresholds (`~/.cost-guardian/config.json`)

```json
{
  "daily_budget_usd": 25.0,
  "session_budget_usd": 5.0,
  "warning_threshold_pct": 80,
  "block_threshold_pct": 95,
  "currency": "USD"
}
```

## Limitations
- Use this skill only when the task clearly matches the scope described above.
- Do not treat the output as a substitute for environment-specific validation, testing, or expert review.
- Stop and ask for clarification if required inputs, permissions, safety boundaries, or success criteria are missing.
