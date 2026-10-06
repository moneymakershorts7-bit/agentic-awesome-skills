---
name: claude-mem
description: Persistent cross-session memory compression system for AI coding agents. Indexes past decisions, fixes, and architecture patterns with progressive retrieval.
category: agentic
risk: safe
source: community
source_repo: thedotmack/claude-mem
source_type: community
date_added: "2026-10-06"
author: thedotmack
tags: [memory, claude-mem, persistent-memory, cross-session, codebase-learning, episodic-memory, indexing]
tools: [Bash, Read, Write]
---

# Claude-Mem: Cross-Session Persistent Memory & Knowledge Graph

## Overview

Claude-Mem captures agent interactions, tool executions, bug resolutions, and codebase patterns into a compressed, persistent SQLite memory layer. It enables instant cross-session recall ("how did we fix auth last week?", "did we already solve this bug?") using a 3-tier progressive disclosure strategy (Index → Metadata → Full Payload) that saves ~90% tokens.

## When to Use

- Answering questions about historical decisions or previous coding sessions ("Did we already implement X?", "How did we resolve this error last time?").
- Indexing a new codebase architecture into persistent knowledge nodes (`learn-codebase`).
- Generating standup summaries or timeline reports across multi-day agent workflows.
- Managing persistent project context without manual copy-pasting across conversation resets.

---

## 3-Tier Progressive Retrieval Pattern

To prevent context window bloat, always follow the 3-step retrieval ladder:

```
Step 1: Search Index (~50 tokens/hit)
  └── mem_search(query="auth token refresh", limit=10)
        │
Step 2: Fetch Summary Metadata (~200 tokens/hit)
  └── mem_fetch(ids=[10942, 11131], detail="summary")
        │
Step 3: Deep Observation Extraction (Only if necessary)
  └── mem_inspect(id=11131, include_raw_diff=true)
```

---

## Core Operations

### 1. Memory Search

```bash
# Query persistent memory store
claude-mem search --query "database migration retry" --project "my-repo" --limit 5
```

### 2. Codebase Learning Pass

```bash
# Analyze repository architecture and record structural patterns
claude-mem learn --path . --depth 2 --tag "architecture"
```

### 3. Timeline & Standup Summary

```bash
# Summarize actions taken over the past 24 hours
claude-mem standup --since "yesterday"
```

---

For complete database schema, MCP server configuration, and vector similarity settings, see [architecture.md](references/architecture.md).
