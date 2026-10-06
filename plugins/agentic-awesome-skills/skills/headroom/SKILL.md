---
name: headroom
description: Context compression layer and memory proxy for AI agents. Compresses tool outputs, logs, RAG chunks, and history locally with token savings and CCR caching.
category: agentic
risk: safe
source: community
source_repo: headroomlabs-ai/headroom
source_type: community
date_added: "2026-10-06"
author: headroomlabs-ai
tags: [headroom, context-compression, token-savings, agent-proxy, memory, llm-optimization, ccr]
tools: [Bash, Read, Write]
---

# Headroom: Local Context Compression & Agent Memory Proxy

## Overview

Headroom compresses everything an AI agent reads — tool outputs, build logs, RAG chunks, large files, and conversation history — locally on the machine before forwarding to the model. It provides zero-data-leakage compression, reversible original caching (CCR), and cross-agent memory sync across Claude Code, Cursor, Codex, OpenHands, and Gemini.

## When to Use

- When tool outputs, log dumps, stack traces, or command responses exceed context limits.
- Wrapping agent CLIs (`claude`, `cursor`, `opencode`, `aider`, `goose`) for transparent token savings.
- Running as a local proxy (`headroom proxy --port 8787`) for unified multi-agent context compression.
- Mining failed sessions and auto-generating rules with `headroom learn`.
- Querying and retrieving original uncompressed tool output fragments via CCR keys.

---

## Core Capabilities & Usage

### 1. Agent CLI Wrapping & Unwrapping

Headroom intercepts standard agent harnesses transparently:

```bash
# Wrap agent CLI
headroom wrap claude
headroom wrap cursor
headroom wrap opencode

# Check active compression status and cumulative savings
headroom status

# Unwrap and restore original configuration
headroom unwrap claude
```

### 2. Standalone Proxy Mode

Run Headroom as a local forward-proxy:

```bash
# Start local compression proxy
headroom proxy --port 8787 --backend https://api.openai.com/v1

# In your agent / SDK configuration:
export OPENAI_BASE_URL="http://127.0.0.1:8787/v1"
export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"
```

### 3. TypeScript & Python SDK Integration

```ts
import { compress, HeadroomClient } from 'headroom-ai'

const client = new HeadroomClient()

// Compress message array before sending to LLM
const compressedMessages = await client.compress(messages, {
  ratio: 0.4, // Target 40% size reduction
  preserveFatal: true,
  cacheOriginals: true
})
```

```python
from headroom_ai import Headroom

hr = Headroom()
compressed_text = hr.compress_text(
    large_log_output,
    preserve_patterns=[r"ERROR", r"FATAL", r"Exception"]
)
```

### 4. Cross-Agent Session Learning (`headroom learn`)

Extract recurring corrections and learnings from completed sessions:

```bash
# Mine recent session logs for failure patterns and save rule distillations
headroom learn --target AGENTS.md --auto-prune
```

---

For complete CLI flags, CCR cache retrieval patterns, and benchmark results, see [cli-reference.md](references/cli-reference.md).
