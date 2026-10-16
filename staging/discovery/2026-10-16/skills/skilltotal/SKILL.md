---
name: skilltotal
description: "Claude Code plugin that scans a package before the agent runs npx, npm install, pip install, uvx or claude mcp add. Malicious indicators block the install. High-risk packages need your approval. The scan runs on your machine and never executes the code or calls an LLM. Every finding cites a file and line. Also a CLI, GitHub Action and MCP server."
license: Apache-2.0
risk: safe
source: community
date_added: '2026-10-16'
allowed-tools:
  - Read
  - Grep
  - Bash
metadata:
  repository: "https://github.com/pezhik/skilltotal"
  stars: 13
  score: 3/5
---

# skilltotal

Candidate agent skill discovered on GitHub from [pezhik/skilltotal](https://github.com/pezhik/skilltotal).

## Overview
Claude Code plugin that scans a package before the agent runs npx, npm install, pip install, uvx or claude mcp add. Malicious indicators block the install. High-risk packages need your approval. The scan runs on your machine and never executes the code or calls an LLM. Every finding cites a file and line. Also a CLI, GitHub Action and MCP server.

## Instructions & Usage
Refer to upstream repository documentation: [https://github.com/pezhik/skilltotal](https://github.com/pezhik/skilltotal)

## Limitations
- Staged candidate awaiting monthly repository maintenance triage and verification.
