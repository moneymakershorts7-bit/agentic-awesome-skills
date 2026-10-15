---
name: superbrain-recall
description: "Search and recall from the user's SuperBrain local Obsidian memory vault. Uses wikilinks, gap sensing, and project-scoped note retrieval before answering from scratch."
category: memory
risk: safe
source: community
source_repo: "m3talux/superbrain"
license: "MIT"
tags: [memory, superbrain, obsidian, second-brain, recall, wikilinks]
---

# SuperBrain Recall

Use this skill whenever the user references past work, prior decisions, "how did we do X", "did we already solve Y", earlier sessions, or a project's history — before answering from scratch.

## 1. Vault Retrieval

Search the user's local SuperBrain Obsidian vault at `~/.agents/memory/`:

1. **Locate matching notes:**
   - Search across `preferences.md`, `system.md`, `projects.md`, `decisions.md`, `lessons.md`, `daily/`, and `sessions/`.
   - Use direct file lookup or grepping for key terms.
   - When the MCP memory server is enabled, query the knowledge graph using `search_nodes` or `open_nodes`.

2. **Ground in Vault Evidence:**
   - Lead with what the vault records.
   - Cite every factual claim using standard Obsidian wikilinks: `[[decisions]]`, `[[lessons]]`, `[[projects/<project-slug>]]`, `[[daily/<date>]]`.
   - If results are empty or irrelevant, state so plainly and proceed without memory — never fabricate a citation or invent a note.

## 2. Gap Sensing — Detecting Stale Memory

Recalled memory can lag reality (e.g., git commits landed outside the agent session, or a session was terminated abruptly). Before answering questions about recent project state:

1. **Check Git Activity:**
   Compare the latest memory timestamp with recent git commits:
   ```bash
   git log -n 5 --oneline
   ```
2. **Identify Gaps:**
   If git history shows commits newer than the latest recorded memory for this project, treat current repository source code and git log as ground truth.
3. **Flight Recorder Check:**
   Inspect `~/.agents/memory/sessions/` and `~/.agents/memory/daily/` for the latest session digest and turn log.
4. **Transparent Attribution:**
   State clearly which parts of your answer come from distilled memory versus recent git/runtime inspection.
