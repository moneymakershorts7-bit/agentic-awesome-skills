---
name: awesome-tools-scout
description: 'Autonomous zero-token scout for GitHub Awesome Topics (topic:awesome). Matches 100% Free & Open-Source tools to active project stacks and proposes integrations via Google Jules.'
category: devops-cloud
risk: safe
source: community
date_added: '2026-10-08'
license: MIT
compatibility: Linux / POSIX environment, Python 3.11+, gh CLI, Google Jules CLI
allowed-tools:
  - Read
  - Grep
  - Bash
metadata:
  tags: Awesome, FOSS, Project Matching, Jules, Zero-Token, Free Tools
  category: devops-cloud
---

# awesome-tools-scout

Autonomous, zero-token scout for [`https://github.com/topics/awesome`](https://github.com/topics/awesome) and curated `awesome-*` lists. Matches verified 100% Free & Open-Source (FOSS) developer tools, libraries, and CLI utilities directly to active project stacks in agent memory.

## Core Capabilities

1. **Zero-Token Cost:** Runs via local Python heuristics, `gh` CLI, GitHub Actions, or asynchronous Google Jules workers. Consumes 0 chat/LLM tokens.
2. **Project-Aware Relevance:** Dynamically extracts project keywords and architectures from [`~/.agents/memory/semantic/projects.md`](file:///home/npirela/.agents/memory/semantic/projects.md) and maps discovered tools to matching repositories.
3. **Strict 100% Free / FOSS Policy:** Enforces verified permissive/copyleft licenses (MIT, Apache-2.0, BSD, GPL, AGPL, CC0, Self-Hosted) and filters out paid-only, subscription-gated, or proprietary commercial products.
4. **Google Jules & GitHub Actions Integration:** Generates daily discovery dossiers and can dispatch background Pull Requests with zero human friction.

## Quick CLI Usage

```bash
# Recommend free tools for a specific active project
skills-maintainer awesome recommend agentic-awesome-skills
skills-maintainer awesome recommend obsidian-skills
skills-maintainer awesome recommend audiobook-tts

# Search topic:awesome for specific technology
skills-maintainer awesome search "postgres vector"
skills-maintainer awesome search "markdown canvas"

# Run full project scout and save proposal dossier
skills-maintainer awesome

# Dispatch autonomous discovery and PR task to Google Jules Cloud
skills-maintainer jules awesome
```

Direct standalone CLI shortcut:
```bash
awesome-scout --recommend presentation-publishing
awesome-scout --search "static analysis"
awesome-scout --dry-run
```

## Proposal Dossiers & Storage

- Daily Proposal Dossiers: [`docs/awesome-proposals/YYYY-MM-DD.md`](file:///home/npirela/agentic-awesome-skills/docs/awesome-proposals/)
- Cumulative Ledger: [`docs/awesome-proposals/LEDGER.md`](file:///home/npirela/agentic-awesome-skills/docs/awesome-proposals/LEDGER.md)
- JSON Proposal Database: [`data/awesome-proposals/proposals-YYYY-MM-DD.json`](file:///home/npirela/agentic-awesome-skills/data/awesome-proposals/)

## When to Use

- Discovering free, high-quality open-source alternatives to proprietary tools for an active project.
- Expanding project toolsets without spending LLM tokens.
- Running autonomous daily or scheduled scouting sweeps via Google Jules.

## Limitations

- Evaluates public GitHub repositories listed under `topic:awesome` or curated awesome registries.
- Requires network connectivity or `gh` token for API searches.
- Candidate tools must still undergo local security scanning (`vet-tool audit <url>` or `SkillSpector`) before production integration.
