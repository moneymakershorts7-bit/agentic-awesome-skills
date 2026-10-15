---
name: claude-code-guidance-cherny
description: Boris Cherny's design principles and best practices for using Claude
  Code effectively, CLAUDE.md architecture, and agentic tool ergonomics.
author: jona
source: community
source_repo: jona/ycombinator-skills
license: MIT
category: startup-strategy
tags:
- claude-code
- agentic-coding
- best-practices
- claude-md
- developer-productivity
allowed-tools:
- view_file
- read_file
- run_command
risk: safe
---
# Claude Code Best Practices

Guidance for using Claude Code effectively and understanding its design philosophy, based on insights from Boris Cherny, the creator of Claude Code.

## Core Philosophy

### Build for T+6 Months

Design and configure for the model six months from now, not today's limitations:

- Avoid over-engineering workarounds for current model weaknesses
- Expect model improvements to obsolete most scaffolding code
- Treat compensatory instructions in CLAUDE.md as temporary

### Blatant Demand Principle

Only optimize behaviors users already perform:

- Observe what you do manually and repeatedly
- Make existing workflows easier, don't invent new ones
- If you're not already doing something manually, Claude Code won't magically make you do it

### Scaffolding is Tech Debt

All code and configuration compensating for model limitations is temporary:

- Expect to delete or rewrite within 6 months
- Don't over-invest in workarounds
- Model improvements typically provide 10-20% gains that obsolete previous scaffolding

## CLAUDE.md Configuration

### Keep It Minimal

```markdown
# Project: [Name]

## Extended Knowledge & Deep-Dive Guide

For full operational workflows, step-by-step evaluation matrices, analytical templates, and extended source materials:
- Consult [references/deep-dive.md](references/deep-dive.md)
