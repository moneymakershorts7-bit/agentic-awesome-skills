---
name: one-skill-to-rule-them-all
description: Meta-skill and continuous friction observer that detects workflow patterns, user corrections, and tool gaps to distill reusable agent skills autonomously.
category: agentic
risk: safe
source: community
source_repo: rebelytics/one-skill-to-rule-them-all
source_type: community
date_added: "2026-10-06"
author: rebelytics
tags: [meta-skill, task-observer, skill-improvement, continuous-learning, friction-log, agentic, orchestration]
tools: [Bash, Read, Write]
---

# Task Observer: One Skill to Rule Them All

## Overview

Skills improve best from friction noticed during real work. The Task Observer monitors multi-step executions, tool errors, retries, and user corrections, logging observations into a structured backlog (`[workspace]/skill-observations/observation-log/`) to iteratively create, refine, and maintain high-grade agent skills.

## When to Use
- During complex, multi-step tasks to detect repetitive workflow friction or manual tool interventions.
- When the user corrects an agent approach or provides specific workflow instructions worth persisting.
- Conducting weekly or milestone skill reviews to synthesize new domain skills from logged observations.
- Meta-orchestration and continuous agent capability improvement.

---

## Observation Workflow

### 1. Friction Detection Triggers

Log an observation when encountering:
- **Correction**: User corrects tool arguments, file paths, or reasoning steps.
- **Trial & Error**: Multiple failed bash attempts or API retries before finding the working pattern.
- **Missing Knowledge**: Information lookup that took multiple searches or documentation crawling.
- **Repetitive Boilerplate**: Writing the same scaffolding code or config across sessions.

### 2. Logging an Observation

Observations are written as YAML-frontmatter Markdown files in `[workspace]/skill-observations/observation-log/`:

```markdown
---
id: OBS-20261006-01
skill_candidate: fast-csv-parser
signal: tool-failure-loop
trigger_phrase: "parse large CSV without loading into memory"
severity: high
date: 2026-10-06
---

## Summary
Agent struggled to query a 500MB CSV with python script in memory.

## Resolved Pattern
Used `duckdb` CLI or `csvkit` stream processing instead.

## Proposed Skill Action
Create a `csv-analytics` skill using DuckDB stream execution.
```

### 3. Progressive Disclosure References

- [environments.md](references/environments.md) — Workspace anchoring across Claude Code, Cowork, Cursor, and OpenHands.
- [observation-log.md](references/observation-log.md) — Backlog schema, lifecycle states, and archive paths.
- [skill-authoring.md](references/skill-authoring.md) — Converting validated observations into production skills.
- [weekly-review.md](references/weekly-review.md) — Triage process for distilling candidate skills.

## Limitations
- Use this skill only when the task clearly matches the scope described above.
- Do not treat the output as a substitute for environment-specific validation, testing, or expert review.
- Stop and ask for clarification if required inputs, permissions, safety boundaries, or success criteria are missing.
