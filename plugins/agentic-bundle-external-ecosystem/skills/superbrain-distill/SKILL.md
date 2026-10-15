---
name: superbrain-distill
description: "Distill active sessions, corrections, and pushback into structured Obsidian markdown notes following strict SuperBrain quality bars."
category: memory
risk: safe
source: community
source_repo: "m3talux/superbrain"
license: "MIT"
tags: [memory, superbrain, obsidian, second-brain, distill, journaling]
---

# SuperBrain Distill

Use this skill at checkpoints, milestone completions, or session end to distill raw interactions into structured Obsidian notes inside `~/.agents/memory/`.

## 1. Distillation Quality Bar

Only emit memory notes when content clears a concrete threshold. If a session is routine or low-signal, recording nothing is the correct outcome.

| Memory Type | Required Threshold | Target Destination |
| :--- | :--- | :--- |
| **decision** | Explicit trade-off chosen (Option A vs B) OR multi-step architectural plan with stated rationale. | `episodic/decisions.md` |
| **gotcha** | Bug reproduced AND diagnosed AND has a verified fix. | `episodic/lessons.md` |
| **lesson** | User pushback/correction that yields a durable generalizable rule. | `episodic/lessons.md` |
| **project_fact** | Durable architectural, stack, or scope statement. Status updates do not qualify. | `semantic/projects.md` or `projects/<slug>.md` |
| **preference** | Stored developer, tooling, or communication preference. | `semantic/preferences.md` |
| **daily_journal** | Incremental digest of completed tasks, routed notes, and open threads. | `daily/<YYYY-MM-DD>.md` |

## 2. Vault Formatting Standards

- **Wikilinks:** Interconnect notes using Obsidian wikilinks: `[[decisions]]`, `[[lessons]]`, `[[preferences]]`.
- **YAML Frontmatter:** Include `tags`, `date`, `project` and `type` metadata where applicable.
- **Append-or-Close:** Never overwrite existing past entries destructively; mark superseded records as `[closed YYYY-MM-DD, replaced by ...]`.
- **Zero Secrets:** Prohibido registrar credenciales, secretos sensibles o claves privadas en archivos de memoria.
