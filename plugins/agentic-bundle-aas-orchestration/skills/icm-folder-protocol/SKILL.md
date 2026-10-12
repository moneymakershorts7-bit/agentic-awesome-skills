---
name: icm-folder-protocol
description: "Implement Interpretable Context Methodology (ICM / Folders-Over-Agents): architect AI agent workflows as deterministic numbered directory pipelines with clear stage contracts, markdown prompts, and human-in-the-loop checkpoints without framework bloat."
category: agent-orchestration
risk: safe
source: community
source_repo: JEVanClief/icm-protocol
source_type: community
date_added: "2026-10-12"
author: JEVanClief
tags: [agent-orchestration, icm, context-engineering, folder-structure, workflows, unix-philosophy]
tools: [claude, codex, antigravity]
license: "MIT"
---

# ICM Folder Protocol (Interpretable Context Methodology)

## Overview

The **Interpretable Context Methodology (ICM)** (also formulated as the *Model Workspace Protocol* by Jake Van Clief and David McDermott, arXiv:2603.16021) replaces fragile multi-agent code orchestration frameworks (LangChain, CrewAI, AutoGen) with a physical, inspectable **filesystem pipeline**.

Instead of complex Python/TypeScript state graphs, an ICM system models the workflow as:
1. **Ordered Directory Stages** (`01_discovery/`, `02_plan/`, `03_execute/`, `04_verify/`) that define process milestones.
2. **Explicit Stage Contracts** defining strictly what input files may be read and what exact artifact must be emitted.
3. **5-Layer Context Hierarchy** eliminating context bloat and hallucination by isolating reference data from active working memory.
4. **Unix Pipeline Simplicity**: Plain text and markdown act as the universal interface; a single agent moves sequentially through stages, pausing at checkpoints for human review.

---

## When to Use This Skill

- When designing multi-step agent tasks that fail due to context drift, runaway token budgets, or opaque multi-agent handoffs.
- When you need 100% transparent auditability: human users can inspect folder contents, tweak markdown rules on disk, and resume execution.
- When converting monolithic prompt loops into modular, multi-pass pipelines.
- Do NOT use for single-shot question-answering or micro-edits where filesystem orchestration is excessive overhead.

---

## The 5-Layer Context Architecture

```
Project Root /
├── 00_identity/              # Layer 1: Agent Role & Principles (CLAUDE.md / SYSTEM.md)
├── 01_routing/               # Layer 2: Lightweight Stage Map & Navigation Index
├── 02_stages/                # Layer 3: Ordered Functional Stages
│   ├── 01_discovery/         #   Stage Prompt + Input / Output Contracts
│   ├── 02_planning/          #   Intermediate artifact generation
│   ├── 03_implementation/    #   Code & asset modifications
│   └── 04_verification/      #   Linters, tests, and human sign-off
├── 03_artifacts/             # Layer 4: Active Working Artifacts (Output of each pass)
└── 04_references/            # Layer 5: Heavy Reference Material (Cold storage / read on demand)
```

| Layer | Name | Scope & Retention | Token Boundary |
|---|---|---|---|
| **L1** | **Identity** | Who the agent is, immutable invariants, coding standards | Injected in every session (~500 tokens) |
| **L2** | **Routing** | Directory tree, stage map, active pointer | Tiny navigational map (~200 tokens) |
| **L3** | **Stage Contract** | Exact criteria, permitted tools, input prerequisites, output schema | Injected only for active stage (~400 tokens) |
| **L4** | **Working Artifacts** | Current drafts, diffs, execution logs | Scoped to active step; passed to next step |
| **L5** | **References** | PDFs, docs, raw transcripts, research dossiers | Cold storage. Never auto-loaded into context |

---

## How It Works

### Step 1: Scaffold an ICM Workspace

Run the standard directory layout for a new complex project:

```bash
mkdir -p workspace/{01_research,02_spec,03_code,04_audit}
```

Create the stage contract `workspace/01_research/STAGE.md`:
```markdown
# Stage 01: Research & Discovery
- Inputs: `user_brief.md`
- Allowed Tools: `search_web`, `view_file`
- Prohibited Tools: `replace_file_content`, `write_to_file` outside `01_research/`
- Output Target: `01_research/dossier.md`
- Gate Criterion: Must contain 5 cited references and zero unverified claims.
```

### Step 2: Multi-Pass Compilation Execution

Execute each step sequentially:
1. **Pass 1 (Read & Synthesize)**: Agent enters `01_research/`, executes according to `STAGE.md`, produces `dossier.md`.
2. **Checkpoint**: Human or validation script verifies `01_research/dossier.md`.
3. **Pass 2 (Plan)**: Agent enters `02_spec/`, ingests only `01_research/dossier.md`, produces `spec.md`.
4. **Pass 3 (Execution)**: Slices code changes atomically based strictly on `02_spec/spec.md`.
5. **Pass 4 (Verification)**: Deterministic smoke tests, linters, and security scanners.

### Step 3: Layered Token Isolation

Never dump raw data into the LLM context. Reference files in `04_references/` remain on disk:
- When the agent needs details, it reads specific byte/line offsets (`view_file` with `StartLine`/`EndLine`).
- The agent summarizes observations into `03_artifacts/`, keeping the conversation transcript clean.

---

## Best Practices

- ✅ **Unix Philosophy**: Each stage does one thing well. The output of stage $N$ is the input of stage $N+1$.
- ✅ **Inspectable State**: Any team member can open the folder in VS Code, inspect intermediate outputs, and edit markdown directly without touching code frameworks.
- ✅ **Deterministic Scripts for Mechanical Tasks**: Use bash/python scripts for file movement, conversion, and validation; do not waste LLM reasoning on deterministic tasks.
- ❌ **No Opaque Memory Buffers**: Never hide conversation history or state inside vector databases when plain markdown files on disk suffice.
- ❌ **No Runaway Loops**: Always establish exit criteria in `STAGE.md`. If gate fails after 3 tries, pause for human review.

---

## Integration with Existing Skills

- Combine with `@jev-use`: Use Jev's fast classifier (`jev_judge`) at stage transitions to check if stage criteria are satisfied before opening the next stage.
- Combine with `@planning-with-files`: Persistent disk state acts as reproducible working memory.
