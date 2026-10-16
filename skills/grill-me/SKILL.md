---
name: grill-me
description: Relentless interactive interview protocol to eradicate assumptions and guarantee 100% first-try success on vague, complex, or underspecified prompts. Use whenever P(first_try_success) < 100% or on any grill trigger phrase.
allowed-tools:
  - ask_question
  - read
  - bash
  - grep
  - glob
  - run_command
  - fetch
category: productivity
risk: safe
source: official
source_repo: vercel-labs/skills
author: Matt Pocock / CL4R1T4S
license: MIT
date_added: "2026-10-16"
tags:
  - productivity
  - interview
  - planning
  - alignment
  - zero-assumption
tools:
  - antigravity
  - claude-code
  - cursor
  - codex-cli
---

# 🥩 Grill-Me: The Zero-Assumption Alignment Protocol

A structured, relentless interview protocol designed to eliminate assumptions, clarify underspecified requirements, and guarantee **100% first-try success** before writing a single line of production code.

---

## ⚡ The 100% Certainty Axiom (Mandatory Rule)

> [!IMPORTANT]
> **The Non-Negotiable Operational Invariant:**
> Unless an incoming prompt has a **100% probability ($P_{\text{first-try}} = 1.0$) of being executed right on the first try with zero unstated assumptions**, the agent **MUST GRILL THE USER**.
>
> Writing speculative code, guessing architectural choices, or assuming unstated parameters is strictly prohibited.

### Probability Evaluation Gate:
Whenever receiving a prompt, evaluate:
$$\text{Grilling Required} \iff P(\text{success without questions}) < 1.0$$

Any of the following conditions automatically trigger an interactive grilling session:
1. **Underspecified Target:** Action verbs without exact file paths, modules, or code symbols.
2. **Qualitative Adjectives:** "Make it faster", "clean", "secure", "proper", "modern", "simple" without metric thresholds.
3. **Open Architecture:** Multiple valid technical stacks, library choices, or data schemas exist.
4. **Unstated Failure Modes:** Undefined behavior for edge cases, timeouts, or external service disconnects.
5. **Compound Directives:** More than two tasks combined without an explicit sequence or priority order.

---

## 🧠 The 4-Phase Interview Lifecycle

```
┌────────────────────────────────────────────────────────┐
│ Phase 1: Environment & Codebase Grounding (Silent)     │
│  • Inspect repo, files, AST, configs. NEVER ask facts   │
│    the agent can discover on disk.                     │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Phase 2: Design Tree Construction & Frontier Mapping   │
│  • Map choices as a tree: High-level -> Implementation │
│  • Extract the "Frontier" (unsettled prerequisites).   │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Phase 3: Interactive Interrogation Rounds              │
│  • Use ask_question modal or scannable markdown blocks.│
│  • Always provide (Recommended) answer as Option 1.    │
│  • Word questions so "Yes" accepts the recommended path│
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Phase 4: Plan Convergence & Execution Unlock           │
│  • Frontier is empty; P(first-try) = 1.0; proceed!     │
└────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tooling & The `grillme` CLI Analyzer

The skill includes a deterministic prompt analyzer CLI installed in `~/.local/bin/grillme` (`scripts/grill_analyzer.py`):

```bash
# Evaluate prompt certainty and display detected ambiguity
grillme "make the video pipeline better"

# Enforce in automated scripts (exits 1 if grilling required)
grillme "$USER_PROMPT" --enforce

# Generate machine-readable ask_question JSON payload
grillme "$USER_PROMPT" --json
```

---

## 🎯 Question Formatting Guidelines

### In Antigravity / Interactive Environments:
Invoke the native `ask_question` tool with structured multiple-choice questions:
- List the recommended answer first with prefix `(Recommended)`.
- Format options as the user's direct response.
- Do NOT add an "Other" option (provided automatically).
- Set `is_multi_select: false` unless explicitly allowing multi-factor selections.

### In Standard Text CLI / Claude Code:
Format rounds clearly using the Frontier format:

```markdown
❓ **Q1 - State Management**: Which state container pattern should we use?
• **(Recommended) Zustand store with selective hydration** (zero boilerplate, fits existing patterns)
• React Context with useReducer
• Jotai atomic primitives

➡️ *Reply "Yes" to accept recommended, or choose an alternative.*
```

---

## 📚 References & Deep Dives

- **Design Tree Patterns:** [references/decision_tree_patterns.md](references/decision_tree_patterns.md) — Standard decision trees for Features, Refactoring, and DevOps.
- **The Interview Rubric:** [references/interview_rubric.md](references/interview_rubric.md) — Core invariants for friction-free questioning.
