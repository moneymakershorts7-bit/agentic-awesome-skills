---
name: fable-orchestration
description: How to prompt Claude Fable / top frontier models so they ORCHESTRATE a build correctly and cheaply — planning and delegating while subagents do the token-heavy execution. Covers advisor mode, architect-and-delegate, effort-level routing as the cost lever, parallel subagents, verification loops, and failure mode mitigation.
allowed-tools:
  - run_command
  - view_file
  - write_to_file
---

# Fable Orchestration: Architecture & Subagent Delegation

Fable / Master Planner = architect only (~5–15% of the work: high-level structure + ambiguous judgment). **Subagents do everything else** — research, execution, verification.

The loop: **Subagent researches → Architect designs → Subagent executes → Verification loop tests.**

---

## 1. Wiring Patterns

- **Advisor Mode:** Primary agent writes everything; Master Architect steers when the builder is stuck or encounters ambiguity. One clean session.
- **Architect + Delegate:** Architect writes the phased plan with strict invariants, then parallel subagents execute each task slice.

---

## 2. Effort & Token Density Controls

- **Cost Lever:** Match effort to task difficulty (low/medium for routine tasks, high for complex refactors).
- **Cap at High:** Avoid excessive reasoning loops on trivial mechanical edits; rely on deterministic tool-first gates.

---

## 3. Subagent Execution Guardrails

1. **Law of Bounded Functional Slicing:** Partition large objectives into decoupled, self-contained functional parts.
2. **Task + Playbook Contract:**
   - **The Task:** Scope, inputs, functional invariants, and acceptance criteria.
   - **The Playbook:** Step-by-step verification commands, expected failure modes, and corrective runbooks.
3. **Continuous Incremental Testing:** Test each component before proceeding to the next.
