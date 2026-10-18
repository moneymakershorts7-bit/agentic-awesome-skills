# Task + Playbook Execution Contracts & State Machine Specification

## 1. Architectural Philosophy: The Contract as Operational Grounding
In high-assurance low-level engineering, natural language specifications result in semantic ambiguity, instruction drift, and silent ABI violations. The `asm-master` platform enforces a deterministic JSON contract schema for every work slice dispatched by the Lead Orchestrator to any of the 4 specialized workers or the adversarial verification agent.

## 2. Complete Contract JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TaskPlaybookContract",
  "type": "object",
  "required": ["task_id", "assigned_agent", "scope", "functional_invariants", "playbook"],
  "properties": {
    "task_id": {
      "type": "string",
      "pattern": "^SLICE-[0-9]{3}-[A-Z0-9_-]+$"
    },
    "assigned_agent": {
      "type": "string",
      "enum": [
        "abi-register-architect",
        "simd-perf-optimizer",
        "systems-lowlevel-engineer",
        "security-crypto-auditor",
        "verifier-qa"
      ]
    },
    "scope": {
      "type": "object",
      "required": ["files_target", "interfaces"],
      "properties": {
        "files_target": {
          "type": "array",
          "items": { "type": "string" }
        },
        "interfaces": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "functional_invariants": {
      "type": "array",
      "items": { "type": "string" }
    },
    "playbook": {
      "type": "object",
      "required": ["verification_commands", "known_failure_modes"],
      "properties": {
        "verification_commands": {
          "type": "array",
          "items": { "type": "string" }
        },
        "known_failure_modes": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["pattern", "diagnostic_recipe"],
            "properties": {
              "pattern": { "type": "string" },
              "diagnostic_recipe": { "type": "string" }
            }
          }
        }
      }
    }
  }
}
```

## 3. Finite State Machine (FSM) Transitions

```
┌──────────────┐
│  DISPATCHED  │
└──────┬───────┘
       │ [Contract Accepted]
       ▼
┌──────────────┐
│   RUNNING    │◄────────────────────────┐
└──────┬───────┘                         │
       │ [Verification Invocation]       │ [Self-Healing Retry]
       ▼                                 │ (iterations < max)
┌──────────────┐                         │
│  VERIFYING   │                         │
└──────┬───────┘                         │
       │                                 │
       ├──► [All Invariants Pass] ──► ┌──┴──────────┐
       │                              │  COMPLETED  │
       │                              └─────────────┘
       ▼ [Any Check Fails]
┌───────────────────────────┐
│   FAILED_HEALING_LOOP     ├────────────┘
└───────────────────────────┘
```

1. **DISPATCHED (0)**: Work slice defined and assigned to a domain agent.
2. **RUNNING (1)**: Domain agent implements or refactors the assembly routines.
3. **VERIFYING (2)**: Independent adversarial verification executes test commands.
4. **COMPLETED (3)**: Invariants verified 100% bitwise and mechanically sound.
5. **FAILED_HEALING_LOOP (4)**: Failure output diagnosed against recipes; state transitions back to `RUNNING` until pass or budget exhausted.
