# Agent Contracts & Finite State Machine Specification

## 1. Task + Playbook Execution Contract Schema

Every task delegated to any worker within `javascript-master` adheres strictly to a deterministic JSON contract:

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
        "ecma-architect",
        "runtime-optimizer",
        "api-engineer",
        "security-auditor",
        "verifier-qa"
      ]
    },
    "status": {
      "type": "string",
      "enum": ["DISPATCHED", "RUNNING", "VERIFYING", "COMPLETED", "FAILED_HEALING_LOOP"],
      "default": "DISPATCHED"
    },
    "healing_iterations": {
      "type": "integer",
      "minimum": 0,
      "default": 0
    },
    "scope": {
      "type": "object",
      "required": ["files_target", "interfaces"],
      "properties": {
        "files_target": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 1
        },
        "interfaces": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "functional_invariants": {
      "type": "array",
      "items": { "type": "string" },
      "minItems": 1
    },
    "playbook": {
      "type": "object",
      "required": ["verification_commands", "known_failure_modes"],
      "properties": {
        "verification_commands": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 1
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

---

## 2. Finite State Machine (FSM) Transitions

The lifecycle of each contract follows a strictly deterministic state graph:

```
[DISPATCHED]
      │
      ▼
  [RUNNING] ◄──────────────────────────────────┐
      │                                        │
      ▼                                        │
 [VERIFYING]                                   │
      │                                        │
      ├──────────────────────┐                 │
      ▼                      ▼                 │
 [COMPLETED]       [FAILED_HEALING_LOOP] ──────┘
                     (if iterations < max)
```

### Transition Table

| From State | To State | Trigger Condition | Max Limit |
| :--- | :--- | :--- | :--- |
| `DISPATCHED` | `RUNNING` | Worker agent receives task and initiates execution | N/A |
| `RUNNING` | `VERIFYING` | Worker completes changes and hands off to verifier-qa | N/A |
| `VERIFYING` | `COMPLETED` | Adversarial verification gate reports `passed: true` | Terminal State |
| `VERIFYING` | `FAILED_HEALING_LOOP` | Any verification command or invariant fails | `iterations < 3` |
| `FAILED_HEALING_LOOP` | `RUNNING` | Diagnostic recipe applied; re-executing slice | Loop back |

---

## 3. Self-Healing Playbook Mechanics

When transitioning to `FAILED_HEALING_LOOP`:
1. The orchestrator captures `stderr` and test reporter logs.
2. It evaluates regex patterns defined in `playbook.known_failure_modes`.
3. Upon matching a pattern, it injects the `diagnostic_recipe` into the worker's working context.
4. The worker applies the prescribed corrective patch without modifying uncontracted files.
5. If `healing_iterations >= maxHealingIterations` (default: 3) and tests still fail, the orchestrator halts with an `AgentInvariantError` to prevent runaway hallucination loops.
