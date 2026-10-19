# Task + Playbook Execution Contracts & State Machine Specification

## 1. TaskPlaybookContract JSON Schema
Every slice of work delegated to a specialized Kotlin enterprise worker must serialize into a deterministic JSON contract:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "TaskPlaybookContract",
  "type": "object",
  "required": [
    "task_id",
    "assigned_agent",
    "scope",
    "functional_invariants",
    "playbook"
  ],
  "properties": {
    "task_id": {
      "type": "string",
      "pattern": "^[A-Z0-9_-]+$"
    },
    "assigned_agent": {
      "type": "string",
      "enum": [
        "coroutine-concurrency-architect",
        "domain-type-architect",
        "server-perf-systems-engineer",
        "security-sandbox-auditor",
        "verifier-qa"
      ]
    },
    "scope": {
      "type": "object",
      "properties": {
        "files_target": {
          "type": "array",
          "items": { "type": "string" }
        },
        "interfaces": {
          "type": "array",
          "items": { "type": "string" }
        }
      },
      "required": ["files_target", "interfaces"]
    },
    "functional_invariants": {
      "type": "array",
      "items": { "type": "string" }
    },
    "playbook": {
      "type": "object",
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
      },
      "required": ["verification_commands", "known_failure_modes"]
    }
  }
}
```

## 2. State Machine Transitions
The execution lifecycle follows a strict Finite State Machine:

```
[ DISPATCHED ]
      │
      ▼
  [ RUNNING ] ──────────┐ (Worker Error)
      │                 ▼
      │           [ FAILED_HEALING_LOOP ]
      ▼                 ▲
 [ VERIFYING ] ─────────┘ (Verifier Veto)
      │
      ▼ (All Gates PASS)
[ COMPLETED ]
```

- **DISPATCHED**: Initial state. Task contract parsed, assigned worker validated.
- **RUNNING**: Worker actively applies code changes or audits target files.
- **VERIFYING**: Adversarial Verifier QA evaluates K2 strictness, Konsist layer boundaries, Detekt/ktlint, and mutation score.
- **FAILED_HEALING_LOOP**: If any gate fails or vetoes, the FSM transitions to healing. Known failure modes in the playbook are matched and diagnostic recipes applied up to `maxHealingAttempts` (default: 3).
- **COMPLETED**: Final state achieved only when 100% of adversarial verification gates pass without veto.
