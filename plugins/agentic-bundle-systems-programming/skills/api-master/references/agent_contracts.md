# Task + Playbook Execution Contracts & FSM Specification

## 1. TaskPlaybookContract Schema

Every delegated task adheres to this deterministic JSON contract:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TaskPlaybookContract",
  "type": "object",
  "required": ["task_id", "assigned_agent", "scope", "functional_invariants", "playbook"],
  "properties": {
    "task_id": {
      "type": "string",
      "pattern": "^SLICE-[A-Z0-9_-]+$"
    },
    "assigned_agent": {
      "type": "string",
      "enum": [
        "rest-openapi-architect",
        "graphql-schema-architect",
        "grpc-async-engineer",
        "api-security-auditor",
        "verifier-qa"
      ]
    },
    "scope": {
      "type": "object",
      "required": ["files_target"],
      "properties": {
        "files_target": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 1,
          "maxItems": 10
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
      "required": ["verification_commands"],
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

## 2. Finite State Machine (FSM) Lifecycle Transitions

```
┌──────────────┐
│  DISPATCHED  │
└──────┬───────┘
       │ trigger_run()
       ▼
┌──────────────┐
│   RUNNING    │◄─────────────────────────────┐
└──────┬───────┘                              │
       │ trigger_verification()               │
       ▼                                      │
┌──────────────┐   Failed & attempts < max    │
│  VERIFYING   ├──────────────────────────────┘
└──────┬───┬───┘
       │   │
       │   │ All gates passed
       │   ▼
       │ ┌──────────────┐
       │ │  COMPLETED   │
       │ └──────────────┘
       │
       │ Failed & attempts >= max
       ▼
┌──────────────────────┐
│ FAILED_HEALING_LOOP  │
└──────────────────────┘
```

### Transition Invariants:
1. `DISPATCHED -> RUNNING`: Worker loads contract and starts slice code or spec generation.
2. `RUNNING -> VERIFYING`: Worker submits artifact to Verifier QA.
3. `VERIFYING -> COMPLETED`: All verification commands exit with 0 code and zero violations.
4. `VERIFYING -> RUNNING`: Gate failure matches a known pattern; self-healing loop consumes 1 retry credit and prescribes remediation recipe.
5. `VERIFYING -> FAILED_HEALING_LOOP`: Self-healing budget (default 3 retries) exhausted without resolving violations; unconditional veto exercised.
