# Task + Playbook Execution Contracts & FSM Specification

## 1. Architectural Philosophy
`swift-master` enforces bounded functional slicing. Monolithic pull requests and unverified multi-file commits are rejected. Every unit of work dispatched to any worker agent is governed by a deterministic JSON contract.

## 2. Contract JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TaskPlaybookContract",
  "type": "object",
  "required": ["task_id", "assigned_agent", "scope", "functional_invariants", "playbook"],
  "properties": {
    "task_id": {
      "type": "string",
      "description": "Unique deterministic identifier for the work slice (e.g., SLICE-001-ORDER-BOOK-ACTOR)"
    },
    "assigned_agent": {
      "type": "string",
      "enum": [
        "concurrency-actor-architect",
        "domain-type-architect",
        "systems-perf-engineer",
        "security-sandbox-auditor",
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

The contract lifecycle strictly traverses the following state transitions:

```
[ DISPATCHED ]
       │
       ▼
  [ RUNNING ] ◄─────────────────────────┐
       │                                │
       ▼                                │ Self-Healing Loop
 [ VERIFYING ] (Agent 5: VerifierQA)    │ (Max 3 iterations)
       │                                │
       ├──────────────► [ FAILED_HEALING_LOOP ]
       ▼
 [ COMPLETED ]
```

1. **`DISPATCHED`**: The orchestrator parses and validates contract invariants using `ContractValidator`.
2. **`RUNNING`**: The assigned worker implements or modifies the targeted files.
3. **`VERIFYING`**: The slice is passed to Agent 5 (`verifier-qa`). All verification commands in `playbook.verification_commands` are executed.
4. **`COMPLETED`**: Reached only when all gates return `PASS` (compiler warnings = 0, tests = 100% green, TSan data races = 0).
5. **`FAILED_HEALING_LOOP`**: Triggered if any command fails. The orchestrator scans the compiler/test output for matching patterns in `known_failure_modes`, extracts the diagnostic recipe, and transitions back to `RUNNING`. If max attempts (default 3) are exhausted, the task aborts with failure.
