# Task + Playbook Execution Contracts & State Machine Specification

## 1. Overview
The Frontier Orchestrator-Worker Architecture enforces deterministic, verifiable delegation through structured JSON contracts. Every delegated work slice contains:
1. **The Task**: Bounded scope, explicit file targets, domain interfaces, and non-negotiable functional invariants.
2. **The Playbook (Self-Healing Runbook)**: Deterministic verification commands, anticipated failure patterns, and executable diagnostic recipes.

---

## 2. JSON Contract Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TaskPlaybookContract",
  "type": "object",
  "required": ["task_id", "assigned_agent", "scope", "functional_invariants", "playbook", "state"],
  "properties": {
    "task_id": {
      "type": "string",
      "description": "Unique identifier for the work slice (e.g. SLICE-001-PAYMENT-AGGREGATOR)"
    },
    "assigned_agent": {
      "type": "string",
      "enum": ["domain-architect", "runtime-optimizer", "api-engineer", "security-auditor", "verifier-qa"]
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
    },
    "state": {
      "type": "string",
      "enum": ["DISPATCHED", "RUNNING", "VERIFYING", "COMPLETED", "FAILED_HEALING_LOOP"]
    }
  }
}
```

---

## 3. Finite State Machine (FSM) Lifecycle

```
    ┌──────────────┐
    │  DISPATCHED  │ ◄── Orchestrator decomposes goal into atomic slice
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   RUNNING    │ ◄── Assigned worker executes code modification
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  VERIFYING   │ ◄── Verifier QA runs static analysis, AST lint, mutation gate
    └──────┬───────┘
           │
     ┌─────┴────────────────────────┐
     │                              │
[All Checks Pass]           [Failure Detected]
     │                              │
     ▼                              ▼
┌──────────────┐            ┌──────────────────────┐
│  COMPLETED   │            │ Match Failure Pattern│
└──────────────┘            └──────────┬───────────┘
                                       │
                         ┌─────────────┴─────────────┐
                         │                           │
                   [Recipe Found]           [Max Retries / Unknown]
                         │                           │
                         ▼                           ▼
                 ┌───────────────┐          ┌──────────────────────┐
                 │ Apply Healing │          │ FAILED_HEALING_LOOP  │
                 │ & Re-verify   │          └──────────────────────┘
                 └───────────────┘
```

---

## 4. Canonical Contract Examples

### Example 1: Domain Architect Contract
```json
{
  "task_id": "SLICE-001-PAYMENT-AGGREGATOR",
  "assigned_agent": "domain-architect",
  "scope": {
    "files_target": ["src/Domain/Payment/PaymentProcessor.php"],
    "interfaces": ["PaymentGatewayInterface", "TransactionRepositoryInterface"]
  },
  "functional_invariants": [
    "declare(strict_types=1) at the top of all files",
    "Readonly class with constructor property promotion and custom DNF types",
    "Zero float math for currency values; must use Money Value Object with integer cents"
  ],
  "playbook": {
    "verification_commands": [
      "./vendor/bin/pest tests/Unit/PaymentProcessorTest.php",
      "./vendor/bin/phpstan analyse -l max src/Domain/Payment",
      "./vendor/bin/infection --filter=src/Domain/Payment --min-msi=80"
    ],
    "known_failure_modes": [
      {
        "pattern": "PHPStan: Parameter #1 $amount of method expects int, float given",
        "diagnostic_recipe": "Refactor floating point math to Money Value Object backed by integer cents."
      },
      {
        "pattern": "Infection: Mutant Escaped in boundary comparison",
        "diagnostic_recipe": "Add explicit test case testing zero and negative balance edge cases."
      }
    ]
  },
  "state": "DISPATCHED"
}
```

### Example 2: Runtime Optimizer Contract
```json
{
  "task_id": "SLICE-002-WORKER-STREAMER",
  "assigned_agent": "runtime-optimizer",
  "scope": {
    "files_target": ["src/Infrastructure/Streaming/EventLogStreamer.php"],
    "interfaces": ["EventStreamInterface"]
  },
  "functional_invariants": [
    "Worker mode state isolation: zero mutable static properties",
    "Generator-first streaming for O(1) memory consumption",
    "Explicit Doctrine entity manager cache clearing ($em->clear())"
  ],
  "playbook": {
    "verification_commands": [
      "php bin/php-master verify-slice --slice SLICE-002-WORKER-STREAMER"
    ],
    "known_failure_modes": [
      {
        "pattern": "Stateful static accumulation detected",
        "diagnostic_recipe": "Refactor static properties to scoped instance variables and decouple worker request cycles."
      }
    ]
  },
  "state": "DISPATCHED"
}
```
