# TaskPlaybookContract & State Machine Reference

The `go-master` platform enforces deterministic, contract-bound execution between the Lead Orchestrator and specialized worker agents. Every delegation adheres to the formal `TaskPlaybookContract` schema.

---

## 1. JSON Contract Schema

```json
{
  "task_id": "SLICE-001-CONCURRENCY-PIPELINE",
  "assigned_agent": "concurrency-architect",
  "scope": {
    "files_target": ["internal/pipeline/worker.go"],
    "interfaces": ["WorkerPool", "Consumer"]
  },
  "functional_invariants": [
    "Context cancellation terminates all worker goroutines within 100ms",
    "Zero goroutine leaks verified by Uber goleak",
    "Channel buffer sizes must be mathematically bounded; no unbounded buffering"
  ],
  "playbook": {
    "verification_commands": [
      "go test -race -v -run TestWorkerPoolShutdown ./internal/pipeline/...",
      "go vet ./internal/pipeline/..."
    ],
    "known_failure_modes": [
      {
        "pattern": "DATA RACE",
        "diagnostic_recipe": "Inspect shared state mutations; replace with atomic primitive or channel handoff."
      },
      {
        "pattern": "goleak: found lingering goroutine",
        "diagnostic_recipe": "Ensure select block listens on ctx.Done() and closes sender channels."
      }
    ]
  }
}
```

---

## 2. Field Specifications

| Field | Type | Description |
| :--- | :--- | :--- |
| `task_id` | `string` | Unique slice identifier (e.g., `SLICE-001-CONCURRENCY-PIPELINE`). |
| `assigned_agent` | `string` | ID of the specialized worker (`concurrency-architect`, `perf-optimizer`, `api-engineer`, `security-auditor`). |
| `scope.files_target` | `[]string` | Bounded file paths or package directories targeted for inspection or mutation. |
| `scope.interfaces` | `[]string` | Primary Go interface types touched by this slice. |
| `functional_invariants`| `[]string` | Non-negotiable architectural and domain invariants that must hold true. |
| `playbook.verification_commands` | `[]string` | Deterministic CLI commands executed by Agent 5 (`verifier-qa`). |
| `playbook.known_failure_modes` | `[]object` | Regex patterns and automated diagnostic recipes executed upon failure. |

---

## 3. Finite State Machine (FSM) Lifecycle

```
┌──────────────┐
│  DISPATCHED  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   RUNNING    │ ◄─────────────────────────┐
└──────┬───────┘                           │
       │                                   │
       ▼                                   │
┌──────────────┐                           │
│  VERIFYING   │                           │
└──────┬───────┘                           │
       │                                   │
       ├─────────────────────┐             │ (Retry Loop)
       ▼                     ▼             │
┌──────────────┐   ┌─────────────────────┐ │
│  COMPLETED   │   │ FAILED_HEALING_LOOP ├─┘
└──────────────┘   └─────────────────────┘
 (Terminal PASS)      (Terminal FAIL after max attempts)
```

### Transition Invariants
1. `DISPATCHED` -> `RUNNING`: Worker begins execution.
2. `RUNNING` -> `VERIFYING`: Worker completes slice modifications and hands over to Agent 5 (`verifier-qa`).
3. `VERIFYING` -> `COMPLETED`: Agent 5 verifies that all commands pass with 0 exit code, 0 data races, and 0 goroutine leaks.
4. `VERIFYING` -> `FAILED_HEALING_LOOP`: Agent 5 detects a failure, matches diagnostic recipes, and initiates a healing attempt (up to `MaxHealingAttempts`, default 3).
5. `FAILED_HEALING_LOOP` -> `RUNNING`: Self-healing iteration begins with diagnostic recipe injected into context.
