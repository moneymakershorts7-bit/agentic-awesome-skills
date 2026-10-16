# TaskPlaybookContract & State Machine Reference (`java-master`)

The `java-master` platform enforces deterministic, contract-bound execution between the Lead Orchestrator and specialized worker agents. Every delegation adheres to the formal `TaskPlaybookContract` schema.

---

## 1. JSON Contract Schema

```json
{
  "task_id": "SLICE-001-LOOM-DISPATCHER",
  "assigned_agent": "loom-architect",
  "scope": {
    "files_target": ["src/main/java/com/master/concurrency/VirtualDispatcher.java"],
    "interfaces": ["TaskDispatcher", "ExecutionPolicy"]
  },
  "functional_invariants": [
    "Tasks executed via StructuredTaskScope.ShutdownOnFailure",
    "Zero synchronized blocks across virtual thread call stacks to prevent carrier thread pinning",
    "Timeout deadlines enforced on all asynchronous operations"
  ],
  "playbook": {
    "verification_commands": [
      "./mvnw test -Dtest=VirtualDispatcherTest",
      "./mvnw spotbugs:check",
      "./mvnw pitest:mutationCoverage"
    ],
    "known_failure_modes": [
      {
        "pattern": "Pinned virtual thread detected",
        "diagnostic_recipe": "Replace synchronized(lock) with java.util.concurrent.locks.ReentrantLock."
      },
      {
        "pattern": "SURVIVED",
        "diagnostic_recipe": "PIT mutation detected missing assertion on boundary condition; add targeted test case."
      }
    ]
  }
}
```

---

## 2. Field Specifications

| Field | Type | Description |
| :--- | :--- | :--- |
| `task_id` | `string` | Unique slice identifier (e.g., `SLICE-001-LOOM-DISPATCHER`). |
| `assigned_agent` | `string` | ID of the specialized worker (`loom-architect`, `jvm-optimizer`, `domain-architect`, `security-auditor`). |
| `scope.files_target` | `[]string` | Bounded file paths or package directories targeted for inspection or mutation. |
| `scope.interfaces` | `[]string` | Primary Java interface types touched by this slice. |
| `functional_invariants`| `[]string` | Non-negotiable architectural and domain invariants that must hold true. |
| `playbook.verification_commands` | `[]string` | Deterministic CLI commands executed by Agent 5 (`verifier-qa`). |
| `playbook.known_failure_modes` | `[]object` | Regex patterns and automated diagnostic recipes executed upon failure. |

---

## 3. Finite State Machine (FSM) Lifecycle

```
┌──────────────┐
│  DISPATCHED  │
└──────┬───────┘
       │ Initial dispatch from Lead Orchestrator
       ▼
┌──────────────┐
│   RUNNING    │◄────────────────────────────────┐
└──────┬───────┘                                 │
       │ Slice execution complete                │ Self-healing retry
       ▼                                         │ (Attempts <= max)
┌──────────────┐                                 │
│  VERIFYING   │ (Independent Verifier-QA Gate)  │
└──────┬───────┘                                 │
       │                                         │
       ├──► Verification FAILED (Within budget) ─┘
       │
       ├──► Verification PASSED
       │    │
       │    ▼
       │ ┌──────────────┐
       │ │  COMPLETED   │ (Merged & Integrated)
       │ └──────────────┘
       │
       └──► Verification FAILED (Budget exhausted > max attempts)
            │
            ▼
         ┌──────────────────────┐
         │ FAILED_HEALING_LOOP  │ (Halted & Escalated)
         └──────────────────────┘
```

---

## 4. State Invariants

1. **Deterministic Slicing**: Slices must be bounded to a single functional unit of work. Monolithic PRs are unconditionally rejected.
2. **Adversarial Separation**: The worker that produces the slice cannot verify its own slice. Only Agent 5 (`verifier-qa`) has verification authority.
3. **Healing Budget**: By default, each task slice has a maximum of 3 healing attempts. When exceeded, the state machine halts in `FAILED_HEALING_LOOP`.
