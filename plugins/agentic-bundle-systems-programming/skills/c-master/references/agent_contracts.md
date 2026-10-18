# Agent Execution Contracts & FSM Specification

## 1. Task + Playbook Execution Contract Schema

Every task delegated to any worker agent in the `c-master` ecosystem adheres to a deterministic JSON schema:

```json
{
  "task_id": "SLICE-001-RING-BUFFER-ALLOCATOR",
  "assigned_agent": "runtime-perf-optimizer",
  "scope": {
    "files_target": [
      "src/core/ring_buffer.c",
      "include/c_master/ring_buffer.h"
    ],
    "interfaces": [
      "ring_buffer_t",
      "ring_buffer_push",
      "ring_buffer_pop"
    ]
  },
  "functional_invariants": [
    "C23 compliance with nullptr and fixed-width integer types",
    "Opaque struct pointer encapsulation in public header",
    "Lock-free single-producer single-consumer atomics with acquire-release memory orders",
    "Cache-line padding (64 bytes) separating head and tail indices to prevent false sharing"
  ],
  "playbook": {
    "verification_commands": [
      "cmake --build build --target test_ring_buffer",
      "ctest --test-dir build -R test_ring_buffer --output-on-failure",
      "clang-tidy src/core/ring_buffer.c -- -Iinclude",
      "valgrind --leak-check=full --error-exitcode=1 ./build/tests/test_ring_buffer"
    ],
    "known_failure_modes": [
      {
        "pattern": "runtime error: member access within misaligned address",
        "diagnostic_recipe": "Align structure or buffer using alignas(64) and verify pointer arithmetic."
      },
      {
        "pattern": "data race detected by ThreadSanitizer",
        "diagnostic_recipe": "Upgrade relaxed memory orders to acquire-release semantics on head and tail pointers."
      },
      {
        "pattern": "implicitly declaring library function 'memcpy'",
        "diagnostic_recipe": "Include <string.h> explicitly in translation unit."
      }
    ]
  }
}
```

---

## 2. Finite State Machine (FSM) Transitions

```
               ┌────────────────┐
               │   DISPATCHED   │
               └───────┬────────┘
                       │ task_contract_transition(RUNNING)
                       ▼
               ┌────────────────┐
    ┌─────────►│    RUNNING     │
    │          └───────┬────────┘
    │                  │ task_contract_transition(VERIFYING)
    │                  ▼
    │          ┌────────────────┐
    │          │   VERIFYING    │
    │          └───────┬────────┘
    │                  │
    │                  ├──────────────────────────────┐
    │                  │ Verdict == PASS              │ Verdict == VETO
    │                  ▼                              ▼
    │          ┌────────────────┐             ┌─────────────────────────┐
    │          │   COMPLETED    │             │   FAILED_HEALING_LOOP   │
    │          └────────────────┘             └────────────┬────────────┘
    │                                                      │
    └──────────────── Apply Healing Recipe ────────────────┘
                      (Retries <= max_retries)
```

### Transition Invariants
1. `DISPATCHED` $\to$ `RUNNING`: Worker begins code implementation or modification.
2. `RUNNING` $\to$ `VERIFYING`: Worker completes implementation; dispatches verification commands to `verifier-qa`.
3. `VERIFYING` $\to$ `COMPLETED`: All compiler, sanitizer, static analysis, and unit test assertions pass with 100% green. Slice is committed and integrated.
4. `VERIFYING` $\to$ `FAILED_HEALING_LOOP`: Any verification failure triggers an unconditional veto. Enters self-healing loop.
5. `FAILED_HEALING_LOOP` $\to$ `RUNNING`: Matches failure pattern, applies diagnostic recipe, and retries. Up to 3 attempts before declaring failure.
