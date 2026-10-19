# Agent Execution Contracts & Finite State Machine (FSM)

The `bash-master` platform enforces the **Frontier Orchestrator-Worker Standard** via deterministic, machine-readable contracts. Monolithic God-Scripts and fragile unverified pipelines are strictly prohibited. Every piece of work dispatched to any domain agent must be formalized as a `TaskPlaybookContract`.

---

## 1. Contract Specification (`contracts/schema.json`)

Each contract defines an immutable functional unit of work:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TaskPlaybookContract",
  "type": "object",
  "required": [
    "task_id",
    "agent",
    "scope",
    "inputs",
    "functional_invariants",
    "acceptance_criteria",
    "playbook"
  ],
  "properties": {
    "task_id": {
      "type": "string",
      "description": "Unique deterministic slug (e.g., slice-001-defensive-init)"
    },
    "agent": {
      "type": "string",
      "enum": [
        "defensive-bash-architect",
        "posix-portability-engineer",
        "concurrency-ipc-engineer",
        "security-secsdlc-auditor",
        "verifier-qa"
      ]
    },
    "scope": {
      "type": "object",
      "required": ["target_files", "description"],
      "properties": {
        "target_files": {
          "type": "array",
          "items": { "type": "string" }
        },
        "description": { "type": "string" }
      }
    },
    "inputs": {
      "type": "object"
    },
    "functional_invariants": {
      "type": "array",
      "items": { "type": "string" }
    },
    "acceptance_criteria": {
      "type": "array",
      "items": { "type": "string" }
    },
    "playbook": {
      "type": "object",
      "required": [
        "pre_flight_checks",
        "execution_steps",
        "verification_commands",
        "failure_modes",
        "diagnostic_recipes"
      ],
      "properties": {
        "pre_flight_checks": { "type": "array", "items": { "type": "string" } },
        "execution_steps": { "type": "array", "items": { "type": "string" } },
        "verification_commands": { "type": "array", "items": { "type": "string" } },
        "failure_modes": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["code", "signature", "remedy"],
            "properties": {
              "code": { "type": "string" },
              "signature": { "type": "string" },
              "remedy": { "type": "string" }
            }
          }
        },
        "diagnostic_recipes": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["error_type", "diagnostic_cmd", "corrective_action"],
            "properties": {
              "error_type": { "type": "string" },
              "diagnostic_cmd": { "type": "string" },
              "corrective_action": { "type": "string" }
            }
          }
        }
      }
    }
  }
}
```

---

## 2. Finite State Machine (FSM) Lifecycle

The execution lifecycle of any contract follows a strict 4-state state machine:

```
  ┌──────────────┐
  │  DISPATCHED  │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │   RUNNING    │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │  VERIFYING   │◄────────┐
  └──────┬───────┘         │ (Self-Healing Loop)
         │                 │
    [Pass / Fail]          │
         ├─────────────────┤
         │ (Pass)          │ (Fail with matching remedy)
         ▼                 │
  ┌──────────────┐         │
  │  COMPLETED   │         │
  └──────────────┘         │
                           │
         │ (Exhausted /    │
         │  Unrecoverable) │
         ▼                 │
  ┌───────────────────────┴┐
  │  FAILED_HEALING_LOOP   │
  └────────────────────────┘
```

### State Definitions
1. **`DISPATCHED`**: Contract created and validated against JSON schema. Initial status before worker execution.
2. **`RUNNING`**: Worker process executes `playbook.execution_steps`.
3. **`VERIFYING`**: Worker runs all deterministic `playbook.verification_commands`.
4. **`COMPLETED`**: All verification commands pass with exit status 0.
5. **`FAILED_HEALING_LOOP`**: Verification failed and diagnostic self-healing recipes were exhausted (max 3 iterations) without reaching green state.

---

## 3. Self-Healing Diagnostic Recovery Loop

When verification commands fail during the `VERIFYING` phase, `bash-worker` triggers the autonomous diagnostic recovery loop:
1. Captures failed command, return code, stdout, and stderr.
2. Matches output signatures against `playbook.failure_modes`.
3. Executes corresponding `playbook.diagnostic_recipes.corrective_action`.
4. Re-enters `VERIFYING` state.
5. If after 3 healing attempts tests do not pass, transitions to `FAILED_HEALING_LOOP` and halts execution cleanly with full diagnostic telemetry.

---

## 4. Security, Sandbox & Execution Boundary Guardrails

To prevent unintended side effects, command injection, and unauthorized actions during autonomous contract execution:
1. **Bounded Shell Command Execution**: All `execution_steps`, `verification_commands`, and diagnostic `corrective_action` entries execute strictly within user-approved workspace boundaries.
2. **Deterministic Argument Passing**: Never interpolate unsanitized strings or user input directly into subshells. Use pipeline streaming (`printf '%s\n' "${cmd}" | bash`) or explicit argument arrays.
3. **Restricted Privileges**: All contracts must execute as an unprivileged user (UID 1000 / `USER bashdev`). Root execution (`UID 0`) is strictly blocked by `lib/core/env.sh`.
4. **Environment Sanitization**: Standard environment variables (`PATH`, `IFS`, `umask 077`) are cleansed before running any playbook step, preventing `LD_PRELOAD`, `PYTHONPATH`, or `CDPATH` hijacking.
5. **No Network Exfiltration**: Contract verification commands are restricted to local deterministic test suites (Bats, ShellCheck, shfmt). Outbound external network connections during verification are prohibited.
