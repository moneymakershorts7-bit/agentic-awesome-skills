# Agent Contracts & State Machine Specification

## 1. Task + Playbook Contract Schema

Every task delegated to any Ruby enterprise worker or verification agent must strictly adhere to the `TaskPlaybookContract` specification:

```json
{
  "task_id": "SLICE-001-PAYMENT-LEDGER-TRANSACTION",
  "assigned_agent": "domain-type-architect",
  "scope": {
    "files_target": [
      "app/domains/billing/transaction.rb",
      "sig/app/domains/billing/transaction.rbs"
    ],
    "interfaces": [
      "Billing::Transaction",
      "Billing::Money"
    ]
  },
  "functional_invariants": [
    "# frozen_string_literal: true at top of all files",
    "Immutable Data.define representing Money with integer cents and currency code",
    "Complete RBS signature with zero untyped definitions",
    "Pure functional transaction transition returning Dry::Monads::Result",
    "Packwerk package boundaries strictly observed without crossing into Web layer"
  ],
  "playbook": {
    "verification_commands": [
      "bundle exec rubocop app/domains/billing/transaction.rb",
      "bundle exec steep check",
      "bundle exec packwerk check",
      "bundle exec rspec spec/domains/billing/transaction_spec.rb",
      "bundle exec mutant run --include lib --require billing/transaction --use rspec 'Billing::Transaction*'"
    ],
    "known_failure_modes": [
      {
        "pattern": "Steep::Diagnostic::Ruby::NoMethodError",
        "diagnostic_recipe": "Declare the method signature in the corresponding .rbs file and verify return type annotations."
      },
      {
        "pattern": "Packwerk::PrivacyViolation",
        "diagnostic_recipe": "Expose the required domain behavior through the package's public API interface."
      },
      {
        "pattern": "Mutant: Mutation score below 80%",
        "diagnostic_recipe": "Add explicit unit test examples covering boundary cases, zero amounts, and invalid currencies."
      }
    ]
  }
}
```

---

## 2. Finite State Machine (FSM) Lifecycle

The Orchestrator-Worker engine operates under a strict finite state machine:

```
┌──────────────┐
│  DISPATCHED  │
└──────┬───────┘
       │ Worker takes assignment
       ▼
┌──────────────┐
│   RUNNING    │
└──────┬───────┘
       │ Worker completes slice implementation
       ▼
┌──────────────┐
│  VERIFYING   │◄─────────────────────────────┐
└──────┬───────┘                              │ Retry attempt (up to 3)
       │ Independent Verifier QA audit        │
       ├──────────────────────────────────────┼────────────────────────┐
       │ PASS                                 │ FAIL                   │ Exceeded max attempts
       ▼                                      ▼                        ▼
┌──────────────┐                    ┌─────────────────────┐  ┌────────────────────┐
│  COMPLETED   │                    │ FAILED_HEALING_LOOP │  │ TERMINAL_ABORT     │
└──────────────┘                    └─────────────────────┘  └────────────────────┘
```

### Transition Invariants
1. **`DISPATCHED` ──► `RUNNING`**: Triggered exclusively when the assigned domain worker initializes the execution context.
2. **`RUNNING` ──► `VERIFYING`**: Triggered when the domain worker finishes generating code and target artifacts.
3. **`VERIFYING` ──► `COMPLETED`**: Triggered ONLY when Agent 5 (`verifier-qa`) reports 100% clean passes on type checking, Brakeman, Packwerk, Mutant, and RSpec.
4. **`VERIFYING` ──► `FAILED_HEALING_LOOP`**: Triggered when any verification check fails. Matches failure patterns to the playbook diagnostic recipe.
5. **`FAILED_HEALING_LOOP` ──► `RUNNING`**: Re-invokes worker with diagnostic recipe for self-healing (up to 3 iterations).
