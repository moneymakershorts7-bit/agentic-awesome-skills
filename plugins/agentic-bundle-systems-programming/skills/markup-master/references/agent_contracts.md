# Agent Contracts and Finite State Machine Specification

## 1. Task + Playbook Execution Contract Schema
Every atomic slice dispatched to any worker conforms to this deterministic contract:

```json
{
  "task_id": "SLICE-001-HTML-PRICING-TABLE",
  "assigned_agent": "html-a11y-architect",
  "scope": {
    "files_target": ["public/components/pricing-table.html"],
    "specifications": ["HTML5", "WCAG 2.2 AA", "JSON-LD"]
  },
  "functional_invariants": [
    "Zero axe-core accessibility violations (color contrast >= 4.5:1, valid ARIA grid/table roles)",
    "Embedded JSON-LD Product schema with valid Offer price currency format",
    "Zero inline styles; semantic table markup using <thead>, <tbody>, <th scope='col'>"
  ],
  "playbook": {
    "verification_commands": [
      "vnu --Werror public/components/pricing-table.html",
      "axe public/components/pricing-table.html --tags wcag2a,wcag2aa",
      "check-jsonschema --schemafile schemas/pricing-schema.json public/components/pricing-data.json"
    ],
    "known_failure_modes": [
      {
        "pattern": "axe: color-contrast",
        "diagnostic_recipe": "Adjust foreground text token to satisfy minimum 4.5:1 ratio against card background."
      },
      {
        "pattern": "vnu: Element p not allowed as child of table",
        "diagnostic_recipe": "Move paragraph outside table or wrap inside <caption> / <td> cell."
      }
    ]
  }
}
```

## 2. Finite State Machine (FSM) Transitions

```
[DISPATCHED]
     │
     ▼
 [RUNNING]  ◄──────────────────────────┐
     │                                 │ (Retry Budget > 0)
     ▼                                 │
[VERIFYING] ──► [Self-Healing Loop] ───┘
     │
     ├─────► [PASS] ──► [COMPLETED]
     │
     └─────► [FAIL & Exhausted] ──► [FAILED_HEALING_LOOP]
```

### Transition Invariants
1. `DISPATCHED` -> `RUNNING`: Worker begins parsing, tokenizing, and executing slice.
2. `RUNNING` -> `VERIFYING`: Worker completes execution and hands artifacts to Agent 5 (`verifier-qa-auditor`).
3. `VERIFYING` -> `COMPLETED`: Independent adversarial verifier grants `PASS`. Changes are committed and integrated.
4. `VERIFYING` -> `RUNNING`: Adversarial verifier grants `FAIL`. If retry budget remains (max 3), the diagnostic recipe matching the failure pattern is applied.
5. `VERIFYING` -> `FAILED_HEALING_LOOP`: Adversarial verifier grants `FAIL` and retry budget is exhausted. Execution halts and emits full diagnostics.
