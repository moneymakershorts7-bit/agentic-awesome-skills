# Playbook 08: Architecture Fitness & ISO/IEC 5055 Static Audit

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                 PLAYBOOK 08: ARCHITECTURE FITNESS & ISO/IEC 5055 AUDIT                  │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ Standards: ISO/IEC 25010 | ISO/IEC 5055 | SonarQube Clean Code Gate | OpenAPI 3.1       │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## Objective
Enforce structural code quality, verify that Cyclomatic Complexity does not exceed 10, Cognitive Complexity does not exceed 15, Nesting depth does not exceed 4, and validate API contracts.

---

## Step 1: Run Cyclomatic & Cognitive Complexity Scans
Scan all modified files for McCabe Cyclomatic Complexity, Cognitive Complexity, and file size:
```bash
python3 ~/.agents/skills/qa-master/scripts/architecture_fitness_checker.py --check-complexity . --max-cc 10 --max-nesting 4 --output .audit/complexity_audit.json
```

### Acceptance Criteria:
- Maximum Cyclomatic Complexity $\le 10$ across all functions.
- Maximum Cognitive Complexity $\le 15$ per function.
- Maximum Nesting Depth $\le 4$ levels.
- File length $\le 500$ LOC.

---

## Step 2: Validate API Schema Contracts
Verify OpenAPI 3.1 and AsyncAPI specifications for syntax correctness and breaking schema drift:
```bash
python3 ~/.agents/skills/qa-master/scripts/architecture_fitness_checker.py --check-contracts docs/openapi/ --output .audit/contract_audit.json
```

### Acceptance Criteria:
- Zero structural schema errors.
- No breaking removal of fields without major API version increment.

---

## Step 3: Run Architecture Fitness Functions
Verify layer separation (e.g. domain entities not importing database drivers):
```bash
python3 ~/.agents/skills/qa-master/scripts/architecture_fitness_checker.py --check-boundaries src/ --output .audit/boundary_audit.json
```
