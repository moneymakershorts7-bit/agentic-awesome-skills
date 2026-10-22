# ISO/IEC/IEEE 29119 Testing Process, Metrics & Machine-Readable Schemas

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    ISO/IEC/IEEE 29119 TESTING STANDARD SPECIFICATION                    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ Standards: ISO/IEC/IEEE 29119 (Parts 1-5) | ISTQB Foundation & Advanced | TMap Suite    │
│            Test Pyramid (70/20/10) | Mutation Testing (MSI >= 80%) | Property Testing   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. ISO/IEC/IEEE 29119 Standard Overview

ISO/IEC/IEEE 29119 is the definitive international series of software testing standards:

- **Part 1: Concepts and Definitions:** Standardizes the vocabulary of verification, test design, and test artifacts.
- **Part 2: Test Processes:** Establishes a 3-layer process model:
  1. *Organizational Test Process:* Organizational test policy and governance.
  2. *Test Management Processes:* Test planning, monitoring, and control.
  3. *Dynamic Test Processes:* Test design, environment setup, execution, and incident logging.
- **Part 3: Test Documentation:** Mandates standardized document templates:
  - Test Policy
  - Test Strategy
  - Test Plan
  - Test Case Specification
  - Test Incident Report
  - Test Summary Report
- **Part 4: Test Design Techniques:**
  - *Specification-Based (Black-box):* Equivalence Partitioning, Boundary Value Analysis, Decision Tables, State Transition.
  - *Structure-Based (White-box):* Statement Coverage, Branch Coverage, Modified Condition/Decision Coverage (MC/DC).
  - *Experience-Based:* Error guessing, Exploratory Testing with Session Charters.
- **Part 5: Keyword-Driven Testing:** Standardized keyword execution frameworks.

---

## 2. Test Execution Invariants & Metrics

### 2.1 The Modern Test Pyramid Distribution
- **Unit Tests (~70%):** Fast, in-memory, deterministic tests validating domain logic and algorithms. Zero network or filesystem dependencies. Execution time: $< 100\text{ms}$ per test.
- **Integration Tests (~20%):** Validates interactions between modules, databases, and message brokers using ephemeral testcontainers or local in-memory engines.
- **Contract & E2E Tests (~10%):** Consumer-Driven Contracts (Pact) and end-to-end user journeys (Playwright/Cypress).

### 2.2 Coverage Thresholds
- **Line Coverage:** Minimum **80.0%** across the repository; minimum **90.0%** on core domain modules.
- **Branch Coverage:** Minimum **75.0%** on conditional branches.

### 2.3 Mutation Score Indicator (MSI)
Coverage alone does not prove test efficacy. Mutation testing injects deliberate artificial faults (mutants) into source code to verify that the test suite detects and fails on them:

$$\text{MSI} = \frac{\text{Killed Mutants}}{\text{Total Mutants} - \text{Incompetent Mutants}} \times 100$$

- **Gating Rule:** **Mutation Score Indicator (MSI) must be $\ge 80.0\%$.**
- Any surviving mutant in newly authored or modified code fails the quality gate.

---

## 3. Machine-Readable Test Summary Report Schema (`.audit/test_summary_report.json`)

Adhering to ISO/IEC/IEEE 29119-3 clause 8.6 (Test Summary Report):

```json
{
  "$schema": "https://iso29119.org/schemas/test-summary-report-v1.json",
  "report_id": "TSR-20261022-001",
  "standard": "ISO/IEC/IEEE 29119-3:2021",
  "project_metadata": {
    "repository": "enterprise/payment-gateway",
    "git_commit": "e83c2497647f44a35f00...",
    "execution_timestamp": "2026-10-22T00:30:00Z"
  },
  "pyramid_distribution": {
    "unit_tests_count": 420,
    "unit_percentage": 72.4,
    "integration_tests_count": 120,
    "integration_percentage": 20.7,
    "e2e_tests_count": 40,
    "e2e_percentage": 6.9
  },
  "execution_metrics": {
    "total_tests": 580,
    "passed": 580,
    "failed": 0,
    "skipped": 0,
    "total_duration_ms": 14250
  },
  "coverage_metrics": {
    "line_coverage_pct": 88.5,
    "branch_coverage_pct": 82.1,
    "line_coverage_threshold_met": true,
    "branch_coverage_threshold_met": true
  },
  "mutation_metrics": {
    "total_mutants": 150,
    "killed_mutants": 132,
    "survived_mutants": 18,
    "mutation_score_indicator": 88.0,
    "msi_threshold_met": true
  },
  "flaky_resilience": {
    "variance_runs_executed": 10,
    "flaky_tests_detected": 0,
    "quarantined_tests_count": 0
  },
  "verdict": "PASS"
}
```
