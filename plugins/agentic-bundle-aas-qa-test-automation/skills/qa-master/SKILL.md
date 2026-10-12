---
name: qa-master
description: Master QA orchestrator for automated & manual testing, test pyramid execution, flaky test quarantine, exploratory charters, and CI/CD quality gates.
risk: safe
source: self
source_type: self
license: MIT
date_added: 2026-10-12
allowed-tools:
  - bash
  - read
  - edit
  - glob
  - grep
  - scan_skill
---

# QA Master: Universal Software Quality Engineering & Assurance

Software Quality Assurance is not mere manual clicking or writing flaky browser scripts; it is **ambient, rigorous, multi-layered empirical verification** embedded directly into the developer workflow (*"Shift-Left Quality, Shield-Every-Layer"*).

This master skill operationalizes the industry's foundational testing literature (Khorikov, Crispin & Gregory, Hendrickson, Bach, Meszaros, Newman) and modern SDET tooling architectures (inspired by `testing-starter-kit`, Playwright, Pact, k6, axe-core, Stryker), fortified with **El Décimo Hombre** adversarial stress-testing.

Operating alongside `devsecops-master`, `qa-master` forms the complete, self-healing twin-engine assurance suite for all modern software development.

---

## When to Use This Skill

Invoke `qa-master` whenever you need to:
1. **Verify Any Code Change or Development:** Execute automated test discovery and run unit, integration, contract, and E2E suites on every feature or refactor.
2. **Design a Comprehensive Test Strategy:** Decompose an application using SFDIPOT (Structure, Function, Data, Interfaces, Platform, Operations, Time) and Agile Testing Quadrants (Q1-Q4).
3. **Conduct Session-Based Exploratory Testing (Manual QA):** Formulate targeted charters and evaluate edge cases against the 11 FEW HICCUPPS consistency oracles.
4. **Implement Flake-Free Browser Automation:** Build resilient Playwright/Cypress suites using accessibility-tree locators (`getByRole`, `getByLabel`), network interception, and auto-waiting.
5. **Enforce Consumer-Driven Contract Testing (Pact):** Verify microservice schema compatibility and eliminate brittle multi-service integration dependencies.
6. **Detect and Quarantine Flaky Tests:** Execute variance-stress runs to detect non-deterministic flakes and automatically isolate them from blocking CI gates.
7. **Measure Assertion Quality (Mutation Testing):** Evaluate the Mutation Score Index (MSI) to ensure tests catch actual logic faults rather than passively exercising code lines.
8. **Automate Performance & Accessibility Gates:** Run k6 latency/error smoke gates and axe-core WCAG 2.2 AA accessibility audits in CI.
9. **Return Machine-Readable CI Reports:** Consolidate test verdicts into standardized JSON, JUnit XML, and GitHub PR comment scorecards.

---

## The 6-Stage Universal QA Engineering Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UNIVERSAL QA ENGINEERING LIFECYCLE                       │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
   ┌──────────────────────────────────┼──────────────────────────────────┐
   ▼                                  ▼                                  ▼
[Stage 1: Strategy & Modeling]   [Stage 2: Unit & Invariants]   [Stage 3: Contract & Boundary]
- SFDIPOT Product Decomposition   - Classical xUnit School       - Consumer-Driven Contracts (Pact)
- Agile Testing Quadrants (Q1-Q4) - Property-Based (fast-check)  - API Schema Validation
- Risk-Weighted Test Layering     - Mutation Score Index (MSI)   - Big List of Naughty Strings
   │                                  │                                  │
   └──────────────────────────────────┼──────────────────────────────────┘
                                      │
   ┌──────────────────────────────────┼──────────────────────────────────┐
   ▼                                  ▼                                  ▼
[Stage 4: Integration & State]   [Stage 5: E2E User Journeys]   [Stage 6: Non-Functional & Exploratory]
- Testcontainers (Real DB/Queues) - Resilient Playwright Locators - Performance Smoke (k6 p95 < 500ms)
- Clean Transaction Rollbacks    - Visual Regression (Pixelmatch) - WCAG 2.2 AA Accessibility (Axe)
- Ephemeral In-Memory Servers     - Network Mocking at Protocol   - SBTM Exploratory Charters
   │                                  │                                  │
   └──────────────────────────────────┼──────────────────────────────────┘
                                      │
                                      ▼
             [Stage 7: Machine-Readable CI Gate & Reporting]
             - Unified Test Summary JSON & JUnit XML
             - PR Comment Scorecards & Flake Quarantine Trigger
             - Joint Evaluation with DevSecOps Master
```

For complete phase details, consult [`references/literature-and-canon.md`](references/literature-and-canon.md).

---

## Core Decision Heuristics & Quality Gates

### 1. The 5-Minute PR Rule
Pull request test gating suites MUST complete execution in under 5 minutes. Heavyweight performance soak tests, whole-history visual audits, and mutation matrices must run asynchronously out-of-band or in scheduled nightly pipelines to protect developer velocity.

### 2. Gating Threshold Enforcement

| Test Dimension | Blocker Threshold (Exit Code 1 / Block PR) | Warning Threshold (Exit Code 0 / Annotate PR) |
| :--- | :--- | :--- |
| **Functional Tests** | Any test failure in Unit, Contract, Integration, or E2E suites | Skipped tests marked with `@todo` or `@pending` |
| **Flaky Tests** | Flake rate $> 0\%$ in blocking suite (must quarantine) | Flake rate $> 0\%$ in non-blocking quarantine suite |
| **Mutation Score** | $\text{MSI} < 70\%$ on critical domain modules | $\text{MSI} < 85\%$ on secondary utility modules |
| **Accessibility** | $\ge 1$ Critical or Serious WCAG 2.2 AA violation | Minor or Moderate contrast / layout warnings |
| **Performance** | Error rate $\ge 0.1\%$ OR p95 latency regressed $> 50\%$ | p95 latency regressed between $20\% - 50\%$ |
| **Test Doubles** | London-school mock hell on pure domain calculation | Mocks used at external HTTP/I-O boundaries |

### 3. Locator Selection Hierarchy (Flake Prevention)
Never use brittle CSS classes (`.submit-btn-v2`) or XPath (`/html/body/div[1]/button`).
1. `page.getByRole('button', { name: /confirm payment/i })` (Accessibility Tree standard)
2. `page.getByLabel('Work Email')`
3. `page.getByPlaceholder('name@example.com')`
4. `page.getByTestId('checkout-action-button')` (Explicit contract)

---

## El Décimo Hombre Adversarial Defenses

Standard QA often degrades into "coverage theater." This skill enforces 4 adversarial tripwires:

1. **Anti-Flake Quarantine Gate:** Any test failing and passing intermittently on the same commit SHA is instantly quarantined into a separate quarantine pipeline. Rerunning CI until green is strictly prohibited.
2. **Anti-Mock Drift Gate:** Testing domain behavior against real in-memory models. External third-party APIs must use Consumer-Driven Contracts or ephemeral container sandboxes (Testcontainers).
3. **Anti-Hollow Coverage Gate:** High statement coverage without assertions is flagged via Mutation Testing. A test suite must demonstrate $\text{MSI} \ge 70\%$.
4. **Order Randomization Gate:** Test suites must pass when run in randomized sequence (`--randomize` / `--shuffle`) to eliminate dirty state leaks and hidden execution coupling.

Consult [`references/decimo-hombre-adversarial.md`](references/decimo-hombre-adversarial.md) for full pre-AAR analyses.

---

## Automated Tooling & Scripts

The skill provides production CLI tools located in `~/.agents/skills/qa-master/scripts/`:

### 1. Unified QA Orchestrator
Auto-detects frameworks (Pytest, Unittest, Vitest, Jest, Bun test, Playwright, Go test, Cargo test), executes suites, and aggregates results:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_orchestrator.py --run-all . --output-dir reports/qa/
```

### 2. Heuristic Test Plan & Charter Generator
Decomposes the codebase into SFDIPOT models and creates Session-Based Exploratory Charters:
```bash
python3 ~/.agents/skills/qa-master/scripts/generate_test_plan.py --repo . --output qa_plan.json
```

### 3. Flaky Test Detector & Variance Profiler
Runs a candidate command $N$ times to verify determinism and compute timing variance:
```bash
python3 ~/.agents/skills/qa-master/scripts/flaky_detector.py --cmd "python3 -m unittest test_api.py" --runs 5
```

### 4. Mutation Testing Quality Evaluator
Mutates operators and conditions in target files to verify test assertion quality:
```bash
python3 ~/.agents/skills/qa-master/scripts/mutation_check.py --file src/calc.py --test-cmd "python3 -m unittest test_calc.py" --threshold 70
```

### 5. Unified PR Reporter & Gate Aggregator
Ingests QA and DevSecOps results to output consolidated Markdown PR comments and CI verdicts:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_reporter.py --qa-results reports/qa/qa_results.json --security-results reports/security_audit.json --output reports/pr_comment.md
```

---

## Playbooks Directory Index

- [`01-project-qa-onboarding.md`](playbooks/01-project-qa-onboarding.md): Inspecting an unfamiliar codebase and establishing test baselines.
- [`02-exploratory-session-charter.md`](playbooks/02-exploratory-session-charter.md): Executing Session-Based Exploratory Testing with FEW HICCUPPS oracles.
- [`03-automated-test-pyramid-execution.md`](playbooks/03-automated-test-pyramid-execution.md): Layered execution across Unit, Contract, Integration, and E2E.
- [`04-flaky-test-quarantine-and-triage.md`](playbooks/04-flaky-test-quarantine-and-triage.md): Flake detection, isolation quarantine, and root-cause repair.
- [`05-performance-and-load-gating.md`](playbooks/05-performance-and-load-gating.md): k6 smoke and sustained load testing with strict latency SLAs.
- [`06-devsecops-qa-joint-gate.md`](playbooks/06-devsecops-qa-joint-gate.md): Twin-engine deployment pipeline combining `devsecops-master` and `qa-master`.

---

## References Directory Index

- [`literature-and-canon.md`](references/literature-and-canon.md): Deep synthesis of Khorikov, Crispin & Gregory, Hendrickson, Bach, Meszaros, Newman.
- [`test-automation-matrix.md`](references/test-automation-matrix.md): Concrete configurations and cheat sheets for Playwright, Cypress, Vitest, Pact, k6, axe-core.
- [`exploratory-heuristics-and-oracles.md`](references/exploratory-heuristics-and-oracles.md): SFDIPOT product breakdown, FEW HICCUPPS oracles, defect severity taxonomy.
- [`decimo-hombre-adversarial.md`](references/decimo-hombre-adversarial.md): Adversarial stress-testing, the 5 false QA illusions, and pre-AAR scenarios.
- [`unified-test-report-schema.md`](references/unified-test-report-schema.md): Machine-readable JSON schema specification for CI/CD gates.
- [`5-investigation-angles-lifecycle-qa.md`](references/5-investigation-angles-lifecycle-qa.md): 5 strategic investigation angles across Plan, Refine, Test, Fix, Implement, and Install.
