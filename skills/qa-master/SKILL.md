---
name: qa-master
description: Master Quality Code Assurance Agent adhering to the 6-layer software standards hierarchy (ISO 9001/27001/12207/25010/5055/29119, SOC 2, NIST SSDF, ASVS, SonarQube Clean Code) with twin-engine DevSecOps integration.
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

`qa-master` operationalizes the industry's holistic **6-Layer Software Standards Hierarchy** (ISO 9001, ISO 27001, SOC 2, CMMI v3.0, ISO 12207, ISO 25010, ISO 5055, IEEE 1016, ISO 29119, NIST SSDF, OWASP ASVS, SEI CERT, MISRA, and SonarQube Clean Code gates). Operating alongside `devsecops-master`, `qa-master` forms the complete, self-healing **Twin-Engine Assurance Suite** for modern enterprise engineering.

---

## The 6-Layer Software Standards Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. GOBERNANZA, CALIDAD DE PROCESOS Y SEGURIDAD ORGANIZACIONAL                           │
│    ISO 9001:2015 | ISO/IEC 27001:2022 (8.25-8.32) | SOC 2 Type II | CMMI v3.0 | ISO 22301 │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. CICLO DE VIDA, OPERACIONES Y GESTIÓN DE SERVICIOS (SDLC)                             │
│    ISO/IEC/IEEE 12207:2026 | ISO/IEC 20000 / ITIL v4 | ISO/IEC 29110 (VSE Profile)        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. CALIDAD DEL PRODUCTO Y ARQUITECTURA DE SISTEMAS                                      │
│    ISO/IEC 25010 (SQuaRE) | ISO/IEC 5055 (CISQ 148 Rules) | IEEE 1016:2009 | C4 Model   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. PRUEBAS, VALIDACIÓN Y VERIFICACIÓN (TESTING)                                         │
│    ISO/IEC/IEEE 29119 (1-5) | ISTQB | TMap | Test Pyramid | Mutation (MSI >= 80%)       │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 5. CICLO DE VIDA DE DESARROLLO SEGURO (SSDLC)                                           │
│    NIST SP 800-218 (SSDF v1.1) | OWASP SAMM v2 | OWASP ASVS v4.0.3 | SLSA Level 1-4    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 6. NORMAS DE CODIFICACIÓN Y ANÁLISIS ESTÁTICO DETERMINÍSTICO                            │
│    SEI CERT | MISRA C/C++:2023 | SonarQube Clean Code Quality Gate | McCabe CC <= 10     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

For complete clause mappings, formulas, and metric thresholds, consult [`references/01-enterprise-standards-hierarchy.md`](references/01-enterprise-standards-hierarchy.md).

---

## When to Use This Skill

Invoke `qa-master` whenever you need to:
1. **Audit Enterprise Standards Compliance:** Generate and verify machine-readable manifests (`.audit/rtm_manifest.json`, `.audit/peer_review_manifest.json`, `.audit/cm_manifest.json`, `.audit/soc2_change_record.json`).
2. **Enforce Static Architecture Fitness (ISO 5055 & Clean Code):** Verify that McCabe Cyclomatic Complexity $\le 10$, Cognitive Complexity $\le 15$, Nesting Depth $\le 4$, and file lengths $\le 500$ LOC.
3. **Verify API Schema Contracts:** Validate OpenAPI 3.1 and AsyncAPI specifications for breaking drift using Spectral and Schemathesis.
4. **Execute the Automated Test Pyramid:** Discover and run Unit (~70%), Integration (~20%), and Contract/E2E (~10%) test suites.
5. **Evaluate Assertion Quality via Mutation Testing:** Run Stryker, Mutmut, Pitest, or Infection to enforce a Mutation Score Indicator ($\text{MSI} \ge 80\%$).
6. **Detect and Quarantine Flaky Tests:** Execute variance-stress runs (minimum 10 iterations) to detect non-deterministic tests and isolate them from blocking CI.
7. **Audit Non-Functional Latency & Accessibility:** Run k6 smoke tests (P95 latency $\le 200\text{ms}$) and axe-core WCAG 2.2 AA accessibility audits.
8. **Enforce Twin-Engine Convergence Gate:** Aggregate all QA and DevSecOps findings into `.audit/unified_quality_scorecard.json` with unconditional pull request veto power.

---

## The Orchestrator-Worker Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                   QA Lead Orchestrator & Task Decomposer (`qa-lead`)                    │
│   • Bounded Functional Slicing Engine (1 slice at a time)                               │
│   • Task + Playbook Contract Enforcer (Zero Ambiguity)                                  │
│   • 6-Layer Standards Compliance Governor                                              │
└────────────────────────────────────────────┬────────────────────────────────────────────┘
                                             │ Dispatches Decoupled Tasks
                    ┌────────────────────────┼────────────────────────┐
                    ▼                        ▼                        ▼
     ┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
     │  Worker 1: Governance   │ │  Worker 2: Architecture │ │   Worker 3: Dynamic     │
     │     & Process Audit     │ │    & Interface Fitness  │ │    Test Automation      │
     │  (ISO 9001, 27001,      │ │  (ISO 25010, ISO 5055,  │ │  (ISO 29119, Pyramid,   │
     │   SOC 2, CMMI, 12207)   │ │   IEEE 1016, C4, Arch)  │ │   Mutation, Property)   │
     └─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
                    │                        │                        │
                    ▼                        ▼                        ▼
     ┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
     │  Worker 4: Flaky Test   │ │ Worker 5: Non-Functional│ │      TWIN-ENGINE:       │
     │   & Chaos Resilience    │ │   Performance & A11y    │ │    devsecops-master     │
     │ (Quarantine, Stress,    │ │ (k6 Latency, Memory,    │ │ (ASVS, SAST, SBOM,      │
     │  Fault Injection)       │ │  Axe-Core WCAG 2.2 AA)  │ │  Cosign, Container)     │
     └─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
                    │                        │                        │
                    └────────────────────────┼────────────────────────┘
                                             │ Emits Verification Artifacts (.audit/*.json)
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│           Independent Adversarial Quality Gatekeeper (`qa-verifier-adversary`)          │
│   • Unconditional Pull Request Veto Power (Non-negotiable Gate)                         │
│   • ISO 5055 Automated Measure Audit (Zero Blocker/Critical)                            │
│   • SonarQube Clean Code Gate (CC <= 10, Duplication < 3%, Line Cov >= 80%)            │
│   • SARIF 2.1.0 Multi-Engine Aggregator & Machine Attestation Signer                    │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Decision Heuristics & Quality Gates

### 1. The 5-Minute PR Rule
Pull request test gating suites MUST complete execution in under 5 minutes. Heavyweight performance soak tests, whole-history visual audits, and mutation matrices must run asynchronously out-of-band or in scheduled nightly pipelines to protect developer velocity.

### 2. Gating Threshold Enforcement

| Test Dimension | Blocker Threshold (Exit Code 1 / Block PR) | Warning Threshold (Exit Code 0 / Annotate PR) |
| :--- | :--- | :--- |
| **Requirements (RTM)** | $\text{Coverage} < 100.0\%$ on documented user stories | Minor documentation formatting warning |
| **Peer Review** | Author approved own PR (Two-Person Rule violation) | Reviewer response latency $> 24\text{ hours}$ |
| **Functional Tests** | Any test failure in Unit, Contract, Integration, or E2E suites | Skipped tests marked with `@todo` or `@pending` |
| **Flaky Tests** | Flake rate $> 0\%$ in blocking suite (must quarantine) | Flake rate $> 0\%$ in non-blocking quarantine suite |
| **Mutation Score** | $\text{MSI} < 80\%$ on modified code or critical domain modules | $\text{MSI} < 85\%$ on secondary utility modules |
| **Complexity (CC)** | McCabe $\text{CC} > 10$ OR Cognitive Complexity $> 15$ | McCabe $\text{CC}$ between $8 - 10$ |
| **Nesting Depth** | Indentation depth $> 4$ levels | Indentation depth equal to 4 levels |
| **Accessibility** | $\ge 1$ Critical or Serious WCAG 2.2 AA violation | Minor or Moderate contrast / layout warnings |
| **Performance** | Error rate $\ge 0.1\%$ OR p95 latency regressed $> 50\%$ | p95 latency regressed between $20\% - 50\%$ |

---

## Automated Tooling & Scripts

The skill provides production CLI tools located in `~/.agents/skills/qa-master/scripts/`:

### 1. QA Master Convergence Gate
Aggregates QA and DevSecOps SARIF logs, evaluates all 6 layers, outputs `.audit/unified_quality_scorecard.json`, and exits 0 on PASS, 1 on FAIL:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_master_gate.py .audit/
```

### 2. Governance Auditor
Audits the Requirements Traceability Matrix (RTM) and enforces the Two-Person Rule:
```bash
python3 ~/.agents/skills/qa-master/scripts/governance_auditor.py --audit-rtm . --output .audit/rtm_manifest.json
python3 ~/.agents/skills/qa-master/scripts/governance_auditor.py --verify-peer-review .audit/peer_review_manifest.json
```

### 3. Architecture Fitness & Code Quality Checker
Evaluates Cyclomatic Complexity (CC $\le 10$), Nesting Depth ($\le 4$), and file length ($\le 500$ LOC):
```bash
python3 ~/.agents/skills/qa-master/scripts/architecture_fitness_checker.py --check-complexity . --max-cc 10 --max-nesting 4 --output .audit/complexity_audit.json
```

### 4. Unified QA Orchestrator
Auto-detects test frameworks, executes suites, and aggregates results into `.audit/test_summary_report.json`:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_orchestrator.py --run-all . --output-dir .audit/
```

### 5. Flaky Test Detector & Variance Profiler
Runs candidate test commands $N$ times to detect non-deterministic flakes:
```bash
python3 ~/.agents/skills/qa-master/scripts/flaky_detector.py --cmd "pytest tests/" --runs 10
```

### 6. Mutation Testing Quality Evaluator
Mutates AST operators and conditions to verify that test suites catch injected defects ($\text{MSI} \ge 80\%$):
```bash
python3 ~/.agents/skills/qa-master/scripts/mutation_check.py --file src/calc.py --test-cmd "pytest tests/" --threshold 80
```

---

## Playbooks Directory Index

- [`01-project-qa-onboarding.md`](playbooks/01-project-qa-onboarding.md): Inspecting an unfamiliar codebase and establishing test baselines.
- [`02-exploratory-session-charter.md`](playbooks/02-exploratory-session-charter.md): Executing Session-Based Exploratory Testing with FEW HICCUPPS oracles.
- [`03-automated-test-pyramid-execution.md`](playbooks/03-automated-test-pyramid-execution.md): Layered execution across Unit, Contract, Integration, and E2E.
- [`04-flaky-test-quarantine-and-triage.md`](playbooks/04-flaky-test-quarantine-and-triage.md): Flake detection, isolation quarantine, and root-cause repair.
- [`05-performance-and-load-gating.md`](playbooks/05-performance-and-load-gating.md): k6 smoke and sustained load testing with strict latency SLAs.
- [`06-devsecops-qa-joint-gate.md`](playbooks/06-devsecops-qa-joint-gate.md): Twin-engine deployment pipeline combining `devsecops-master` and `qa-master`.
- [`07-iso-governance-rtm-audit.md`](playbooks/07-iso-governance-rtm-audit.md): Requirements traceability matrix, two-person rule, and SOC 2 / ISO 27001 change manifests.
- [`08-architecture-fitness-and-iso5055.md`](playbooks/08-architecture-fitness-and-iso5055.md): CISQ source code rules, Cyclomatic Complexity $\le 10$, and OpenAPI contract checks.

---

## References Directory Index

- [`01-enterprise-standards-hierarchy.md`](references/01-enterprise-standards-hierarchy.md): Comprehensive 6-layer software standards guide with exact clauses and metrics.
- [`02-architecture-and-fitness-rules.md`](references/02-architecture-and-fitness-rules.md): ISO 25010/5055 CISQ 148 rules, IEEE 1016 viewpoints, and ArchUnit/TsArch fitness functions.
- [`03-iso-29119-test-process-and-schemas.md`](references/03-iso-29119-test-process-and-schemas.md): ISO/IEC/IEEE 29119 Parts 1–5, Test Pyramid, Mutation Testing ($\text{MSI} \ge 80\%$), and JSON report schemas.
- [`04-twin-engine-devsecops-integration.md`](references/04-twin-engine-devsecops-integration.md): Twin-Engine SARIF aggregation, ASVS L1–L3 convergence, and PR veto architecture.
- [`literature-and-canon.md`](references/literature-and-canon.md): Deep synthesis of Khorikov, Crispin & Gregory, Hendrickson, Bach, Meszaros, Newman.
- [`test-automation-matrix.md`](references/test-automation-matrix.md): Toolchain configurations for Playwright, Cypress, Vitest, Pact, k6, axe-core.
- [`exploratory-heuristics-and-oracles.md`](references/exploratory-heuristics-and-oracles.md): SFDIPOT product breakdown, FEW HICCUPPS oracles, defect severity taxonomy.
- [`decimo-hombre-adversarial.md`](references/decimo-hombre-adversarial.md): Adversarial stress-testing, the 5 false QA illusions, and pre-AAR scenarios.
- [`unified-test-report-schema.md`](references/unified-test-report-schema.md): Machine-readable JSON schema specification for CI/CD gates.
- [`5-investigation-angles-lifecycle-qa.md`](references/5-investigation-angles-lifecycle-qa.md): 5 strategic investigation angles across Plan, Refine, Test, Fix, Implement, and Install.
