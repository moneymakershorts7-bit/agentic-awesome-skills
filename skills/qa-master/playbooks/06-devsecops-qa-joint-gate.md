# Playbook 06: Joint DevSecOps & QA Master CI/CD Gate

This playbook defines the unified integration pipeline combining **`devsecops-master`** (Security & Supply Chain Assurance) with **`qa-master`** (Functional, Non-Functional & Behavioral Verification).

---

## 1. The Twin-Engine Software Assurance Architecture

```
                                [PULL REQUEST OPENED]
                                          │
                 ┌────────────────────────┴────────────────────────┐
                 ▼                                                 ▼
     [ENGINE 1: DEVSECOPS MASTER]                         [ENGINE 2: QA MASTER]
     - Secret Scanning (Gitleaks)                         - Static Lint & Types
     - SAST (Semgrep, Ruff, Bandit)                       - Unit & Invariant Tests
     - SCA Vulnerability Reachability                     - Contract & API Schema Fuzzing
     - Pipeline Integrity (Pinned SHAs)                   - Component & Integration Tests
     - SBOM & Supply Chain Provenance                     - E2E Journeys (Playwright)
     - Cloud IaC & Container Hardening                    - Accessibility (axe-core WCAG)
                 │                                                 │
                 └────────────────────────┬────────────────────────┘
                                          │
                                          ▼
                       [UNIFIED CI SCORECARD & GATE EVALUATOR]
                                          │
                 ┌────────────────────────┴────────────────────────┐
                 │                                                 │
            [GATE PASS]                                       [GATE FAIL]
     - 0 Secrets Detected                              - Critical Security Vulnerability
     - 0 Critical/High Exploitable CVEs                - Any Broken Functional Test
     - 100% Functional Tests Pass                      - Flaky Test Detected without Quarantine
     - p95 Latency within SLA                          - WCAG Critical Accessibility Defect
     - Mutation Score >= 70%                           - p95 Latency Regression > 50%
                 │                                                 │
                 ▼                                                 ▼
        [AUTO-MERGE APPROVED]                            [PR MERGE BLOCKED]
        (Deploy to Staging)                              (Actionable Diagnostic Comment)
```

---

## 2. CI/CD Pipeline Orchestration Script

A unified GitHub Actions / GitLab CI workflow executing both skills:

```yaml
name: "SecSDLC & Quality Gate (devsecops + qa)"

on:
  pull_request:
    branches: [ main, master ]
  push:
    branches: [ main, master ]

jobs:
  software_assurance:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0

      - name: Setup Runtimes (Python & Node)
        uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c # v5.0.0
        with:
          python-version: '3.11'

      # ==============================================================
      # ENGINE 1: DevSecOps Master Security Audit
      # ==============================================================
      - name: Run DevSecOps Master Audit
        run: |
          python3 ~/.agents/skills/devsecops-master/scripts/devsecops_audit.py . --output reports/security_audit.json
          python3 ~/.agents/skills/devsecops-master/scripts/verify_pipeline_integrity.py .

      # ==============================================================
      # ENGINE 2: QA Master Automated Verification
      # ==============================================================
      - name: Run QA Master Orchestrator
        run: |
          python3 ~/.agents/skills/qa-master/scripts/qa_orchestrator.py --run-all . --output-dir reports/qa/
          python3 ~/.agents/skills/qa-master/scripts/mutation_check.py --repo . --threshold 70 --output reports/qa/mutation_report.json

      # ==============================================================
      # UNIFIED REPORTING & GATE EVALUATION
      # ==============================================================
      - name: Consolidate Unified PR Comment
        if: always()
        run: |
          python3 ~/.agents/skills/qa-master/scripts/qa_reporter.py \
            --qa-results reports/qa/qa_results.json \
            --security-results reports/security_audit.json \
            --output reports/unified_assurance_comment.md
```

---

## 3. Failure Resolution SLA & Ownership

| Failure Type | Primary Skill | Triaged By | SLA |
| :--- | :--- | :--- | :--- |
| **Leaked Secret** | `devsecops-master` | Security Champion | Immediate (< 1 hr) |
| **Critical CWE (SQLi/RCE)** | `devsecops-master` | Security / Backend | Immediate (< 4 hrs) |
| **Functional Test Regression** | `qa-master` | Feature Author | Pre-merge blocker |
| **Flaky Test Appearance** | `qa-master` | SDET / Author | Immediate quarantine, fix in sprint |
| **Mutation Score Drop** | `qa-master` | Feature Author | Add missing test assertions |
| **Accessibility Defect** | `qa-master` | Frontend Author | Fix before release |
