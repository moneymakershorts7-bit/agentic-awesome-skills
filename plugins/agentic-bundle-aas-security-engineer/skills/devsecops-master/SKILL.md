---
name: devsecops-master
description: Master-grade DevSecOps and SecSDLC orchestrator integrating NIST SSDF, OWASP SAMM, SLSA L1-L3, threat modeling, CI/CD quality gates, and adversarial defense across all tech stacks.
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

# DevSecOps Master: Secure Software Development Life Cycle (SecSDLC)

DevSecOps is not a collection of blocking scanners or compliance check-boxes; it is **automated, ambient, continuous software assurance** embedded directly into the engineering workflow, from initial architectural design to production runtime defense (*"Shift-Left and Shield-Right"*).

This master skill operationalizes the industry's leading treatises (Vehent, Bell, Shostack, Wilson, Hughes & Turner) and standards (NIST SP 800-218 SSDF v1.1, OWASP SAMM v2, SLSA v1.0), fortified with **El Décimo Hombre** adversarial stress-testing to eliminate blind spots, false-positive fatigue, and supply chain poisoning.

---

## When to Use This Skill

Invoke `devsecops-master` whenever you need to:
1. **Audit or Onboard a Project:** Assess any repository's security posture and generate a tailored SecSDLC adoption plan across its tech stack (Node/TS, Python, Go, Rust, Java, C#, Docker, Kubernetes, Terraform, or AI Agents).
2. **Execute Threat Modeling:** Run a structured STRIDE-per-element or PASTA threat modeling session before architectural changes or new feature releases.
3. **Design or Hardened CI/CD Pipelines:** Build tamper-proof GitHub Actions or GitLab CI pipelines with SHA-pinned actions, minimal OIDC token permissions, automated SARIF reporting, and zero-trust runner security.
4. **Implement Shift-Left Quality Gates:** Configure pre-commit secret scanning (Gitleaks), semantic SAST (Semgrep, Ruff, Bandit, GoSec), SCA (Trivy, OSV-Scanner), and IaC checks (Checkov, Hadolint) with strict blocker thresholds.
5. **Secure the Software Supply Chain:** Generate machine-readable SBOMs (CycloneDX/SPDX), sign artifacts keylessly (Cosign/Sigstore), and produce verifiable SLSA Level 2/3 provenance.
6. **Triage Vulnerabilities Deterministically:** Prioritize CVEs using empirical reachability, CISA Known Exploited Vulnerabilities (KEV), and Exploit Prediction Scoring System (EPSS) to avoid alert fatigue.
7. **Close Incident Feedback Loops:** Convert production vulnerabilities, penetration test findings, or red-team reports into permanent, automated CI regression tests.

---

## The 7-Stage Universal SecSDLC Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       UNIVERSAL SecSDLC ARCHITECTURE                        │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
  ┌───────────────────────────────────┼───────────────────────────────────┐
  ▼                                   ▼                                   ▼
[Stage 1: Governance & Policy]   [Stage 2: Threat Modeling]      [Stage 3: Secure Coding]
- Asset Tiering (Tiers 0-2)       - STRIDE / PASTA Analysis       - Pre-commit Hooks (Gitleaks)
- ASVS Baseline Selection         - Evil User / Abuse Stories     - IDE Semantic Linters
- Policy-as-Code (OPA/Rego)       - Auth & Cryptographic NFRs     - Sensitive File Git Blocker
  │                                   │                                   │
  └───────────────────────────────────┼───────────────────────────────────┘
                                      │
  ┌───────────────────────────────────┼───────────────────────────────────┐
  ▼                                   ▼                                   ▼
[Stage 4: CI/CD Pipeline Gating] [Stage 5: Pre-Deployment Verify][Stage 6: Runtime Defense]
- Fast PR Gate (<8 min): SAST/SCA - Dynamic DAST (OWASP ZAP/AF)   - Kernel eBPF Telemetry (Falco)
- Secrets Scan (Zero tolerance)   - Contract API Fuzzing          - WAF / RASP & DDoS Defense
- CycloneDX SBOM + Cosign Sign    - Admission Control (Kyverno)   - Zero Trust mTLS Mesh
- SLSA L2/L3 Provenance           - Non-root / Read-only rootfs   - Least-Privilege IAM
  │                                   │                                   │
  └───────────────────────────────────┼───────────────────────────────────┘
                                      │
                                      ▼
                   [Stage 7: Monitoring & Feedback Loop]
                   - Risk-Weighted Triage (EPSS + KEV + Reachability)
                   - Strict Remediation SLAs (Critical <24h)
                   - Blameless Post-Mortem Regression Closure
```

For complete phase details, consult [`references/secsdlc-7-stages.md`](references/secsdlc-7-stages.md).

---

## Core Decision Heuristics & Quality Gates

### 1. The 8-Minute PR Rule
PR-blocking security checks MUST complete in under 8 minutes. Heavyweight scans (deep inter-procedural taint analysis, whole-history scans, fuzzing) must run asynchronously out-of-band to prevent developer velocity collapse.

### 2. Quality Gate Enforcement Thresholds
* **Blocker (Exit Code 1 / PR Block):**
  - **Secrets:** Any verified API key, private key, or cloud token detected.
  - **SAST:** Critical/High severity CWE Top 25 (SQLi, Command Injection, SSRF, Deserialization).
  - **SCA:** Critical CVE with known public exploit (CISA KEV or EPSS > 0.10) AND an available patch.
  - **IaC:** Public exposure of internal ports (`0.0.0.0/0`), unencrypted storage, or wildcard admin IAM.
  - **Pipeline:** Any third-party GitHub Action referenced by mutable tag (`@v2`, `@main`) instead of full commit SHA.
* **Warning (Exit Code 0 / Annotate PR):**
  - Medium/Low severity vulnerabilities without active exploits.
  - Vulnerabilities in development dependencies (`devDependencies`, `test/`).
  - Missing non-critical HTTP security headers on preview/staging deployments.

### 3. Vulnerability Triage Priority Formula
Prioritize remediation by active exploitability, not theoretical CVSS severity alone:

$$\text{Priority} = f(\text{CISA KEV}, \text{EPSS}, \text{Reachability}, \text{CVSS})$$

| Condition | Priority | Remediation SLA |
| :--- | :--- | :--- |
| In CISA KEV (Known Exploited) | **Emergency Hotfix** | $< 24$ hours |
| EPSS $> 0.10$ + Reachable in Code + CVSS $\ge 7.0$ | **Critical** | $< 7$ days |
| Reachable in Code + CVSS $\ge 9.0$ | **High** | $< 14$ days |
| Unreachable (VEX `not_affected`) OR EPSS $< 0.05$ | **Low / Backlog** | Next sprint cycle |

Consult [`references/quality-gates-and-sarif.md`](references/quality-gates-and-sarif.md) for SARIF normalization and VEX schemas.

---

## El Décimo Hombre Adversarial Defenses

Standard DevSecOps often degrades into "compliance theater." This skill enforces 3 non-negotiable adversarial hardening tripwires derived from `el-decimo-hombre`:

1. **Anti-Poisoning Runner Gate:** Never execute third-party CI actions pinned to mutable tags. All actions must use full 40-character commit SHAs with explicit inline version comments. All workflows must declare restrictive top-level `permissions: contents: read`.
2. **Anti-Evasion Gate:** Automated blocks against inline scanner suppressions (`// nosec`, `@SuppressWarnings`, `# pragma: allowlist`). Introducing suppressions requires a dual Principal Architect review and written threat model rationale.
3. **Architecture Authorization Gate:** Automated static scanners cannot detect Broken Object Level Authorization (IDOR) or transaction race conditions. Any PR modifying authentication, authorization middleware, or multi-tenant database queries requires a designated threat modeling checklist.

Consult [`references/decimo-hombre-adversarial.md`](references/decimo-hombre-adversarial.md) for full pre-AAR scenarios and attack vector analyses.

---

## Bundled Deterministic Utilities

This skill includes zero-dependency automation scripts in `scripts/`:

* **`devsecops_audit.py`**: Autodetects project tech stacks, verifies existing security controls (secrets, SAST, SCA, IaC, CI hardening, Dockerfile configs), and produces an audit scorecard with remediation steps:
  ```bash
  python3 scripts/devsecops_audit.py /path/to/project --format markdown
  ```
* **`verify_pipeline_integrity.py`**: Scans GitHub Actions workflows for mutable action tags, insecure permissions, and codebases for illicit suppression directives:
  ```bash
  python3 scripts/verify_pipeline_integrity.py /path/to/project
  ```
* **`sarif_aggregator.py`**: Aggregates disparate SARIF reports from Trivy, Semgrep, Checkov, and Bandit into a unified PR-blocking summary:
  ```bash
  python3 scripts/sarif_aggregator.py --inputs semgrep.sarif trivy.sarif --output scorecard.json
  ```
* **`python_master_gate.py`**: Executes the deterministic Python Master SecSDLC quality gate (Bandit SAST, pip-audit SCA, Mypy Strict, Ruff, Radon CC <= 10, Vulture):
  ```bash
  python3 scripts/python_master_gate.py /path/to/project --format markdown
  ```
* **`rust_master_gate.py`**: Executes the deterministic Rust Master SecSDLC quality gate (Clippy Pedantic SAST, Cargo Audit SCA, rust-master AST Safety Invariants, Cargo Test):
  ```bash
  python3 scripts/rust_master_gate.py /path/to/project --format markdown
  ```

---

## Operational Playbooks

Step-by-step operational workflows:
- [01: Project Onboarding & Baseline Audit](playbooks/01-project-onboarding.md)
- [02: 60-Minute Threat Modeling Sprint](playbooks/02-threat-modeling-sprint.md)
- [03: CI/CD Pipeline Gating Setup](playbooks/03-pipeline-gating-setup.md)
- [04: Risk-Weighted Vulnerability Triage](playbooks/04-vulnerability-triage.md)
- [05: Incident Feedback Loop Closure](playbooks/05-incident-feedback-loop.md)
- [06: Python Master Autonomous SecSDLC Quality Gate](playbooks/06-python-master-secsdlc.md)
- [07: Rust Master Autonomous SecSDLC Quality Gate](playbooks/07-rust-master-secsdlc.md)

---

## Detailed References

- [Literature & Authoritative Standards](references/literature-and-standards.md)
- [The 7-Stage Universal SecSDLC](references/secsdlc-7-stages.md)
- [El Décimo Hombre Adversarial Directives](references/decimo-hombre-adversarial.md)
- [Tooling Matrix Across Tech Stacks](references/tooling-and-stacks.md)
- [Quality Gates & SARIF Normalization](references/quality-gates-and-sarif.md)
- [CI/CD Hardening Templates (GitHub Actions & GitLab CI)](references/ci-cd-hardening-templates.md)
- [Threat Modeling Templates (STRIDE & PASTA)](references/threat-modeling-guide.md)
