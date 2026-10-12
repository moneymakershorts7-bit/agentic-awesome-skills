# DevSecOps Literature & Authoritative Standards Reference

This document encapsulates the distilled wisdom of foundational DevSecOps literature and global regulatory frameworks.

---

## 1. Seminal Literature & Expert Treatises

### 1.1 "Securing DevOps: Security in the Cloud" — Julien Vehent (Mozilla)
* **Core Thesis:** Security is an automated quality attribute. If an organization cannot express security controls as automated code and telemetry within the CI/CD pipeline, it cannot secure modern distributed systems.
* **The Three Pillars:**
  1. *Continuous Integration & Testing:* Pre-commit checks, automated unit/integration security tests, deterministic dependency vulnerability auditing.
  2. *Continuous Deployment & Pipeline Hardening:* Zero-trust deployment workers, ephemeral credentials, immutable infrastructure.
  3. *Continuous Monitoring & Operations:* Audit trail preservation, real-time alerting, host/network-level telemetry.
* **Secret Management Doctrine:** Persistent secrets in git or baked into disk images represent a structural failure. Employ just-in-time credential brokers with dynamic leasing and automated rotation.

### 1.2 "Agile Application Security" — Laura Bell, Michael Brunton-Spall, Rich Smith, Jim Bird
* **Core Thesis:** Security practices that create friction or delay sprint velocity will be circumvented. Security must operate within Agile ceremonies and user backlogs.
* **Key Innovations:**
  - *Evil User Stories / Abuser Stories:* Formulating threat vectors as standard user stories: *"As an unauthorized actor, I want to tamper with API parameters so that I can view another tenant's private records."*
  - *Security Acceptance Criteria:* Non-negotiable security definitions of "Done" embedded in sprint backlogs.
  - *Security Champions:* Training a network of developers (10-15% of engineering staff) to conduct first-line threat assessments and code reviews.

### 1.3 "Threat Modeling: Designing for Security" — Adam Shostack
* **Core Thesis:** Finding a structural vulnerability in production costs two orders of magnitude more than addressing it during design. Threat modeling is a foundational engineering discipline, not an AppSec luxury.
* **The 4 Essential Questions:**
  1. What are we building? (System decomposition, DFDs, Trust Boundaries).
  2. What can go wrong? (Threat elicitation using STRIDE).
  3. What are we going to do about it? (Mitigations: Redesign, standard controls, input validation, encryption).
  4. Did we do a good enough job? (Retrospectives, continuous threat model updates).

### 1.4 "DevSecOps: A Leader's Guide" — Glenn Wilson
* **Core Thesis:** Successful DevSecOps is 80% culture and 20% tooling. Tooling without psychological safety results in developer evasion and alert fatigue.
* **Key Concepts:**
  - *Westrum Generative Culture:* Fostering a high-trust, blame-free environment where security incidents trigger root-cause learning rather than punishment.
  - *DORA Metric Alignment:* Security gates must not degrade Deployment Frequency (DF) or Lead Time for Changes (LTFC). Maintain strict scan time budgets ($< 8$ minutes).

### 1.5 "Software Transparency: Supply Chain Security" — Chris Hughes & Tony Turner
* **Core Thesis:** Modern software is assembled, not written. 80-90% of codebases consist of third-party open-source components. True security requires total software supply chain transparency.
* **Key Concepts:**
  - *SBOM Standards:* CycloneDX (OWASP) for security triage and dependency tracking; SPDX (Linux Foundation) for licensing and component metadata.
  - *VEX (Vulnerability Exploitability eXchange):* Contextual declarations indicating whether an upstream CVE is truly reachable and exploitable in the target execution runtime.
  - *Cryptographic Provenance:* Cryptographically signed attestations (Sigstore, Cosign, in-toto) confirming that released binaries match verified source code and trusted builders.

---

## 2. Authoritative Standards & Frameworks

### 2.1 NIST SP 800-218: Secure Software Development Framework (SSDF v1.1)

| Practice Group | Code | Core Invariant | Key Automation Artifact |
| :--- | :--- | :--- | :--- |
| **Prepare the Organization (PO)** | PO.1–PO.5 | Define organizational security policies, roles, toolchains, and quality gate criteria. | Policy-as-Code repository, Security Champion charters, hardened devcontainers. |
| **Protect the Software (PS)** | PS.1–PS.3 | Protect code from unauthorized tampering and guarantee release integrity. | Branch protection rules, signed commits, Cosign keyless signatures, tamper-evident logs. |
| **Produce Well-Secured Software (PW)** | PW.1–PW.9 | Design secure software, verify third-party libraries, follow secure coding standards. | Threat modeling DFDs, automated SAST PR gates, SCA scans, compiler hardening flags. |
| **Respond to Vulnerabilities (RV)** | RV.1–RV.3 | Continuously ingest vulnerability data, prioritize remediation, and perform root-cause retrospectives. | CISA KEV feeds, EPSS scoring triage, blameless post-mortem regression checks. |

### 2.2 OWASP SAMM v2.0 (Software Assurance Maturity Model)
Five Business Functions across three maturity levels:
1. **Governance:** Strategy & Metrics, Policy & Compliance, Education & Guidance.
2. **Design:** Threat Assessment, Security Requirements, Security Architecture.
3. **Implementation:** Secure Build, Secure Deployment, Defect Management.
4. **Verification:** Architecture Validation, Requirements-Driven Testing, Security Testing.
5. **Operations:** Incident Management, Environment Management, Operational Management.

* **Level 1 (Ad-hoc):** Basic awareness, reactive scanning, ad-hoc patching.
* **Level 2 (Standardized):** Structured policies, automated PR gates, centralized tracking.
* **Level 3 (Optimized):** Continuous self-healing pipelines, SLSA L3 build hermeticity, real-time runtime eBPF defense.

### 2.3 SLSA v1.0 (Supply-chain Levels for Software Artifacts)
- **Level 1 (Build Automation):** Build process is automated and generates basic provenance.
- **Level 2 (Hosted Build & Signed Provenance):** Build runs on hosted CI service; provenance is cryptographically signed by the hosted builder platform.
- **Level 3 (Hardened Isolated Build):** Ephemeral single-use build runners, hermetic compilation (no undeclared external internet network calls during build), immutable build definitions strictly sourced from git.
