# Enterprise Standards Hierarchy: The 6-Layer Software Quality Framework

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. GOVERNANCE, PROCESS QUALITY & ORGANIZATIONAL SECURITY                                │
│    ISO 9001:2015 | ISO/IEC 27001:2022 (8.25-8.32) | SOC 2 Type II | CMMI v3.0 | ISO 22301 │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. SDLC, OPERATIONS & IT SERVICE MANAGEMENT                                             │
│    ISO/IEC/IEEE 12207:2026 | ISO/IEC 20000 / ITIL v4 | ISO/IEC 29110 (VSE Profile)        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. PRODUCT QUALITY & SYSTEM ARCHITECTURE INTEGRITY                                      │
│    ISO/IEC 25010 (SQuaRE) | ISO/IEC 5055 (CISQ Code Rules) | IEEE 1016 | C4 Model       │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. SOFTWARE TESTING, VERIFICATION & VALIDATION                                          │
│    ISO/IEC/IEEE 29119 (1-5) | ISTQB | TMap | Test Pyramid | Mutation (MSI >= 80%)       │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 5. SECURE SOFTWARE DEVELOPMENT LIFE CYCLE (SSDLC)                                       │
│    NIST SP 800-218 (SSDF v1.1) | OWASP SAMM v2 | OWASP ASVS v4.0.3 | SLSA Level 1-4    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ 6. CODE-LEVEL STANDARDS & DETERMINISTIC STATIC ANALYSIS                                 │
│    SEI CERT | MISRA C/C++:2023 | SonarQube Clean Code Quality Gate | McCabe CC <= 10     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Governance, Process Quality & Organizational Security

### 1. ISO 9001:2015 (Quality Management Systems - QMS)
- **Clause 7.5 (Documented Information):** All technical specifications, architectures, and test designs must be version-controlled with cryptographic commit provenance.
- **Clause 8.1 (Operational Planning and Control):** Defined quality criteria and acceptance gates prior to execution.
- **Clause 8.2 (Requirements for Products and Services):** Complete, unambiguous, verifiable stakeholder requirements.
- **Clause 8.3 (Design and Development Controls):** Formal verification (does the output match input requirements?) and validation (does the software fulfill its intended use?).
- **Clause 8.5.2 (Identification and Traceability):** Bi-directional **Requirements Traceability Matrix (RTM)** linking:
  $$\text{User Story} \longleftrightarrow \text{System Requirement} \longleftrightarrow \text{Architecture Node} \longleftrightarrow \text{Source Code AST} \longleftrightarrow \text{Unit/Integration Test}$$
  - *Automated Gate:* `.audit/rtm_manifest.json` must achieve `traceability_coverage_pct == 100.0`.
- **Clause 8.7 & 10.2 (Nonconforming Outputs & Corrective Action):** Systematic defect logging and automated root-cause analysis (5-Whys).

### 2. ISO/IEC 27001:2022 (Information Security Management Systems - ISMS)
Annex A Controls 8.25 through 8.32 establish mandatory software development security controls:
- **Control 8.25 (Secure Development Life Cycle):** Continuous security gates integrated into CI/CD pipelines (pre-commit secret linting, SAST, SCA, container signing).
- **Control 8.26 (Application Security Requirements):** Formal STRIDE threat models and security non-functional requirements (NFRs) codified in `.audit/appsec_requirements.json`.
- **Control 8.27 (Secure System Architecture and Engineering Principles):** Zero-trust architecture, defense-in-depth, least-privilege RBAC, and container non-root execution (`USER 65534`).
- **Control 8.28 (Secure Coding):** Static Application Security Testing (SAST) enforcing zero critical and zero high-severity findings; mandatory compiler hardening flags (`-fstack-protector-strong -D_FORTIFY_SOURCE=2`).
- **Control 8.29 (Security Testing in Development and Acceptance):** Automated API fuzzing (Schemathesis, ZAP) and security regression tests in ephemeral staging.
- **Control 8.30 (Outsourced Development & Supply Chain):** Software Bill of Materials (SBOM) in CycloneDX 1.6 / SPDX 3.0 format, lockfile hash enforcement, and license compliance audits.
- **Control 8.31 (Separation of Development, Test, and Production Environments):** Complete data isolation; strict prohibition of live production PII in development or test environments; synthetic test data generation.
- **Control 8.32 (Change Management):** Immutable git commit lineage, signed tags, mandatory peer reviews, and automated rollback scripts.

### 3. SOC 2 Type II (Trust Services Criteria - CC Series)
- **CC6 (Logical and Physical Access):** Least privilege, cryptographic commit signatures (GPG/SSH), automated branch protection rules.
- **CC7 (System Operations):** Continuous observability, health probes, anomaly alerts, automated incident runbooks.
- **CC8 (Change Management):** Segregation of duties enforcing the **Two-Person Rule** (the author of a change cannot approve their own pull request). Automated gate verifies `.audit/peer_review_manifest.json`.
- **CC9 (Risk Mitigation):** Continuous dependency vulnerability scanning and business continuity validation.

### 4. CMMI v3.0 & ISO/IEC 33001 (SPICE / ASPICE 4.0)
- Process capability and organizational maturity levels 1 through 5.
- Key practice areas: Requirements Development & Management (RDM), Technical Solution (TS), Verification & Validation (VV), Peer Reviews (PR), Configuration Management (CM), and Causal Analysis & Resolution (CAR).

### 5. ISO 22301:2019/2024 & ITIL v4 (Continuity & Incident Governance)
- **RTO (Recovery Time Objective):** Maximum tolerable downtime (Tier 1 API $\le 15\text{ min}$).
- **RPO (Recovery Point Objective):** Maximum tolerable data loss (Transactions $= 0\text{ sec}$; synchronous replication).
- **ITIL v4 Incident Lifecycle:** P1 (Critical) to P4 (Informational) classification with automated post-incident review (PIR) generation.

---

## Layer 2: SDLC, Operations & IT Service Management

### 1. ISO/IEC/IEEE 12207:2026 (Systems and Software Engineering - Lifecycle Processes)
Defines universal technical processes:
1. Stakeholder Requirements Definition (Clause 6.4.2)
2. System/Software Requirements Definition (Clause 6.4.3)
3. Architecture Definition (Clause 6.4.4)
4. Design Definition (Clause 6.4.5)
5. System Analysis (Clause 6.4.6)
6. Implementation / Construction (Clause 6.4.7)
7. Integration (Clause 6.4.8)
8. Verification (Clause 6.4.9)
9. Transition / Deployment (Clause 6.4.10)
10. Validation (Clause 6.4.11)
11. Operation (Clause 6.4.12)
12. Maintenance (Clause 6.4.13)

### 2. ISO/IEC 29110 (Lifecycle Profiles for Very Small Entities - VSEs)
Eliminates enterprise document bloat by translating heavy waterfall artifacts into Git-native, machine-readable specifications:
- Project Management (PM) $\rightarrow$ `docs/project_plan.md` + automated CI milestones.
- Software Implementation (SI) $\rightarrow$ Architecture Decision Records (`docs/adr/`) + automated test suites.
- Verified via `.audit/vse_profile_manifest.json`.

---

## Layer 3: Product Quality & System Architecture Integrity

### 1. ISO/IEC 25010 (SQuaRE - System and Software Quality Models)
The 8 core product quality characteristics:
1. **Functional Suitability:** Completeness, correctness, appropriateness.
2. **Performance Efficiency:** Time behavior (P95 latency $\le 200\text{ms}$), resource utilization, capacity.
3. **Compatibility:** Co-existence, API interoperability.
4. **Usability & Accessibility:** Learnability, operability, user error protection, WCAG 2.2 AA accessibility via automated `axe-core`.
5. **Reliability:** Maturity, fault tolerance, availability, recoverability.
6. **Security:** Confidentiality, integrity, non-repudiation, accountability, authenticity.
7. **Maintainability:** Modularity, reusability, analyzability, modifiability, testability (MSI $\ge 80\%$).
8. **Portability:** Adaptability, installability, multi-platform container execution.

### 2. ISO/IEC 5055:2021 (Automated Source Code Quality Measures - CISQ)
148 automated rules mapped to CWE weaknesses across 4 architectural pillars:
- **Reliability:** Resource leaks (CWE-404, CWE-775), unhandled exceptions (CWE-391), thread safety/concurrency flaws (CWE-362, CWE-820).
- **Security:** Buffer errors (CWE-120), injection flaws (CWE-89, CWE-78), broken authentication (CWE-287).
- **Performance Efficiency:** Expensive loops in algorithms, unindexed database queries, blocking I/O on event loops.
- **Maintainability:** God classes, excessive cyclomatic complexity, high afferent/efferent coupling.

### 3. Architecture Documentation & Fitness Functions
- **IEEE 1016:2009:** 10 software design viewpoints documented in version-controlled ADRs.
- **C4 Model:** Context, Container, Component, and Code diagrams rendered with Mermaid.
- **Contract Testing:** OpenAPI 3.1 & AsyncAPI schema contracts validated with Spectral and Schemathesis.
- **Architecture Fitness Functions:** Automated tests (ArchUnit, TsArch, Deptrac) enforcing domain boundary rules and prohibiting circular dependencies.

---

## Layer 4: Software Testing, Verification & Validation

### 1. ISO/IEC/IEEE 29119 (Parts 1 to 5)
- **Part 1:** Concepts, definitions, and verification taxonomy.
- **Part 2:** Three-level test processes: Organizational, Test Management, Dynamic Testing.
- **Part 3:** Test documentation schemas: Test Policy, Test Strategy, Test Plan, Test Case Spec, Test Incident Report, Test Summary Report.
- **Part 4:** Test design techniques (Equivalence Partitioning, Boundary Value Analysis, Decision Tables, State Transitions, MC/DC).
- **Part 5:** Keyword-Driven Testing conventions.

### 2. The Test Pyramid & Modern Verification Invariants
- **Pyramid Distribution:** Unit Tests (~70%), Integration Tests (~20%), Contract & E2E (~10%).
- **Mutation Testing (Efficacy Metric):** Mutation Score Indicator ($\text{MSI} \ge 80\%$) via Stryker, Pitest, Mutmut, or Infection.
- **Property-Based Testing:** Invariant validation over thousands of generated inputs (Hypothesis, fast-check).
- **Flaky Test Quarantine:** 10x variance execution isolating non-deterministic tests from blocking production gates.
- **Chaos & Fault Injection:** Simulated network drops, process termination, and memory pressure.

---

## Layer 5: Secure Software Development Life Cycle (SSDLC)
*(Co-engineered with `devsecops-master`)*
- **NIST SP 800-218 (SSDF v1.1):** Prepare the Organization (PO), Protect Software (PS), Produce Well-Secured Software (PW), Respond to Vulnerabilities (RV).
- **OWASP SAMM v2 & ASVS v4.0.3:** Verification Levels 1–3 across all 14 chapters.
- **ISO/IEC 27034:** Application Security Controls (ASC) embedded into CI steps.
- **SLSA Framework (Levels 1–4):** Hermetic builds, two-person reviews, Sigstore/Cosign provenance signing.
- **SBOM:** CycloneDX 1.6 / SPDX 3.0 vulnerability enrichment via Grype and Trivy.

---

## Layer 6: Code-Level Standards & Deterministic Static Analysis

### 1. SEI CERT & MISRA C/C++:2023
- Strict type safety, memory bounds verification, zero undefined behavior.

### 2. SonarQube Clean Code Quality Gate Standards
- **Zero Blocker and Zero Critical Issues.**
- **Cyclomatic Complexity (McCabe CC):** $\le 10$ per function.
- **Cognitive Complexity:** $\le 15$ per function.
- **Maximum Nesting Depth:** $\le 4$ levels.
- **Maximum File Length:** $\le 500$ LOC (bounded functional slicing).
- **Maximum Function Parameters:** $\le 4$ arguments.
- **Code Duplication:** $< 3\%$.
- **Line Coverage:** $\ge 80\%$.
- **Branch Coverage:** $\ge 75\%$.
