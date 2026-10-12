# The 7-Stage Universal SecSDLC Architecture

The Secure Software Development Life Cycle (SecSDLC) transforms security from a reactive post-build bottleneck into a proactive, continuous quality attribute present across every engineering phase.

---

## Stage 1: Governance, Policy & Risk Classification

### 1. Objectives
- Establish uniform security standards, regulatory compliance baselines, and asset risk classifications before any code is written.
- Eliminate ambiguity by translating corporate policy into automated Policy-as-Code (PaC).

### 2. Asset Risk Tiering Matrix

| Tier | Classification | Description & Criteria | Mandatory Controls |
| :--- | :--- | :--- | :--- |
| **Tier 0** | **Mission Critical / Crown Jewels** | Core payment systems, authentication backbones, PII databases, crypto key management. | OWASP ASVS Level 3, STRIDE threat model, 100% SHA action pinning, dual architect PR approvals, hermetic builds, eBPF runtime defense. |
| **Tier 1** | **Business Operational** | Customer-facing APIs, admin dashboards, ingestion pipelines, billing reporting. | OWASP ASVS Level 2, semi-annual threat models, automated SAST/SCA/IaC PR gates, signed container images, weekly vulnerability triage. |
| **Tier 2** | **Internal & Auxiliary** | Developer tooling, internal documentation portals, offline batch utilities. | OWASP ASVS Level 1, automated pre-commit hooks, secret scanning, monthly vulnerability updates. |

### 3. Policy-as-Code Implementation
Store organizational security policies directly in git repositories using Open Policy Agent (OPA) Rego or Kyverno:
- Enforce mandatory branch protection rules across all repositories.
- Disallow wildcard IAM permissions (`"Action": "*"`, `"Resource": "*"`).
- Mandate non-root user execution in all containerized workloads.

---

## Stage 2: Architecture, Threat Modeling & Security Requirements

### 2. Objectives
- Discover architectural vulnerabilities, broken trust boundaries, and logical flaws during the system design phase where remediation cost is minimal ($\approx 1/100$th of post-production fixes).

### 3. STRIDE-per-Element Threat Analysis
Analyze Data Flow Diagrams (DFDs) across every architectural element:

```
[External Actor] ---> (API Gateway) ---> [Microservice Process] ---> [(Encrypted DB)]
     │                       │                        │                      │
     ▼                       ▼                        ▼                      ▼
Spoofing /              Tampering /              Elevation of           Information
Repudiation             Info Disclosure          Privilege / DoS        Disclosure / Tampering
```

* **External Entities:** Spoofing, Repudiation. (Mitigation: Mutual TLS, OIDC PKCE, cryptographically signed audit logs).
* **Data Flows:** Tampering, Information Disclosure, Denial of Service. (Mitigation: TLS 1.3 in-transit, HMAC payload signing, rate limiting).
* **Processes:** Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. (Mitigation: Least privilege service accounts, memory-safe execution, input sanitization).
* **Data Stores:** Tampering, Information Disclosure, Denial of Service. (Mitigation: AES-256-GCM encryption at rest, role-based table access, connection pooling quotas).

### 4. Evil User Stories & Acceptance Criteria
Translate architectural threats into backlog stories:
* *"As an attacker, I want to modify the `tenant_id` query parameter on `/api/v2/orders` so that I can exfiltrate another customer's order history."*
* **Security Acceptance Criteria:**
  - Automated integration test asserts that substituting `tenant_id` returns HTTP 403 Forbidden.
  - Verification that database queries enforce row-level security (`WHERE org_id = current_tenant()`).

---

## Stage 3: Secure Coding, Pre-Commit & Local IDE Guardrails

### 1. Objectives
- Provide immediate, sub-second feedback to engineers on their workstations, preventing secrets and insecure code patterns from ever reaching git history.

### 2. Workstation Defense Layers
1. **IDE Linter Extension:** Real-time semantic analysis (e.g., SonarLint, Semgrep IDE extension, Ruff).
2. **Pre-Commit Hook Framework:** Runs in $< 3$ seconds prior to `git commit`:
   - `gitleaks protect --staged`: Blocks commits containing private keys, AWS tokens, GitHub PATs, JWT secrets.
   - `check-added-large-files`: Prevents accidental staging of binary blobs or DB dumps.
   - Stack-specific formatters and safety checks (e.g., `ruff check`, `eslint`).
3. **Sensitive File Git Guard:**
   Automated blocking of file patterns in repository configuration:
   ```gitignore
   # Configuration and secret files
   *.local_config_file
   *.local.json
   secrets/*.key
   config/credentials_*.json
   ```

---

## Stage 4: CI/CD Pipeline Gating & Supply Chain Security

### 1. Objectives
- Deterministically validate every pull request and release build. Ensure no vulnerable, unvetted, or tampered artifact can be deployed.

### 2. The Multi-Tier CI/CD Pipeline Structure

```
Pull Request Created
  │
  ▼
[Fast PR Gate] (< 8 min, PR Blocking)
  ├── 1. Secret Scanning (Gitleaks diff)
  ├── 2. Semantic SAST (Semgrep OSS rules / Ruff bandit)
  ├── 3. Dependency Scanning (Trivy FS / OSV-Scanner)
  └── 4. IaC & Container Linting (Checkov / Hadolint)
  │
Merge to Main
  │
  ▼
[Release & Provenance Gate] (Asynchronous, Non-blocking on PR, Mandatory on Release)
  ├── 1. Deep SAST & Taint Flow (CodeQL)
  ├── 2. SBOM Generation (Syft: CycloneDX JSON)
  ├── 3. Keyless Image Signing (Cosign / Sigstore OIDC)
  └── 4. SLSA Level 2/3 Attestation Generation
```

### 3. Supply Chain Security (SLSA & Cosign)
- **Immutable Action Pinning:** All CI/CD workflow actions must reference immutable 40-character commit SHAs.
- **Keyless Signing:** Release workflows obtain short-lived OIDC tokens from GitHub Actions / GitLab CI and issue non-forgeable signatures into the public Rekor transparency log.
- **Software Bill of Materials (SBOM):** Export complete hierarchical dependency tree with cryptographic package hashes using CycloneDX format.

---

## Stage 5: Pre-Deployment & Dynamic Verification

### 1. Objectives
- Validate running applications, API contracts, and runtime configurations in isolated preview/staging environments before routing production traffic.

### 2. Verification Capabilities
1. **Dynamic Application Security Testing (DAST):**
   - Run OWASP ZAP Automation Framework (`zap.sh -cmd -autorun zap.yaml`) or Nuclei against ephemeral staging preview environments.
   - Focus on HTTP security headers (CSP, HSTS, X-Frame-Options), CORS misconfigurations, SSL/TLS protocol weaknesses, and OpenAPI endpoint security.
2. **Contract-Driven API Security Fuzzing:**
   - Execute negative boundary fuzzing against declared OpenAPI/Swagger specifications using tools like Schemathesis or RESTler.
   - Test for parameter pollution, schema violations, and unhandled 500 Internal Server Errors.
3. **Admission Control Policies (Kubernetes / Cloud):**
   - Enforce Kyverno or OPA Gatekeeper policies at deployment time:
     - Disallow images without valid Cosign cryptographic signatures.
     - Mandate `securityContext.runAsNonRoot: true`.
     - Mandate `securityContext.readOnlyRootFilesystem: true`.
     - Drop all default Linux capabilities (`capabilities.drop: ["ALL"]`).

---

## Stage 6: Production Runtime Defense & Cloud Hardening

### 1. Objectives
- Protect live production workloads from zero-day exploits, unauthorized lateral movement, and runtime drift.

### 2. Runtime Defense Pillars
1. **Kernel-Level eBPF Telemetry (Falco & Cilium Tetragon):**
   - Real-time detection of anomalous syscalls inside containers:
     - Spawning unexpected interactive shells (`/bin/sh`, `/bin/bash` in production pods).
     - Writing to protected directories (`/etc`, `/bin`, `/lib`).
     - Modifying kernel namespaces or mounting sensitive host directories.
2. **Cloud Security Posture Management (CSPM):**
   - Continuous scanning of AWS, GCP, and Azure configurations against CIS Benchmarks.
   - Automated remediation of publicly exposed S3 buckets, open security groups (0.0.0.0/0 on port 22/3389), and unrotated KMS keys.
3. **Web Application Firewall (WAF) & Rate Limiting:**
   - Enforce OWASP Core Rule Set (CRS) at edge gateways (Cloudflare, AWS WAF).
   - Dynamic IP reputation filtering, DDoS mitigation, and credential stuffing defense.
4. **Zero-Trust Microsegmentation:**
   - Enforce Mutual TLS (mTLS) with cryptographically verified service identities (SPIFFE/SPIRE, Istio, Linkerd) between all backend microservices.

---

## Stage 7: Continuous Monitoring, Vulnerability Triage & Incident Feedback

### 1. Objectives
- Ingest threat intelligence, prioritize newly discovered CVEs in running workloads, and close the loop on every security incident.

### 2. The Closed-Loop Incident Remediation Lifecycle

```
Security Incident / Pentest Finding Escapes
  │
  ▼
1. Emergency Mitigation (Hotfix / WAF Rule / Quarantine)
  │
  ▼
2. Blameless Root-Cause Analysis (5-Whys)
  │
  ▼
3. The Three-Fold Feedback Invariant:
   ├── A. Pipeline Regression Test (Automated test that fails if bug recurs)
   ├── B. Semantic SAST / Linter Rule (Custom Semgrep rule detecting pattern)
   └── C. Threat Model & Policy Update (Updated architecture documentation)
```

Every escaped vulnerability must yield a permanent, automated regression check in the CI pipeline so that the same vulnerability class can never be introduced again.
