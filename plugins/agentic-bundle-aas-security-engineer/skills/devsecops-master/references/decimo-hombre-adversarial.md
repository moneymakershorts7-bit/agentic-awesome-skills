# El Décimo Hombre Adversarial Audit & SecSDLC Directives

This document establishes the adversarial counter-doctrine formulated under the mandate of **El Décimo Hombre (The Tenth Man)**:
> *"When nine analysts agree that the DevSecOps pipeline is secure, the Tenth Man is duty-bound to assume the nine are wrong and construct the most rigorous, evidence-grounded failure vectors possible."*

---

## 1. The DevSecOps Consensus Under Attack

The prevailing industry consensus asserts:
- *Consensus Thesis:* "By shifting left, embedding automated scanners (SAST, SCA, Linters, Container scanning) into CI/CD pull request gates, and blocking merges on High/Critical vulnerabilities, systems achieve deterministic security assurance."

### Unstated Fragile Axioms
1. **Axiom 1 (Scanner Competence):** Assumes rule-based pattern matching catches real-world exploitation paths rather than benign syntax anomalies.
2. **Axiom 2 (Developer Compliance):** Assumes developers carefully investigate warnings rather than bypassing gates using inline suppressions (`// nosec`, `eslint-disable`, `--no-verify`).
3. **Axiom 3 (Runner Immutability):** Assumes the CI build environment, third-party actions, and container base images are untampered and trustworthy.
4. **Axiom 4 (SBOM Efficacy):** Assumes an inventory of open-source packages detects or prevents obfuscated malicious code injected upstream.

---

## 2. Inversion & Attack Vectors (Ipcha Mistabra)

### Vector A (Tail Event / Black Swan): Supply Chain Poisoning & CI Compute Subversion
* **Mechanics:** An adversary compromises an unpinned upstream action (e.g., `actions/cache@v2`), a third-party dependency repository, or an internal CI runner token.
* **The Blind Spot:** In an XZ-style or SolarWinds-style multi-stage attack:
  - During CI static scans, linters and SAST evaluate source code cleanly with zero CVE alerts.
  - During the release packaging step, the build script dynamically compiles injected malicious logic directly into release binaries.
  - The poisoned release is cryptographically signed with valid OIDC Cosign provenance, boasting a clean, spotless SBOM.
* **Blast Radius:** 100% of pipeline gates report "Green." Malware ships to production with cryptographic trust.

### Vector B (Hidden Friction / Scaling Bottleneck): False Positive Fatigue & Developer Evasion
* **Mechanics:** Off-the-shelf SAST and container scanners generate an 80–90% false-positive ratio (flagging unreachable code, test utilities, or benign regex patterns).
* **The Blind Spot:**
  - Deployment velocity drops, causing engineering friction.
  - Developers routinely establish evasion patterns: blanket suppressions (`// nosec: B101`, `# pragma: no-scanner`), bypassing pre-commit hooks (e.g. hook verification skip flags), or downgrading scan rulesets.
  - Real, high-impact alerts drown in hundreds of low-severity notices.

### Vector C (Adversarial / Exploitation): Architectural & Business Logic Blind Spots
* **Mechanics:** Critical real-world breaches target authorization state and application business logic:
  - Broken Object Level Authorization (BOLA / IDOR).
  - Race conditions in ledger/transaction states.
  - Multi-tenant tenant boundary leakage via unconstrained query filters.
* **The Blind Spot:**
  - SAST cannot analyze dynamic multi-tenant session contexts. SCA only tracks declared packages.
  - The application achieves a 100% clean security scorecard while exposing wide-open tenant data enumeration.

---

## 3. Simulated After Action Report (Disaster Scenario: Pre-AAR)

* **1. What was supposed to happen?**
  A core microservice passed all DevSecOps CI/CD gates: 0 High/Critical CVEs, clean SAST/SCA reports, signed Cosign provenance, and green Trivy scans.
* **2. What disastrously happened instead?**
  48 hours post-deployment, 1.2M user records and tenant billing data were exfiltrated. Attackers exploited an IDOR endpoint combined with an unpinned GitHub Action that had poisoned the build cache 6 days earlier.
* **3. Root Cause Breakdown (5-Whys):**
  1. *Why was data exfiltrated?* The account switching API allowed parameter substitution without server-side tenancy verification.
  2. *Why didn't CI scanners catch it?* SAST does not model multi-tenant runtime authorization logic.
  3. *Why wasn't it caught during code review?* Security engineers were backlogged triaging 400+ false-positive library alerts from automated dependency scanners.
  4. *Why did developers bypass checks?* Developers introduced inline ignore comments (`// nosec`) to unblock release deadlines.
  5. *Why was a backdoor present in the runner?* The workflow used floating tags (`uses: actions/cache@v2`) rather than immutable 40-character commit SHAs.
* **4. Detection Lag:** 48 hours to breach, 14 days to discovery. Teams assumed green CI gates equaled security.

---

## 4. Non-Negotiable Kill Criteria (Automated Abort Triggers)

The following criteria MUST trigger an immediate build abort or PR block:

| Trigger Metric | Abort Threshold | Immediate Action |
| :--- | :--- | :--- |
| **Unpinned CI Action** | Any action referenced by tag/branch (`@v2`, `@main`) instead of full commit SHA (`@<sha>`). | Pipeline exits with Code 1 immediately. |
| **Suppression Directive Infiltration** | Any PR introducing inline scanner bypasses (`// nosec`, `@SuppressWarnings`, `# pragma: allowlist`). | Automated PR block; requires dual Principal Architect sign-off and written threat model rationale. |
| **Scanner False Positive Saturation** | Noise/False Positive ratio $> 40\%$ over a rolling 14-day window. | Deactivate blocking status for offending rule; reroute to offline rule tuning. |
| **Permissive Workflow Permissions** | Workflow lacking top-level `permissions: contents: read` or equivalent minimal declaration. | Pipeline lint failure via Actionlint. |

---

## 5. Structural Hardening Directives

1. **Zero-Trust Ephemeral CI Runners:** Enforce default `permissions: read-all` or empty `{}` on all workflows. Never grant ambient write permissions or pass long-lived secrets to test steps.
2. **Runtime Defense-in-Depth (Shield-Right):** Implement eBPF kernel tripwires (Falco) to catch unexpected process execution or privilege escalation in production, recognizing that shift-left static analysis is never sufficient alone.
3. **Mandatory Architectural Review on Sensitive Boundaries:** Isolate changes to authentication, tenancy boundaries, cryptography, and financial state from automated fast-path approvals.
