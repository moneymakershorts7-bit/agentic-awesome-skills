# Threat Modeling Guide: STRIDE & PASTA Methodology

This reference guides teams in conducting rapid, actionable threat modeling in agile iterations.

---

## 1. STRIDE-per-Element Analysis

STRIDE maps directly to Data Flow Diagram (DFD) components:

| Element Type | Applicable STRIDE Threats | Standard Engineering Mitigations |
| :--- | :--- | :--- |
| **External Interactor** | **S**poofing, **R**epudiation | Strong authentication (OIDC, PKCE, MFA), digital signatures, append-only immutable audit logs. |
| **Data Flow** | **T**ampering, **I**nformation Disclosure, **D**enial of Service | TLS 1.3 encryption in transit, HMAC message authentication, network rate-limiting. |
| **Data Store** | **T**ampering, **I**nformation Disclosure, **D**enial of Service | AES-256-GCM encryption at rest, database row-level security, resource storage quotas. |
| **Process / Service** | **S**poofing, **T**ampering, **R**epudiation, **I**nfo Disclosure, **D**oS, **E**levation of Privilege | Memory-safe runtimes, strict input validation, least-privilege OS user, seccomp/AppArmor isolation. |

---

## 2. PASTA (Process for Attack Simulation and Threat Analysis)

For high-risk systems (Tier 0), PASTA aligns technical threats with business impact across 7 stages:
1. **Define Objectives:** Business impact, compliance, operational value.
2. **Define Technical Scope:** System boundaries, trust perimeters, software assets.
3. **Decompose Application:** Data flows, actors, call trees, data states.
4. **Threat Analysis:** Threat intelligence, CVE feeds, attacker actor profiles.
5. **Vulnerability Analysis:** Known weaknesses, code auditing, flaw mapping.
6. **Attack Modeling:** Attack trees, exploit simulations, path analysis.
7. **Risk & Impact Analysis:** Residual risk scoring and targeted countermeasure selection.

---

## 3. Threat Model Template (Markdown)

```markdown
# Threat Model: [Component Name]

## 1. System Decomposition
* **Target:** [API / Service / Data Pipeline]
* **Trust Boundaries:** [Internet -> API Gateway -> Private VPC -> DB]
* **Data Classification:** [Confidential / PII / Financial]

## 2. Threat Matrix (STRIDE)
| Threat ID | Category | Description | Existing Control | Residual Risk | Required Action |
|---|---|---|---|---|---|
| TM-01 | Elevation | Parameter tampering on tenant ID | None | HIGH | Add row-level tenant check |
| TM-02 | Info Leak | Verbose error stack trace in 500 responses | Default framework handler | MED | Enforce sanitized error envelope |

## 3. Verification Test Cases
* `test_unauthorized_tenant_access_returns_403()`
* `test_invalid_payload_returns_opaque_error()`
```
