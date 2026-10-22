# Twin-Engine DevSecOps Master Integration Protocol

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                      THE TWIN-ENGINE SOFTWARE ASSURANCE ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ Engine 1: qa-master        │ Functional, Structural, Mutation, Performance, A11y, Gov  │
│ Engine 2: devsecops-master │ ASVS L1-L3, Threat Modeling, SAST, SCA, SBOM, Cosign, SLSA │
│ Convergence Gate           │ scripts/qa_master_gate.py aggregating SARIF 2.1.0 streams   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Division of Responsibilities

Enterprise software verification cannot be accomplished with a single monolithic scanner. It operates via two specialized, synchronized engines:

| Dimension | Engine 1: `qa-master` | Engine 2: `devsecops-master` |
| :--- | :--- | :--- |
| **Primary Invariant** | Functional & Structural Correctness | Defense-in-Depth & Supply Chain Security |
| **Standards Governed**| ISO 9001, ISO 12207, ISO 25010, ISO 5055, ISO 29119, ISTQB, WCAG 2.2 AA | ISO 27001, NIST SSDF, OWASP ASVS, ISO 27034, SLSA 1-4, CIS Benchmarks |
| **Testing Scope** | Unit, Integration, Mutation (MSI $\ge 80\%$), Contracts (Pact), Property-Based, Flaky Isolation | SAST, DAST, Secret Scanning, SCA/SBOM, Container Non-Root, Infrastructure-as-Code |
| **Performance & Load**| k6 Smoke & Stress (P95 $\le 200\text{ms}$), Memory leaks, Concurrency | DoS resilience, Rate-limiting validation, Network egress controls |
| **Primary Telemetry** | JUnit XML, Test Summary Report, Axe-Core JSON, Mutation Log | SARIF 2.1.0, CycloneDX 1.6 SBOM, Cosign Attestation, SLSA Provenance |

---

## 2. The Convergence Point: SARIF 2.1.0 Aggregation

Both engines produce findings standardized on the OASIS SARIF (Static Analysis Results Interchange Format) 2.1.0 standard:

```
                  ┌───────────────────────────────┐
                  │    Engine 1: qa-master        │
                  │   - ISO 5055 Static Rules     │
                  │   - Cyclomatic Complexity     │
                  │   - Schema Contract Drift     │
                  └───────────────┬───────────────┘
                                  │
                                  │ qa_results.sarif
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│              Unified Quality Gate (scripts/qa_master_gate.py)    │
│              - Ingests all .audit/*.sarif files                  │
│              - Calls devsecops-master/scripts/sarif_aggregator.py│
│              - Evaluates SonarQube Clean Code Quality Gate       │
│              - Generates .audit/unified_quality_scorecard.json   │
└─────────────────────────────────▲────────────────────────────────┘
                                  │
                                  │ devsecops.sarif
                  ┌───────────────┴───────────────┐
                  │ Engine 2: devsecops-master    │
                  │   - Semgrep SAST              │
                  │   - Trivy SCA & Secrets       │
                  │   - Checkov IaC               │
                  └───────────────────────────────┘
```

---

## 3. Pull Request Veto & Release Decision Logic

The gate script `scripts/qa_master_gate.py` evaluates all 6 layers simultaneously. If any layer fails, the pull request or release pipeline is immediately blocked with exit code `1`:

1. **Layer 1 Gate:** `.audit/rtm_manifest.json` coverage must be $100.0\%$. Two-Person Rule must be verified.
2. **Layer 2 Gate:** `.audit/vse_profile_manifest.json` present and compliant.
3. **Layer 3 Gate:** Zero ISO/IEC 5055 Blocker/Critical findings.
4. **Layer 4 Gate:** Zero failed tests. Line coverage $\ge 80\%$, branch coverage $\ge 75\%$. Mutation Score Indicator $\ge 80\%$. Zero unquarantined flaky tests.
5. **Layer 5 Gate:** Zero critical/high SAST findings. Zero unpatched high CVEs in dependencies. Non-root container enforced.
6. **Layer 6 Gate:** McCabe Cyclomatic Complexity $\le 10$ across all functions. Cognitive Complexity $\le 15$. Max Nesting $\le 4$. Code duplication $< 3\%$.
