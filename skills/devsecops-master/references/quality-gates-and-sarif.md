# Quality Gates & SARIF Normalization Specification

This reference defines the deterministic quality gate criteria, break-build thresholds, and SARIF (Static Analysis Results Interchange Format) processing standard for DevSecOps workflows.

---

## 1. Quality Gate Enforcement Thresholds

Quality gates must protect production environments without stalling developer velocity.

### Gate Evaluation Matrix

| Category | Blocker Condition (Exit Code 1) | Warning Condition (Exit Code 0) | Exemption Criteria |
| :--- | :--- | :--- | :--- |
| **Secrets** | Any active/verified credential, private key, or cloud token found in git diff. | Low-entropy false positive in test mock directory. | Must reside in explicitly declared mock fixture directory (`tests/fixtures/`). |
| **SAST** | Severity `error` / `critical` in OWASP Top 10 or CWE Top 25 (e.g. SQLi, RCE, SSRF). | Severity `warning` / `note` (code quality, minor style). | Inline suppressions strictly forbidden without Principal Architect approval. |
| **SCA** | CVE Severity `CRITICAL` with public exploit (CISA KEV = Yes OR EPSS $> 0.10$) AND available patch. | Medium/Low CVE, or Critical CVE with no available upstream patch. | Verified VEX declaration `not_affected` confirming unreachable call path. |
| **IaC / Config** | Public ingress `0.0.0.0/0` on sensitive ports (22, 3389, 5432), unencrypted storage volumes. | Informational compliance recommendations (tagging standards). | Documented exception for public web proxies (ports 80/443). |
| **Containers** | Image running as `root` user, or critical OS package vulnerability with patch. | Base image minor version updates. | Build-stage scratch/builder containers (final runtime must be non-root). |
| **Pipelines** | Third-party GitHub Action referenced by branch/tag (`@v2`, `@main`) instead of full commit SHA. | Action version comment missing. | First-party actions inside repository (`./.github/actions/*`). |

---

## 2. SARIF (Static Analysis Results Interchange Format) Standard

All scanners (Semgrep, Trivy, Bandit, GoSec, Checkov, Hadolint) output results adhering to OASIS SARIF v2.1.0 (`schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`).

### Standard SARIF Schema Excerpt
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Semgrep",
          "rules": [
            {
              "id": "python.lang.security.deserialization.pickle.avoid-pickle",
              "shortDescription": { "text": "Avoid using pickle deserialization on untrusted data" },
              "defaultConfiguration": { "level": "error" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.lang.security.deserialization.pickle.avoid-pickle",
          "level": "error",
          "message": { "text": "Identified unsafe pickle.loads() execution." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/api/auth.py" },
                "region": { "startLine": 42 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 3. Vulnerability Exploitability eXchange (VEX) Integration

When a dependency contains a CVE that is unreachable due to library configuration or unused module paths, the team creates an OpenVEX or CycloneDX VEX document (`security/vex.json`):

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/example/vex-001",
  "author": "SecOps Architect",
  "timestamp": "2026-10-12T18:00:00Z",
  "statements": [
    {
      "vulnerability": { "name": "CVE-2026-12345" },
      "products": [{ "@id": "pkg:npm/vulnerable-lib@1.2.0" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The vulnerable XML parsing method is never invoked; only JSON codecs are active."
    }
  ]
}
```

The pipeline scanner ingests `security/vex.json` to suppress unreachable alerts without requiring dirty inline source code comment bypasses.
