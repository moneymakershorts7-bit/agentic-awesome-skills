# Playbook 03: CI/CD Pipeline Gating Setup

This playbook guides configuring quality gates in GitHub Actions or GitLab CI, balancing speed with strict security enforcement.

---

## Step 1: Establish Time and Tool Budgets
Security checks must adhere to the **8-Minute PR Rule**:
- Fast PR Gate (blocking):
  - Secret scan: $< 30$ seconds (Gitleaks diff).
  - Semantic SAST: $< 3$ minutes (Semgrep OSS with focused security rulesets).
  - SCA / Lockfile scan: $< 2$ minutes (Trivy FS mode).
  - IaC & Dockerfile scan: $< 1$ minute (Hadolint / Checkov).
- Heavyweight Scans (asynchronous nightly / on-release):
  - Full git history secret scan.
  - Deep inter-procedural taint tracking (CodeQL).
  - Dynamic container & DAST scans (ZAP / Nuclei).

---

## Step 2: Configure SARIF Aggregation and Pull Request Annotations
1. Standardize all tool outputs to `.sarif` format.
2. Ingest SARIF files into GitHub Code Scanning using `github/codeql-action/upload-sarif`:
   ```yaml
   - name: Upload Security Findings
     uses: github/codeql-action/upload-sarif@48ab28a6f5dab2aab706736bd510d5f6fcd718b6 # v3.28.0
     if: always()
     with:
       sarif_file: results.sarif
   ```
3. Use `scripts/sarif_aggregator.py` to produce a high-density Markdown summary comment on pull requests with passing/failing status.

---

## Step 3: Implement Immutable Action Pinning
Never use mutable branch or release tags for third-party actions:
- Insecure: `uses: actions/checkout@v4`
- Hardened: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`

Run the integrity validator before opening the PR:
```bash
python3 scripts/verify_pipeline_integrity.py .
```
Ensure the validator returns `0 errors`.
