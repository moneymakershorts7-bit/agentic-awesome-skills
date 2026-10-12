# OpenSSF Scorecard Hardening & Actions Security Governance

Technical specification and automated remediation guide for achieving maximum OpenSSF Scorecard ratings, SLSA Build Level 2/3 provenance, and strict GitHub Actions security.

---

## 1. OpenSSF Scorecard: 18 Security Controls & Settings Matrix

OpenSSF Scorecard evaluates repository supply-chain health across 18 automated criteria. The table below maps each check directly to GitHub platform configurations and automated commands:

| Scorecard Check | Security Objective | GitHub Remediation Command / Setting |
| :--- | :--- | :--- |
| **Branch-Protection** | Prevent direct commits to trunk, require PR reviews and passing CI. | Apply Ruleset: `pull_request` (approvals >= 1, dismiss stale), `required_status_checks` (strict: true). |
| **Token-Permissions** | Restrict automatic `GITHUB_TOKEN` to read-only permissions by default. | `gh api -X PUT /repos/:owner/:repo/actions/permissions/workflow -F default_workflow_permissions="read" -F can_approve_pull_request_reviews=false` |
| **Pinned-Dependencies** | Pin all third-party GitHub Actions to immutable full 40-character commit SHAs. | `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2` |
| **Dangerous-Workflow** | Avoid `pull_request_target` with untrusted checkouts or script injection. | Enforce static analysis with CodeQL / zizmor. Never checkout PR HEAD under `pull_request_target`. |
| **Vulnerabilities** | Ensure no open unresolved vulnerabilities exist in dependencies. | `gh api -X PUT /repos/:owner/:repo/vulnerability-alerts` & monitor Dependabot alerts. |
| **Dependency-Update-Tool** | Automate dependency updates and CVE patch PRs. | Commit `.github/dependabot.yml` and run `gh api -X PUT /repos/:owner/:repo/automated-security-fixes`. |
| **Security-Policy** | Provide clear vulnerability reporting instructions. | Commit `SECURITY.md` or enable Private Vulnerability Reporting (`gh api -X PUT /repos/:owner/:repo/private-vulnerability-reporting`). |
| **SAST** | Static Application Security Testing enabled in CI. | Enable CodeQL Default Setup: `gh api -X PATCH /repos/:owner/:repo/code-scanning/default-setup -f state="configured"`. |
| **Signed-Releases** | Cryptographically sign release artifacts and provenance. | Sign tags with SSH/GPG or generate SLSA provenance attestations using GitHub Artifact Attestations. |
| **Binary-Artifacts** | Ensure no compiled binaries or archives are tracked in git. | Scan git tree with `git ls-files` and enforce `.gitignore` for `.exe`, `.so`, `.dylib`, `.jar`, `.zip`. |

---

## 2. Hardening GitHub Actions Workflows

### A. Minimal GITHUB_TOKEN Permissions
Workflows should declare read-only permissions at top-level, granting elevated scopes only to individual jobs:

```yaml
# Top-level: Least Privilege
permissions: read-all

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: npm test

  publish-release:
    runs-on: ubuntu-latest
    needs: test
    permissions:
      contents: write # Isolated permission for release tagging
      id-token: write # For OIDC authentication
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: ./publish.sh
```

### B. Action SHA Pinning Automation Script
To convert mutable action tags into immutable SHAs across `.github/workflows/`:

```bash
# Resolve latest commit SHA of an action release
gh api repos/actions/checkout/commits/v4.2.2 --jq '.sha'
```

---

## 3. GitHub Actions Runtime & Runner Governance

```bash
# 1. Audit current Actions permissions
gh api /repos/:owner/:repo/actions/permissions

# 2. Restrict actions to GitHub-owned and verified creators only
gh api -X PUT /repos/:owner/:repo/actions/permissions --input - << 'EOF'
{
  "enabled": true,
  "allowed_actions": "selected"
}
EOF

gh api -X PUT /repos/:owner/:repo/actions/permissions/selected-actions --input - << 'EOF'
{
  "github_owned_allowed": true,
  "verified_allowed": true,
  "patterns_allowed": [
    "actions/*"
  ]
}
EOF
```
