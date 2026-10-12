# Repository Settings & Merge Policies Configuration Matrix

Comprehensive reference for managing every GitHub repository setting via GitHub CLI (`gh`) and the GitHub REST API v3 (`gh api`).

---

## 1. General Repository Settings (`gh repo edit` & REST API)

### A. Core CLI Configuration Flags (`gh repo edit`)
```bash
gh repo edit <owner>/<repo> \
  --description "Production hardened repository" \
  --homepage "https://example.com" \
  --default-branch main \
  --visibility public \
  --enable-issues=true \
  --enable-projects=false \
  --enable-wiki=true \
  --enable-discussions=false \
  --template=false
```

### B. Full REST API Domain Payloads (`PATCH /repos/{owner}/{repo}`)
For settings not directly reachable via `gh repo edit` flags, use `gh api -X PATCH /repos/{owner}/{repo}` with deterministic JSON:

```bash
gh api -X PATCH /repos/:owner/:repo --input - << 'EOF'
{
  "name": "repo-name",
  "description": "Enterprise repository",
  "homepage": "https://example.com",
  "private": false,
  "visibility": "public",
  "has_issues": true,
  "has_projects": false,
  "has_wiki": true,
  "has_discussions": false,
  "is_template": false,
  "default_branch": "main",
  "allow_squash_merge": true,
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "allow_auto_merge": true,
  "delete_branch_on_merge": true,
  "allow_update_branch": true,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "PR_BODY",
  "merge_commit_title": "MERGE_MESSAGE",
  "merge_commit_message": "PR_TITLE",
  "use_squash_pr_title_as_default": true,
  "allow_forking": true,
  "web_commit_signoff_required": true
}
EOF
```

---

## 2. PR & Merge Strategy Policy Matrix

| Merge Strategy Option | Recommended Security Baseline | Description / Permitted Values |
| :--- | :--- | :--- |
| `allow_squash_merge` | `true` | Enables squash merging for clean linear Git history. |
| `allow_merge_commit` | `false` | Disables non-linear multi-parent merge commits on trunk. |
| `allow_rebase_merge` | `false` (or `true` if rebase-driven) | Rebase individual commits onto trunk without squash. |
| `squash_merge_commit_title` | `"PR_TITLE"` | Value options: `"PR_TITLE"`, `"COMMIT_OR_PR_TITLE"`. |
| `squash_merge_commit_message` | `"PR_BODY"` | Value options: `"PR_BODY"`, `"COMMIT_MESSAGES"`, `"BLANK"`. |
| `delete_branch_on_merge` | `true` | Automatically deletes head branches upon PR merge to prevent branch clutter. |
| `allow_auto_merge` | `true` | Allows contributors to schedule merge once required checks pass. |
| `allow_update_branch` | `true` | Shows button to update head branch via trunk fast-forward. |
| `web_commit_signoff_required` | `true` | Requires sign-off (DCO) on commits made via GitHub web interface. |

---

## 3. Repository Vulnerability & Code Security Settings

### A. Automated Security Fixes & Alerts
```bash
# Enable Dependabot security alerts
gh api -X PUT /repos/:owner/:repo/vulnerability-alerts

# Disable Dependabot security alerts
gh api -X DELETE /repos/:owner/:repo/vulnerability-alerts

# Enable Automated Dependabot PR updates (security fixes)
gh api -X PUT /repos/:owner/:repo/automated-security-fixes

# Disable Automated Dependabot PR updates
gh api -X DELETE /repos/:owner/:repo/automated-security-fixes
```

### B. Secret Scanning & Push Protection
Available for public repositories or GitHub Advanced Security (GHAS) enabled private repositories:

```bash
gh api -X PATCH /repos/:owner/:repo --input - << 'EOF'
{
  "security_and_analysis": {
    "secret_scanning": {
      "status": "enabled"
    },
    "secret_scanning_push_protection": {
      "status": "enabled"
    },
    "secret_scanning_non_provider_patterns": {
      "status": "enabled"
    }
  }
}
EOF
```

### C. Private Vulnerability Reporting (PVR)
Allows security researchers to report vulnerabilities privately without creating public issues:

```bash
# Enable Private Vulnerability Reporting
gh api -X PUT /repos/:owner/:repo/private-vulnerability-reporting

# Disable Private Vulnerability Reporting
gh api -X DELETE /repos/:owner/:repo/private-vulnerability-reporting
```

---

## 4. Topics & Tagging Management

```bash
# Get current topics
gh repo view :owner/:repo --json repositoryTopics --jq '.repositoryTopics[].name'

# Replace repository topics atomically
gh api -X PUT /repos/:owner/:repo/topics --input - << 'EOF'
{
  "names": ["security", "automation", "devops", "slsa", "openssf"]
}
EOF
```
