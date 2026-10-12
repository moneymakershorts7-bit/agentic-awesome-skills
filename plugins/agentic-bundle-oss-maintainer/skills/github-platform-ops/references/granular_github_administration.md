# GitHub Enterprise & Repository Granular Administration: Runner Groups, Pages, Autolinks & Properties

Reference specification and automation guide for 100% granular control across GitHub Actions Runner Groups, ephemeral autoscaling (ARC), GitHub Pages, Autolink ticketing integrations, and Custom Organization Properties.

---

## 1. Actions Runner Groups & Ephemeral Autoscaling Architecture

### A. Runner Group Isolation (`POST /orgs/{org}/actions/runner-groups`)
Prevent untrusted repositories from consuming privileged compute or accessing internal networks:

```bash
gh api -X POST /orgs/:org/actions/runner-groups --input - << 'EOF'
{
  "name": "isolated-production-runners",
  "visibility": "selected",
  "selected_repository_ids": [1234567, 8910111],
  "allows_public_repositories": false,
  "restricted_to_workflows": true,
  "selected_workflows": [
    "owner/repo/.github/workflows/deploy.yml@refs/heads/main"
  ]
}
EOF
```

### B. Ephemeral Runner Autoscaling (ARC - Actions Runner Controller)
- **Token Registration Endpoint:**
  ```bash
  # Repository scope
  gh api -X POST /repos/:owner/:repo/actions/runners/registration-token --jq '.token'

  # Organization scope
  gh api -X POST /orgs/:org/actions/runners/registration-token --jq '.token'
  ```
- **Ephemeral Invariant:** Ensure Kubernetes RunnerDeployment or AutoscalingRunnerSet sets `ephemeral: true`. Each job runs on a sterile container and terminates upon job completion, wiping all disk state.

---

## 2. GitHub Pages Configuration API (`PUT /repos/{owner}/{repo}/pages`)

### A. Workflow-Driven Modern Artifact Mode (Recommended)
Deploys documentation via `actions/deploy-pages@v4` using OpenID Connect (OIDC) tokens:

```bash
gh api -X POST /repos/:owner/:repo/pages --input - << 'EOF'
{
  "build_type": "workflow"
}
EOF
```

### B. Branch-Driven Legacy Mode
```bash
gh api -X POST /repos/:owner/:repo/pages --input - << 'EOF'
{
  "build_type": "legacy",
  "source": {
    "branch": "gh-pages",
    "path": "/"
  }
}
EOF
```

### C. Enforce HTTPS & Custom Domain (CNAME)
```bash
gh api -X PUT /repos/:owner/:repo/pages --input - << 'EOF'
{
  "cname": "docs.company.internal",
  "https_enforced": true
}
EOF
```

---

## 3. Autolink Ticketing References (`POST /repos/{owner}/{repo}/autolinks`)

Automatically turns issue and ticket IDs in commit messages and PR bodies into clickable markdown links without external bot comments:

### A. Register Jira / Linear / Shortcut Autolink
```bash
# Jira Integration
gh api -X POST /repos/:owner/:repo/autolinks --input - << 'EOF'
{
  "key_prefix": "PROJ-",
  "url_template": "https://jira.company.internal/browse/PROJ-<num>",
  "is_alphanumeric": false
}
EOF

# Linear Integration
gh api -X POST /repos/:owner/:repo/autolinks --input - << 'EOF'
{
  "key_prefix": "ENG-",
  "url_template": "https://linear.app/myorg/issue/ENG-<num>",
  "is_alphanumeric": false
}
EOF
```

### B. List and Delete Autolinks
```bash
# List autolinks
gh api /repos/:owner/:repo/autolinks --jq '.[] | {id: .id, prefix: .key_prefix, url: .url_template}'

# Delete autolink by ID
gh api -X DELETE /repos/:owner/:repo/autolinks/:autolink_id
```

---

## 4. Organization Custom Repository Properties & Dynamic Rulesets

Custom properties allow tagging repositories at enterprise scale and binding branch governance rules dynamically:

### A. Define Custom Property Schema (`PUT /orgs/{org}/properties/schema/{property_name}`)
```bash
gh api -X PUT /orgs/:org/properties/schema/criticality --input - << 'EOF'
{
  "value_type": "single_select",
  "required": true,
  "default_value": "tier-3",
  "description": "Production criticality level determining security ruleset enforcement",
  "allowed_values": [
    "tier-1",
    "tier-2",
    "tier-3"
  ]
}
EOF
```

### B. Assign Property Values to Repositories (`PATCH /orgs/{org}/properties/values`)
```bash
gh api -X PATCH /orgs/:org/properties/values --input - << 'EOF'
{
  "repository_names": [
    "agentic-awesome-skills",
    "core-payment-gateway"
  ],
  "properties": [
    {
      "property_name": "criticality",
      "value": "tier-1"
    }
  ]
}
EOF
```

### C. Dynamic Organization Ruleset Targeting
Organization Rulesets can use `"conditions": { "repository_property": { "include": [ { "name": "criticality", "values": ["tier-1"] } ] } }` to automatically apply production branch protection across hundreds of repos tagged as `tier-1`.
