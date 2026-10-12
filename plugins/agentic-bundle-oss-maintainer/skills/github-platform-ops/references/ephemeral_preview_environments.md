# Ephemeral Preview Environments & GitHub Deployments API Lifecycle

Operational reference for provisioning on-demand PR preview environments and emitting GitHub Deployment Status events.

---

## 1. Ephemeral Environment Architecture

| Stage | Trigger | Action | GitHub API Target |
| :--- | :--- | :--- | :--- |
| **Provision** | `pull_request` (open/sync) | Deploy isolated compute stack | `POST /deployments` (state: `success`, `environment_url`) |
| **Teardown** | `pull_request` (closed) | Decommission cloud resources | `POST /deployments/:id/statuses` (state: `inactive`), delete env |

---

## 2. GitHub Deployments & Statuses REST API

### A. Register Deployment (`POST /repos/{owner}/{repo}/deployments`)
```bash
gh api -X POST /repos/:owner/:repo/deployments \
  -f ref="refs/pull/42/head" \
  -f environment="preview-pr-42" \
  -f description="Ephemeral preview environment for PR #42" \
  -F auto_merge=false \
  -F transient_environment=true \
  -F production_environment=false
```

### B. Transition Deployment Status (`POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses`)
```bash
# 1. In-progress notification
gh api -X POST /repos/:owner/:repo/deployments/:deployment_id/statuses \
  -f state="in_progress" \
  -f description="Spinning up isolated ephemeral services..."

# 2. Success with Live Preview URL
gh api -X POST /repos/:owner/:repo/deployments/:deployment_id/statuses \
  -f state="success" \
  -f environment_url="https://preview-pr-42.apps.domain.com" \
  -f description="Preview environment live and verified" \
  -F auto_inactive=true

# 3. Mark Inactive on Teardown
gh api -X POST /repos/:owner/:repo/deployments/:deployment_id/statuses \
  -f state="inactive" \
  -f description="Preview environment destroyed upon PR closure."
```

---

## 3. Automation Shell Script Steps

### A. Provisioning & Status Step
```bash
#!/usr/bin/env bash
set -euo pipefail

ENV_NAME="preview-pr-${PR_NUMBER}"

# Register deployment
DEPLOY_ID=$(gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments" \
  -f ref="${HEAD_REF}" \
  -f environment="${ENV_NAME}" \
  -F auto_merge=false \
  -F transient_environment=true \
  -F production_environment=false \
  --jq '.id')

# Set in-progress
gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments/${DEPLOY_ID}/statuses" \
  -f state="in_progress"

# Deploy preview service and emit success URL
PREVIEW_URL="https://${ENV_NAME}.preview.internal.domain"
gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments/${DEPLOY_ID}/statuses" \
  -f state="success" \
  -f environment_url="${PREVIEW_URL}" \
  -F auto_inactive=true
```

### B. Teardown Step
```bash
#!/usr/bin/env bash
set -euo pipefail

ENV_NAME="preview-pr-${PR_NUMBER}"

# Decommission active deployments
for id in $(gh api "repos/${GITHUB_REPOSITORY}/deployments?environment=${ENV_NAME}" --jq '.[].id'); do
  gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments/${id}/statuses" \
    -f state="inactive" || true
done

# Delete GitHub environment
gh api -X DELETE "repos/${GITHUB_REPOSITORY}/environments/${ENV_NAME}" || true
```
