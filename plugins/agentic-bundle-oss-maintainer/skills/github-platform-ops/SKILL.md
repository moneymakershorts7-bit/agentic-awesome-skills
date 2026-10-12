---
name: github-platform-ops
description: Master GitHub Repository Settings, Modern Rulesets, Deployment Environments, Ephemeral Previews, CI/CD Testing Frameworks, Actions Governance, and Git Plumbing via gh CLI, Git, and REST/GraphQL APIs.
license: MIT
risk: safe
source: internal
date_added: '2026-10-03'
allowed-tools:
  - bash
  - read
  - grep
---

# GitHub Platform Operations & CI/CD Environment Mastery Engine

Complete operational manual and declarative configuration suite for GitHub repository administration, CI/CD environment creation, pipeline testing frameworks, branch governance, supply chain security, and advanced Git plumbing.

---

## When to Use

Use this skill when you need programmatic, deterministic control over:
1. **CI/CD Environments & Deployment Protection:** Creating environments, setting manual approvals (`reviewers`), canary delays (`wait_timer`), deployment branch policies, isolated secrets/variables, and tracking deployments via the Deployments API.
2. **Ephemeral / Preview Environments:** Automating isolated PR preview stacks, emitting native GitHub Deployment Status events (`in_progress`, `success`, `inactive`), and triggering teardown hooks on PR closure.
3. **CI/CD Testing & Local Simulation:** Local execution with `act`, programmable pipelines with Dagger/Earthly, test matrix pruning, Vitest/Jest test sharding, and security linting (`actionlint`, `shellcheck`, `zizmor`).
4. **Repository Settings & Merge Strategies:** Default branches, visibility, issues/wiki/discussions toggles, squash/merge/rebase configurations, commit title/body formatting, and auto-merge automation.
5. **Branch & Tag Rulesets (Modern Governance):** Enforcing linear history, commit signatures (GPG/SSH), pull request approval gates (code owners, stale dismissal, thread resolution), strict status checks, and release tag immutability.
6. **Actions Governance & Infrastructure Administration:** Actions Runner Groups, ephemeral autoscaling (ARC), workflow token permissions (`permissions: read-all`), Actions cache inspection/purging (`/actions/caches`), Pages configuration, and Autolink ticketing integrations.
7. **Advanced Git Internals & Plumbing:** Scripting with `git hash-object`/`write-tree`/`commit-tree`/`update-ref`, parallel development with `git worktree`, conflict resolution caching with `git rerere`, and binary search debugging with `git bisect run`.

---

## 1. CI/CD Deployment Environments & Protection Rules

Provision environments and enforce deployment gates using the REST API:

```bash
# 1. Create protected environment with required reviewer and wait timer
gh api -X PUT /repos/:owner/:repo/environments/production --input - << 'EOF'
{
  "wait_timer": 15,
  "prevent_self_review": true,
  "reviewers": [
    { "type": "User", "id": 272625412 }
  ],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
EOF

# 2. Add custom branch and tag deployment policies
gh api -X POST /repos/:owner/:repo/environments/production/deployment-branch-policies -f name="main" -f type="branch"
gh api -X POST /repos/:owner/:repo/environments/production/deployment-branch-policies -f name="v*.*.*" -f type="tag"

# 3. Manage environment-scoped secrets and variables
gh secret set DB_PASSWORD --env production --body "$DB_PASSWORD_VAL"
gh variable set API_BASE_URL --env production --body "https://api.internal"
```

Detailed payloads and options: [references/environments_guide.md](references/environments_guide.md).

---

## 2. Ephemeral Preview Environments & GitHub Deployments API

Manage the lifecycle of temporary PR environments directly through GitHub's Deployments API:

```bash
# 1. Register an ephemeral deployment for PR #42
gh api -X POST /repos/:owner/:repo/deployments --input - << 'EOF'
{
  "ref": "refs/pull/42/head",
  "task": "deploy",
  "auto_merge": false,
  "environment": "preview-pr-42",
  "transient_environment": true,
  "production_environment": false
}
EOF

# 2. Publish deployment success with live preview URL
gh api -X POST /repos/:owner/:repo/deployments/:deployment_id/statuses --input - << 'EOF'
{
  "state": "success",
  "environment_url": "https://preview-pr-42.apps.domain.com",
  "auto_inactive": true
}
EOF

# 3. Teardown on PR closure (mark inactive & delete environment)
gh api -X POST /repos/:owner/:repo/deployments/:deployment_id/statuses -f state="inactive"
gh api -X DELETE /repos/:owner/:repo/environments/preview-pr-42
```

Complete workflow implementations: [references/ephemeral_preview_environments.md](references/ephemeral_preview_environments.md).

---

## 3. CI/CD Testing Frameworks, Local Emulation & Linters

Run deterministic local pipelines and static security verification:

```bash
# 1. Local GitHub Actions simulation with act
act push -j test
act pull_request -s GITHUB_TOKEN="mock_token"

# 2. Pipeline syntax, shell and security audits
actionlint .github/workflows/*.yml
shellcheck -s bash .github/scripts/*.sh
zizmor .github/workflows/

# 3. Cache inspection and cleanup via gh API
gh api /repos/:owner/:repo/actions/caches --jq '.actions_caches[] | {id: .id, key: .key, size_mb: (.size_in_bytes / 1048576 | floor)}'
gh api -X DELETE /repos/:owner/:repo/actions/caches/:cache_id
```

Matrix sharding and caching guides: [references/cicd_testing_frameworks.md](references/cicd_testing_frameworks.md).

---

## 4. Modern Branch & Tag Rulesets

Deploy composable, declarative rulesets across branches and release tags:

```bash
gh api -X POST /repos/:owner/:repo/rulesets --input - << 'EOF'
{
  "name": "Production Trunk Governance",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    { "type": "required_signatures" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [{ "context": "test" }, { "context": "security-scan" }]
      }
    }
  ],
  "bypass_actors": []
}
EOF
```

Complete ruleset catalog (23 rule types): [references/rulesets_governance.md](references/rulesets_governance.md).

---

## 5. Granular Infrastructure: Runner Groups, Pages & Autolinks

```bash
# 1. Configure Actions Runner Group for isolated compute
gh api -X POST /orgs/:org/actions/runner-groups \
  -f name="isolated-production-runners" -f visibility="selected"

# 2. Configure GitHub Pages in workflow-driven mode
gh api -X POST /repos/:owner/:repo/pages -f build_type="workflow"

# 3. Register ticketing autolink (Jira / Linear)
gh api -X POST /repos/:owner/:repo/autolinks \
  -f key_prefix="PROJ-" -f url_template="https://jira.internal/browse/PROJ-<num>"
```

Granular settings specifications: [references/granular_github_administration.md](references/granular_github_administration.md).

---

## 6. Advanced Git Plumbing & Diagnostics

```bash
# 1. Parallel branch isolation with git worktree
git worktree add ../feature-auth -b feat/auth
git worktree list
git worktree remove ../feature-auth

# 2. Automated regression pinpointing with git bisect run
git bisect start
git bisect bad HEAD
git bisect good v1.0.0
git bisect run npm test
git bisect reset

# 3. Reusable conflict resolution with rerere
git config --global rerere.enabled true
git config --global rerere.autoUpdate true
```

Plumbing recipes & DAG internals: [references/git_plumbing_mastery.md](references/git_plumbing_mastery.md).

---

## Reference Documentation Index

- [references/environments_guide.md](references/environments_guide.md): Deployment environments, wait timers, reviewers, and secret scoping.
- [references/ephemeral_preview_environments.md](references/ephemeral_preview_environments.md): PR preview lifecycle, Deployments API, and automated teardown.
- [references/cicd_testing_frameworks.md](references/cicd_testing_frameworks.md): Local emulation (`act`), test sharding, caching, and security linters (`zizmor`, `actionlint`).
- [references/granular_github_administration.md](references/granular_github_administration.md): Runner groups, ephemeral ARC runners, Pages, autolinks, and custom properties.
- [references/repo_settings_matrix.md](references/repo_settings_matrix.md): Repository settings, merge policies, and topics.
- [references/rulesets_governance.md](references/rulesets_governance.md): GitHub Ruleset schema, 23 rule types, and production templates.
- [references/ossf_scorecard_hardening.md](references/ossf_scorecard_hardening.md): OpenSSF Scorecard 18 checks, SLSA provenance, and token permissions.
- [references/git_plumbing_mastery.md](references/git_plumbing_mastery.md): Git plumbing primitives, worktree workflows, rerere, and bisect run.
- [references/workflows_mastery.md](references/workflows_mastery.md): Actions matrix, concurrency control, and logging.
- [references/wiki_management.md](references/wiki_management.md): Dedicated Git wiki repository operations.
