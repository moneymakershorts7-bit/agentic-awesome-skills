---
name: github-platform-ops
description: Master GitHub Repository Settings, Modern Rulesets, Environments, OpenSSF Scorecard Hardening, Actions, and Git Plumbing via gh CLI, Git, and REST/GraphQL APIs.
license: MIT
risk: safe
source: internal
date_added: '2026-10-03'
allowed-tools:
  - bash
  - read
  - grep
---

# GitHub Platform Operations & Git Mastery Engine

Complete operational manual and declarative configuration suite for GitHub repository administration, branch governance, supply chain security, and advanced Git plumbing.

---

## When to Use

Use this skill when you need programmatic, deterministic control over:
1. **Repository Settings & Merge Policies:** Default branches, visibility, issues/wiki/discussions toggles, squash/merge/rebase configurations, commit title/body formatting, and auto-merge automation.
2. **Branch & Tag Rulesets (Modern GitHub Governance):** Enforcing linear history, commit signatures (GPG/SSH), pull request approval gates (code owners, stale dismissal, thread resolution), strict status checks, and release tag immutability.
3. **Supply Chain Security & OpenSSF Scorecard:** Token permissions (`permissions: read-all`), Dependabot alerts, Secret Scanning with Push Protection, CodeQL default setup, and Private Vulnerability Reporting (PVR).
4. **Deploy Environments & Secrets:** Environments, protection rules (reviewers, wait timers, branch policies), and NaCl-encrypted secrets/variables across environment, repository, and organization scopes.
5. **Actions Governance & CI/CD Debugging:** Allowed actions restrictions, fork pull request policies, runner groups, and targeted log debugging (`gh run view --log-failed`).
6. **Advanced Git Internals & Plumbing:** Scripting with `git hash-object`/`write-tree`/`commit-tree`/`update-ref`, parallel development with `git worktree`, conflict resolution caching with `git rerere`, and binary search debugging with `git bisect run`.

---

## 1. Repository Settings & Merge Strategies

Execute declarative configuration using `gh repo edit` or direct REST API payloads (`gh api -X PATCH /repos/:owner/:repo`):

```bash
# 1. Apply standardized PR and merge policies
gh repo edit :owner/:repo \
  --enable-squash-merge=true \
  --enable-merge-commit=false \
  --enable-rebase-merge=false \
  --squash-merge-commit-message pr-title-description \
  --enable-auto-merge=true \
  --delete-branch-on-merge=true \
  --allow-update-branch=true

# 2. Audit current configuration posture
gh api /repos/:owner/:repo --jq '{
  name: .name,
  visibility: .visibility,
  default_branch: .default_branch,
  features: { issues: .has_issues, wiki: .has_wiki, discussions: .has_discussions },
  pr_policy: { squash: .allow_squash_merge, merge: .allow_merge_commit, rebase: .allow_rebase_merge, auto_merge: .allow_auto_merge, delete_on_merge: .delete_branch_on_merge }
}'
```

Detailed payloads and options: [references/repo_settings_matrix.md](references/repo_settings_matrix.md).

---

## 2. Modern Branch & Tag Rulesets

Rulesets replace legacy branch protection with declarative, composable policy objects.

### Production Trunk Ruleset (SLSA Level 2+ Baseline)
```bash
gh api -X POST /repos/:owner/:repo/rulesets --input - << 'EOF'
{
  "name": "Production Trunk Governance",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
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
        "required_status_checks": [
          { "context": "test" },
          { "context": "security-scan" }
        ]
      }
    }
  ],
  "bypass_actors": []
}
EOF
```

Complete rule catalog and tag rulesets: [references/rulesets_governance.md](references/rulesets_governance.md).

---

## 3. Supply Chain Security & OpenSSF Hardening

Align repository configurations with OpenSSF Scorecard and SLSA recommendations:

```bash
# 1. Enforce least privilege for GITHUB_TOKEN (Read-Only)
gh api -X PUT /repos/:owner/:repo/actions/permissions/workflow \
  -F default_workflow_permissions="read" \
  -F can_approve_pull_request_reviews=false

# 2. Enable Dependabot alerts and automated patch PRs
gh api -X PUT /repos/:owner/:repo/vulnerability-alerts
gh api -X PUT /repos/:owner/:repo/automated-security-fixes

# 3. Enable Secret Scanning & Push Protection
gh repo edit :owner/:repo --enable-secret-scanning --enable-secret-scanning-push-protection

# 4. Enable Private Vulnerability Reporting
gh api -X PUT /repos/:owner/:repo/private-vulnerability-reporting
```

Detailed Scorecard checks: [references/ossf_scorecard_hardening.md](references/ossf_scorecard_hardening.md).

---

## 4. Deploy Environments, Secrets & Variables

```bash
# 1. Create protected environment with approval timers
gh api -X PUT /repos/:owner/:repo/environments/production \
  -f wait_timer=10 \
  -F prevent_self_review=true

# 2. Restrict deployments to protected branches
gh api -X PUT /repos/:owner/:repo/environments/production \
  --input - <<< '{"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}'

# 3. Manage environment-scoped secrets and variables
gh secret set DB_PASSWORD --env production --body "$DB_PASSWORD_VAL"
gh variable set API_BASE_URL --env production --body "https://api.internal"
```

Environment architecture guide: [references/environments_guide.md](references/environments_guide.md).

---

## 5. Actions Governance & Log Debugging

```bash
# 1. List recent runs
gh run list --limit 10

# 2. Extract only failed logs (massive token saving)
gh run view <run-id> --log-failed

# 3. Re-run only failed jobs
gh run rerun <run-id> --failed

# 4. Restrict allowed Actions to verified publishers
gh api -X PUT /repos/:owner/:repo/actions/permissions -f allowed_actions="selected"
```

Workflow design patterns: [references/workflows_mastery.md](references/workflows_mastery.md).

---

## 6. Advanced Git Plumbing & Diagnostics

Use deterministic Git plumbing for scripting and parallel maintenance:

```bash
# 1. Parallel work with worktrees
git worktree add ../feature-branch -b feat/service
git worktree list
git worktree remove ../feature-branch

# 2. Automate regression hunting with bisect run
git bisect start
git bisect bad HEAD
git bisect good v1.0.0
git bisect run npm test
git bisect reset

# 3. Enable conflict resolution reuse (rerere)
git config --global rerere.enabled true
git config --global rerere.autoUpdate true
```

Plumbing recipes & DAG internals: [references/git_plumbing_mastery.md](references/git_plumbing_mastery.md).

---

## Reference Documentation Index

- [references/repo_settings_matrix.md](references/repo_settings_matrix.md): Repository settings, merge policies, and topics.
- [references/rulesets_governance.md](references/rulesets_governance.md): GitHub Ruleset schema, 23 rule types, and production templates.
- [references/ossf_scorecard_hardening.md](references/ossf_scorecard_hardening.md): OpenSSF Scorecard 18 checks, SLSA provenance, and token permissions.
- [references/git_plumbing_mastery.md](references/git_plumbing_mastery.md): Git plumbing primitives, worktree workflows, rerere, and bisect run.
- [references/environments_guide.md](references/environments_guide.md): Deployment environments, protection gates, and secret scoping.
- [references/workflows_mastery.md](references/workflows_mastery.md): Actions matrix, concurrency control, and logging.
- [references/wiki_management.md](references/wiki_management.md): Dedicated Git wiki repository operations.
