# GitHub Rulesets & Branch Governance Specification

Comprehensive specification and implementation guide for GitHub Repository Rulesets (REST API `/repos/{owner}/{repo}/rulesets`).

---

## 1. Rulesets Architectural Overview

GitHub Rulesets replace legacy branch protection by decoupling targets, conditions, and enforcement policies into composable, audit-friendly rulesets.

### Key Ruleset Properties:
- **`target`**: `"branch"` or `"tag"`.
- **`enforcement`**:
  - `"active"`: Rule is enforced on all matching refs.
  - `"disabled"`: Rule is inactive.
  - *(Note: `"evaluate"` mode is restricted to GitHub Enterprise Cloud/Server organizations).*
- **`conditions`**: Ref targeting expressions (`~DEFAULT_BRANCH`, `refs/heads/main`, `refs/tags/v*`).
- **`bypass_actors`**: Array of roles, apps, or teams permitted to bypass specific rules (e.g., `RepositoryRole` with `role_id: 5` for Admin).

---

## 2. Complete RepositoryRuleType Catalog

GitHub supports 23 native rule types across branch and tag targets:

1. `creation`: Restricts branch/tag creation.
2. `update`: Prevents non-fast-forward updates or branch history rewrites.
3. `deletion`: Prevents branch or tag deletion.
4. `required_linear_history`: Disallows merge commits (fast-forward, squash, or rebase only).
5. `required_deployments`: Requires successful deployment to specified environments before merging.
6. `required_signatures`: Requires all commits pushed to the ref to have verified cryptographic GPG/SSH signatures.
7. `pull_request`: Enforces code review, approval counts, and dismissal policies prior to merging.
8. `required_status_checks`: Requires specific CI/CD jobs or status checks to pass before merging.
9. `non_fast_forward`: Blocks non-fast-forward pushes.
10. `commit_message_pattern`: Enforces regex on commit messages (e.g. Conventional Commits).
11. `commit_author_email_pattern`: Enforces email domain matching for commit authors.
12. `committer_email_pattern`: Enforces email domain matching for committers.
13. `branch_name_pattern`: Enforces naming conventions on branch creation (`feat/*`, `fix/*`).
14. `tag_name_pattern`: Enforces semver conventions on tag creation (`v*.*.*`).
15. `file_path_restriction`: Blocks pushes modifying restricted paths.
16. `max_file_path_length`: Limits file path depth.
17. `file_extension_restriction`: Blocks forbidden extensions (`.exe`, `.key`, `.pem`).
18. `max_file_size`: Restricts individual file sizes (e.g. 50MB limit).
19. `workflows`: Requires specific reusable GitHub Actions workflows to pass.
20. `code_scanning`: Requires CodeQL alerts of high/critical severity to be resolved.
21. `code_quality`: Enforces automated code quality metrics before merge.
22. `copilot_code_review`: Requires GitHub Copilot automated code review to pass.
23. `merge_queue`: Requires PRs to pass through a merge queue before merging into trunk.

---

## 3. Production Hardened Trunk Ruleset Template

The following template implements the OpenSSF Scorecard & SLSA Level 2+ recommended branch protection ruleset for `~DEFAULT_BRANCH`:

```bash
gh api -X POST /repos/:owner/:repo/rulesets --input - << 'EOF'
{
  "name": "Production Trunk Governance",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": [
        "~DEFAULT_BRANCH"
      ],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "required_linear_history"
    },
    {
      "type": "required_signatures"
    },
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
          {
            "context": "test"
          },
          {
            "context": "security-scan"
          }
        ]
      }
    }
  ],
  "bypass_actors": []
}
EOF
```

---

## 4. Protected Tag Immutability Ruleset (SLSA Release Protection)

To prevent supply chain poisoning of release binaries and Git tags, enforce tag creation and update restrictions:

```bash
gh api -X POST /repos/:owner/:repo/rulesets --input - << 'EOF'
{
  "name": "Immutable Release Tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": [
        "refs/tags/v*"
      ],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "update"
    },
    {
      "type": "deletion"
    },
    {
      "type": "required_signatures"
    }
  ],
  "bypass_actors": []
}
EOF
```

---

## 5. Inspection & Deletion Operations

```bash
# List all rulesets
gh api /repos/:owner/:repo/rulesets

# Inspect ruleset by ID
gh api /repos/:owner/:repo/rulesets/:ruleset_id

# Update existing ruleset
gh api -X PUT /repos/:owner/:repo/rulesets/:ruleset_id --input ruleset.json

# Delete ruleset
gh api -X DELETE /repos/:owner/:repo/rulesets/:ruleset_id
```
