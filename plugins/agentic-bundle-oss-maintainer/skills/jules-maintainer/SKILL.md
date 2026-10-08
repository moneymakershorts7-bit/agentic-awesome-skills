---
name: jules-maintainer
description: Autonomous asynchronous repository maintenance, background issue triage, and patch review using Google Jules CLI and REST API.
license: Apache-2.0
metadata:
  allowed-domains: '["jules.googleapis.com"]'
  aas-risk: safe
  aas-source: official
  aas-date-added: '2026-10-04'
  aas-permissions: '["shell","file_read","network"]'
allowed-tools: Bash Read Write Edit Grep
---

# Jules Maintainer (Google Jules Coding Agent)

Orchestrate Google's autonomous cloud coding agent **Jules** (`https://jules.google`) to delegate asynchronous repository maintenance, long-running refactors, issue resolution, and batch testing without blocking local agent sessions.

Jules runs tasks inside secure, isolated Ubuntu cloud VMs with preinstalled toolchains (Node 22, Bun, Python 3.12 with uv, Go 1.24, Rust 1.87, Java 21, Docker). It natively reads project guidelines (`AGENTS.md`) at repository root to discover build, test, and contribution rules.

---

## When to Use
- **Asynchronous Task Delegation**: Hand off long-running maintenance, unit test expansion, or dependency upgrades to run autonomously in Google's cloud.
- **Offline / Session Handoff**: Dispatch tasks to Jules before ending an interactive coding session or when operating with constrained local resources.
- **Automated Issue Triage**: Chain `gh issue` with Jules to dispatch and solve GitHub issues into draft PRs.
- **Parallel Solution Exploration**: Launch `--parallel <N>` exploration candidates to compare architectural approaches.
- **Continuous AI Maintenance**: Configure scheduled tasks (Performance, UX/Design, Security) or proactive Suggested Tasks (`#TODO` remediation).

---

## Tooling & Operation Modes

Jules provides two primary orchestration interfaces:

| Interface | Mechanism | Best For |
| :--- | :--- | :--- |
| **Jules CLI (`jules`)** | `@google/jules` npm/bun package | Interactive terminal usage, TUI navigation, local git branch checkout (`teleport`). |
| **Jules REST API** | Official `v1alpha` endpoints via `curl` | Headless execution, CI/CD pipelines, agent programmatic control via `JULES_API_KEY`. |

---

## Mode 1: REST API Orchestration (`https://jules.googleapis.com/v1alpha`)

The official Google Jules REST API enables programmatic session orchestration from any shell or automation script.

### 1. Prerequisites & Authentication
Generate your API key in the [Jules Web App](https://jules.google.com) under **Settings** (supports up to 3 active keys).
Store securely in your local environment (`~/.config/jules/env`), never committed to git:
```bash
# Load securely from local environment (~/.config/jules/env)
export JULES_API_KEY=${JULES_API_KEY}
```

### 2. Standard REST API Workflows

#### List Connected Sources (Repositories)
```bash
curl -s -H "x-goog-api-key: $JULES_API_KEY" \
  https://jules.googleapis.com/v1alpha/sources
```

#### Dispatch Task with Automatic PR Creation
```bash
curl -s -X POST https://jules.googleapis.com/v1alpha/sessions \
  -H "x-goog-api-key: $JULES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Refactor error handling in src/api to use typed domain exceptions",
    "title": "Refactor domain errors",
    "sourceContext": {
      "source": "sources/github/owner/repo",
      "githubRepoContext": {
        "startingBranch": "main"
      }
    },
    "automationMode": "AUTO_CREATE_PR"
  }'
```

#### Monitor Session & Retrieve PR Output
```bash
curl -s -H "x-goog-api-key: $JULES_API_KEY" \
  https://jules.googleapis.com/v1alpha/sessions/<SESSION_ID>
```

#### List Session Activities (Plan, Agent Thoughts, Execution Logs)
```bash
curl -s -H "x-goog-api-key: $JULES_API_KEY" \
  "https://jules.googleapis.com/v1alpha/sessions/<SESSION_ID>/activities?pageSize=50"
```

#### Approve Plan (When `requirePlanApproval: true`)
```bash
curl -s -X POST "https://jules.googleapis.com/v1alpha/sessions/<SESSION_ID>:approvePlan" \
  -H "x-goog-api-key: $JULES_API_KEY" \
  -H "Content-Type: application/json"
```

#### Send User Feedback to Active Session
```bash
curl -s -X POST "https://jules.googleapis.com/v1alpha/sessions/<SESSION_ID>/activities" \
  -H "x-goog-api-key: $JULES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Ensure backwards compatibility for v1 clients"}'
```

*For full schemas and error codes, see [references/api_reference.md](references/api_reference.md).*

---

## Mode 2: Jules CLI Orchestration (`@google/jules`)

### 1. Installation & Authentication
```bash
# Install globally
bun add -g @google/jules
# or: npm install -g @google/jules

# Authenticate with Google account
jules login

# For headless servers (no auto-launched browser):
jules login --no-launch-browser
```

### 2. Dispatching Tasks
```bash
# Dispatch task on current repo (inferred automatically from git)
jules remote new --session "Add comprehensive unit tests for auth middleware"

# Explicit repository target:
jules remote new --repo owner/repo --session "Upgrade dependencies and fix breaking changes"

# Parallel candidate exploration (generates 3 candidate solutions):
jules remote new --parallel 3 "Optimize database queries in user service"
```

### 3. Monitoring & Local Verification
```bash
# List remote sessions and active status
jules remote list --session

# Launch interactive visual Terminal User Interface (TUI)
jules

# Inspect diff without applying:
jules remote pull --session <SESSION_ID>

# Apply patch directly to local working tree:
jules remote pull --session <SESSION_ID> --apply

# Or teleport into a clean branch with the patch pre-applied:
jules teleport <SESSION_ID>
```

*For complete CLI flags and options, see [references/cli_reference.md](references/cli_reference.md).*

---

## Workflow: GitHub Issue Dispatch Pipeline

Combine GitHub CLI (`gh`) with Jules to resolve repository issues automatically:

```bash
# 1. Fetch assigned issue body and dispatch to Jules with auto PR
ISSUE_DATA=$(gh issue view 42 --json title,body -q '"\(.title)\n\n\(.body)"')
curl -s -X POST https://jules.googleapis.com/v1alpha/sessions \
  -H "x-goog-api-key: $JULES_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"prompt\": \"Resolve issue #42: $ISSUE_DATA\",
    \"sourceContext\": {\"source\": \"sources/github/owner/repo\"},
    \"automationMode\": \"AUTO_CREATE_PR\"
  }"

# 2. Batch dispatch backlog issues labeled 'good-first-issue'
gh issue list --label "good-first-issue" --limit 3 --json number,title --jq '.[] | "Fix issue #\(.number): \(.title)"' | while IFS= read -r task; do
  jules remote new --session "$task"
done
```

---

## Optimizing Repositories for Jules (`AGENTS.md`)

Jules automatically reads `AGENTS.md` at repository root. To ensure Jules executes tests and follows project standards correctly:

1. Specify exact setup and test verification commands (`pnpm test`, `pytest`, `cargo test`).
2. Declare code conventions and architectural constraints.
3. Define handling for `#TODO` items and proactive tasks.

*See [references/agents_md_template.md](references/agents_md_template.md) for a ready-to-use template.*

---

## Quality Gates & Verification Checklist

Before merging or accepting patches generated by Jules:
1. **Pull & Inspect**: Check the diff with `jules remote pull --session <ID>` or review the PR generated on GitHub.
2. **Local Validation**:
   - Run type checking: `tsc --noEmit` or `mypy`.
   - Run linter: `eslint` or `ruff check`.
   - Run test suite: `pytest` or `vitest` / `jest`.
3. **Security Audit**: Ensure no unexpected dependencies or external network calls were introduced.

---

## Dual-Mode Maintenance Automation (`skills-maintainer`)

The repository maintainer CLI (`skills-maintainer`) seamlessly bridges the official Jules CLI and the headless REST API:

```bash
# Check CLI version and runtime
skills-maintainer jules version

# List remote sessions or connected repositories (CLI or REST API fallback)
skills-maintainer jules list [--repo|--session]

# Pull code diffs or inspect session output
skills-maintainer jules pull <SESSION_ID> [--apply]

# Dispatch ad-hoc prompt
skills-maintainer jules new "Fix flaky end-to-end auth tests"

# Dispatch specialized autonomous sentinels
skills-maintainer jules security   # Multi-engine security audit
skills-maintainer jules docs       # Documentation & Wiki sync
skills-maintainer jules optimize   # Performance & Progressive Disclosure
skills-maintainer jules ci-fix     # CI/CD and Dependabot auto-healing
skills-maintainer jules malware    # Supply-chain & reverse shell scanner
skills-maintainer jules discovery  # Daily GitHub Scout for new Skills & MCPs

# Review and arbitrate staged discoveries (Monthly Maintenance Sweep)
skills-maintainer review-discovery --dossier  # Inspect candidate skills and MCPs
skills-maintainer review-discovery --audit    # Run security scans on candidates
skills-maintainer review-discovery --accept <id|all-safe> # Promote candidate
skills-maintainer review-discovery --reject <id> --reason "..." # Reject candidate
```

---

## Daily Discovery Scout & Monthly Triage Protocol

1. **Daily GitHub Scout (Jules Cloud Sentinel)**:
   - At `06:00 UTC` daily, Jules executes `tools/scripts/discovery_scout.py` to search GitHub for newly released Agent Skills and MCP servers.
   - De-duplicates against existing catalog in `skills/` and `skills_index.json`.
   - Stages candidate skills under `staging/discovery/YYYY-MM-DD/skills/` and MCP configurations under `staging/discovery/YYYY-MM-DD/mcps/`.
   - Generates daily scouting report at `docs/discovery/YYYY-MM-DD.md` and appends to `docs/discovery/LEDGER.md`.
   - Opens an atomic PR on branch `jules/daily-discovery-YYYY-MM-DD`.

2. **Daily GitHub Wiki Synchronizer (Jules Documentation Sentinel)**:
   - At `06:30 UTC` daily (or triggered on catalog updates), Jules and GitHub Actions execute `tools/scripts/generate_wiki.py --sync` via `.github/workflows/daily-wiki-sync.yml`.
   - Generates fully indexed `Home.md`, `_Sidebar.md`, `Skills-Catalog.md` (2,764+ skills), `Editorial-Bundles.md` (59 bundles), `Daily-Discovery.md`, and `Free-For-Dev-Directory.md` (1,300+ free tools).
   - Commits and pushes updates atomically to `https://github.com/<owner>/<repo>.wiki.git`.

3. **Monthly Repository Maintenance Decision Gate**:
   - On the 1st of each month (during `skills-maintainer all`):
   - The maintainer/agent runs `skills-maintainer review-discovery --dossier` to inspect all candidates gathered over the month.
   - Evaluates each candidate against quality, utility, and safety criteria (`skills-maintainer review-discovery --audit`).
   - Promotes approved skills/MCPs (`--accept <id>`) or discards duplicates/low-quality items (`--reject <id>`).

*For detailed search queries, risk thresholds, and schemas, see [references/discovery_scout.md](references/discovery_scout.md).*

---

## Limitations

- **Asynchronous Execution Only**: Jules is not designed for synchronous, sub-second terminal interactions; tasks run as cloud jobs with turn-around times of 1–5 minutes.
- **Merge Authority**: Jules operates under strict restrictive governance; it only proposes pull requests and cannot push or merge directly to `main`.
- **Public & Connected GitHub Sources Only**: Jules currently requires repositories connected via GitHub App permissions; local non-git folders cannot be dispatched directly without pushing.

