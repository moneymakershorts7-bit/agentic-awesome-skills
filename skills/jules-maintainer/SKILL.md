---
name: jules-maintainer
description: Autonomous asynchronous repository maintenance, background issue triage, and patch review using Google Jules CLI.
risk: safe
source: official
source_repo: google/jules
source_type: official
date_added: "2026-10-03"
---

# Jules Maintainer

Orchestrate Google's autonomous coding agent **Jules** (`jules`) to handle asynchronous repository maintenance, long-running refactors, issue resolution, and batch testing when interactive agents are offline or busy.

## When to Use

Use this skill when:
- Delegating long-running maintenance, test expansion, or dependency upgrades to run asynchronously in Google's cloud.
- The interactive agent needs to hand off tasks before ending a session or when offline.
- Triage and batch resolution of incoming GitHub issues are required without blocking local workflow.
- Exploring parallel implementation candidates (`--parallel <N>`) for complex tasks.
- Inspecting, reviewing, and applying completed Jules session diffs locally.

## Prerequisites & Setup

1. **Jules CLI Installed**:
   ```bash
   bun add -g @google/jules
   # or
   npm install -g @google/jules
   ```

2. **Authentication**:
   ```bash
   # Standard interactive login:
   jules login

   # Headless or terminal-only (no auto-launched browser):
   jules login --no-launch-browser
   ```

3. **Status Check**:
   ```bash
   jules version
   jules remote list --repo
   ```

## Asynchronous Maintenance Workflows

### 1. Dispatching Asynchronous Tasks

Start new remote background tasks for Jules directly from the local repository root:

```bash
# Delegate a scoped refactor or maintenance task
jules new "Update unit test coverage for tools/scripts and fix failing edge cases"

# Target a specific repository explicitly
jules new --repo user/project "Review open security advisories and prepare fixes"

# Generate 3 parallel exploration paths for a complex problem
jules new --parallel 3 "Refactor build pipeline to optimize caching and reduce CI time"
```

### 2. GitHub Issue Automated Dispatch

Chain GitHub CLI (`gh`) with Jules to dispatch open maintainer issues:

```bash
# Dispatch the first assigned open issue
gh issue list --assignee @me --limit 1 --json title,body -q '.[0] | "\(.title)\n\(.body)"' | jules new

# Batch dispatch high-priority issues to individual Jules sessions
gh issue list --label "maintenance" --limit 5 --json number,title --jq '.[] | "Fix issue #\(.number): \(.title)"' | while IFS= read -r task; do
  jules new "$task"
done
```

### 3. Monitoring & Reviewing Remote Sessions

List and inspect the state of dispatched sessions:

```bash
# List all active and completed sessions
jules remote list --session

# Launch the visual Terminal User Interface (TUI) for interactive review
jules
```

### 4. Pulling and Verifying Patches

Once a session completes, pull the changes and verify them locally before merging:

```bash
# Inspect the diff of a specific session without applying
jules remote pull --session <SESSION_ID>

# Pull and apply the patch directly to the working tree
jules remote pull --session <SESSION_ID> --apply

# Or clone and teleport into a clean branch with the patch applied
jules teleport <SESSION_ID>
```

### 5. Verification & Quality Gates

After pulling patches from a Jules session, always run local validation checks before committing:

```bash
# 1. Run linting and static checks
npm run lint

# 2. Run test suites
npm test

# 3. Check for security vulnerabilities or unintended changes
repo-audit
```
