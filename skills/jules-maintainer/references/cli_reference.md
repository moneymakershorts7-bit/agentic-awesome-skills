# Google Jules CLI Tools Reference (`@google/jules`)

Official package: `@google/jules`
CLI executable: `jules`

---

## 1. Installation & Authentication

### Installation
```bash
# Global install via npm or bun
npm install -g @google/jules
# or
bun add -g @google/jules
```

### Authentication
```bash
# Standard browser-assisted OAuth login
jules login

# Headless / remote server login (prints auth URL without opening browser)
jules login --no-launch-browser

# Logout
jules logout
```

---

## 2. Command Index

### `jules version`
Displays current CLI version and environment diagnostics.

### `jules` (Terminal User Interface)
Running `jules` without subcommands launches an interactive TUI for browsing repositories, active cloud sessions, reviewing diffs, and approving plans.
```bash
jules --theme dark   # Default
jules --theme light
```

### `jules remote list`
Lists cloud resources connected to Jules.
```bash
# List all GitHub repositories connected to Jules
jules remote list --repo

# List active and completed cloud coding sessions
jules remote list --session
```

### `jules remote new` / `jules new`
Starts an asynchronous cloud session. Jules automatically infers the current repository if run from a git clone.
```bash
# Inferred local repository:
jules remote new --session "Implement exponential backoff in client retries"

# Explicit repository target:
jules remote new --repo owner/repository --session "Add comprehensive unit tests for core module"

# Parallel session exploration (N candidate solutions in parallel):
jules remote new --parallel 3 "Refactor caching layer to use Redis instead of memory"
```

### `jules remote pull`
Pulls session diffs and artifacts locally.
```bash
# Inspect session diff without applying:
jules remote pull --session <SESSION_ID>

# Pull and apply patch directly to working tree:
jules remote pull --session <SESSION_ID> --apply
```

### `jules teleport`
Checks out a fresh temporary working branch with the session patch applied, allowing local verification and tests.
```bash
jules teleport <SESSION_ID>
```

### `jules completion`
Generates shell autocompletion scripts for bash, zsh, or fish.
```bash
jules completion bash > /etc/bash_completion.d/jules
```
