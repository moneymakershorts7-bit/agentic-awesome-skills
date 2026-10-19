---
name: bash-master
description: Master autonomous Shell & Bash engineering platform and systems automation orchestrator specializing in modern Bash (Bash 5.2+/5.3+) and POSIX.1-2024 (sh) systems programming, defensive quote hygiene, atomic flock concurrency, and automated SecSDLC verification.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# `bash-master`: Enterprise Shell & Systems Automation Platform

`bash-master` is an autonomous Shell and Bash engineering platform specializing in production-hardened Bash 5.2+/5.3+ and POSIX.1-2024 (`sh`) systems programming. Rejecting both monolithic god-scripts and fragile unverified pipelines, `bash-master` operates on the **Frontier Orchestrator-Worker Standard**, enforcing bounded functional slicing, deterministic testing, and continuous SecSDLC verification.

---

## 1. Core Architecture: 4 Domain Workers + 1 Verifier

```
                         ┌────────────────────────────────────┐
                         │   bash-master Lead Orchestrator    │
                         └─────────────────┬──────────────────┘
                                           │
         ┌───────────────────┬─────────────┴───────┬───────────────────┐
         ▼                   ▼                     ▼                   ▼
┌─────────────────┐ ┌─────────────────┐   ┌─────────────────┐ ┌─────────────────┐
│     Agent 1     │ │     Agent 2     │   │     Agent 3     │ │     Agent 4     │
│ Defensive Bash  │ │ POSIX Standards │   │ Concurrency, IPC│ │ Security, CWE-78│
│ & Quote Hygiene │ │ & Portability   │   │ & flock Locks   │ │ & Sanitization  │
└────────┬────────┘ └────────┬────────┘   └────────┬────────┘ └────────┬────────┘
         │                   │                     │                   │
         └───────────────────┼─────────────────────┴───────────────────┘
                             │ Dispatched Contract
                             ▼
                 ┌──────────────────────────────────────┐
                 │     Agent 5: Verifier QA Agent       │
                 │  • ShellCheck Style (--enable=all)   │
                 │  • shfmt Canonical (-i 2 -ci -bn)   │
                 │  • checkbashisms (0 /bin/sh leaks)   │
                 │  • Bats-Core 100% Test Suite Pass    │
                 │  • lizard Cyclomatic Complexity <=10 │
                 └──────────────────────────────────────┘
```

1. **Agent 1 (`defensive-bash-architect`)**: Enforces strict `set -euo pipefail`, explicit parameter expansion braces `"${var}"`, non-zero return value preservation (banning `local var="$(cmd)"` in single statements), and predictable arrays.
2. **Agent 2 (`posix-portability-engineer`)**: Produces strict POSIX.1-2024 compliance for `/bin/sh` scripts, eliminating non-portable bashisms (`[[ ]]`, `==`, `local`, `function`, `$'...'`, `${var//pat/repl}`) and GNU-specific CLI flags (`sed -i`, `date -d`).
3. **Agent 3 (`concurrency-ipc-engineer`)**: Manages kernel-level atomic advisory lockfiles (`flock`), signal trap stacks (`EXIT`, `INT`, `TERM`, `HUP`), bounded worker pools via `wait -n`, and TOCTOU elimination.
4. **Agent 4 (`security-secsdlc-auditor`)**: Detects and remediates CWE-78 OS Command Injection (blocking `eval` and unquoted subshell interpolations), hardcoded secrets/API keys, insecure temporary files, and cleanses the runtime environment (`PATH`, `umask 077`, non-root user).
5. **Agent 5 (`verifier-qa`)**: Independent adversarial QA checker executing ShellCheck in style mode (`--enable=all`), `shfmt`, `checkbashisms`, and Bats test suites.

---

## 2. CLI Invocation Reference

The platform provides dual entrypoints: `/home/npirela/bash-master/bin/bash-master` (pure Shell) and `python3 ~/.agents/skills/bash-master/scripts/bash_master_cli.py` (companion CLI).

### Common Commands
```bash
# 1. Vectorless BM25 Standards Search across canonical books
./bin/bash-master search-corpus "command injection CWE-78" 5

# 2. Display 38+ FOSS Toolchain Matrix
./bin/bash-master toolchain-matrix
./bin/bash-master export-toolchain # Outputs normalized JSON

# 3. Independent Verification Battery on any Shell script
./bin/bash-master verify path/to/script.sh

# 4. 30-Day Documentation Freshness Cadence Audit
./bin/bash-master check-docs-cadence
./bin/bash-master update-docs --force # Recalculates SHA-256 manifests

# 5. Worker Contract Execution with Self-Healing Loop
./bin/bash-worker contracts/sample_slice_001.json
```

---

## 3. Engineering Invariants & Quality Standards

- **Strict Quoting**: Every variable expansion MUST be enclosed in double quotes: `"${var}"`.
- **No Masked Returns**: Never combine `local`, `export`, or `readonly` with command substitutions in the same statement:
  ```bash
  # Prohibited (SC2155):
  local res="$(compute_status)"
  
  # Required:
  local res
  res="$(compute_status)"
  readonly res
  ```
- **Execution Header**: Every production Bash script begins with:
  ```bash
  #!/usr/bin/env bash
  set -euo pipefail
  IFS=$'\n\t'
  umask 077
  ```
- **POSIX Scripts**: Shebang must be `#!/bin/sh` and pass `checkbashisms -f -x` with zero warnings.
- **Complexity Bound**: Every function MUST satisfy Cyclomatic Complexity **CC <= 10** (`lizard -C 10`).
- **Zero Suppression Anti-Pattern**: ShellCheck suppressions (`# shellcheck disable=...`) are banned unless mathematically unavoidable and fully documented.
- **Rootless Container**: Dockerfiles must execute under unprivileged user (`USER bashdev` or non-root UID 1000).

---

## 4. Progressive Disclosure References

For detailed specifications, workflows, and runbooks:
- [Agent Execution Contracts & FSM](file:///home/npirela/.agents/skills/bash-master/references/agent_contracts.md): JSON schema, state transitions, and self-healing diagnostic recovery.
- [38+ FOSS Toolchain Matrix](file:///home/npirela/.agents/skills/bash-master/references/toolchain_matrix.md): Exhaustive tool catalog, installation recipes, and verification patterns.
- [Troubleshooting Playbook](file:///home/npirela/.agents/skills/bash-master/references/troubleshooting_playbook.md): Diagnostic runbooks for SC2086, SC2155, SC2046, lockfile deadlocks, subshell variable loss, and SIGPIPE handling.
