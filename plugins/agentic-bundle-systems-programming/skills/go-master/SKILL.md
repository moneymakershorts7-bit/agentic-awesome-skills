---
name: go-master
description: Enterprise-grade autonomous Go (Golang) engineering platform and orchestrator harness. Coordinates 4 domain-specialized Go agents (concurrency-architect, perf-optimizer, api-engineer, security-auditor) and 1 independent adversarial verification gate (verifier-qa), grounded in canonical literature and 38+ FOSS Go engineering tools.
allowed-tools:
  - run_command
  - Bash
  - shell
  - view_file
  - replace_file_content
  - write_to_file
---

# `go-master`: Autonomous Go Engineering Platform & Orchestrator Harness

`go-master` is an enterprise-grade autonomous engineering platform for Go (Golang) applications, microservices, and system libraries located at `/home/npirela/go-master`. It eliminates both the *Monolithic God-Agent* and *Chatty Role-Playing Committee* anti-patterns through a strict **Orchestrator-Worker Architecture** with **Maker/Checker Orthogonality**.

---

## 1. Non-Negotiable Invariants

> [!IMPORTANT]
> Whenever designing, modifying, refactoring, profiling, auditing, or verifying code in the Go programming language, the agent **MUST ALWAYS** invoke and adhere to `go-master`.

1. **100% Pure Go Implementation**: Core engine is written in pure, idiomatic Go (`go.mod`, `go.sum`).
2. **Deterministic Compiler Verification**: All changes must pass `go test -race` (LLVM ThreadSanitizer) and `go vet` with 0 errors.
3. **Goroutine Leak Discipline**: Zero goroutine leaks verified by Uber `goleak`.
4. **Tool-First Literature Grounding**: All architectural claims and patterns must be grounded in canonical literature via vectorless TF-IDF search.
5. **Cyclomatic Complexity Discipline**: No function or method shall exceed a Cyclomatic Complexity (CC) of 10.

---

## 2. Specialized Agent Directory

| Agent ID | Role | Core Domain & Invariants | Key Tools |
| :--- | :--- | :--- | :--- |
| **`concurrency-architect`** | Concurrency & Systems Architect | CSP, Goroutines, Channels, `sync/atomic`, `sync.Cond`, `errgroup`. Context must be 1st parameter; never in structs. Explicit goroutine lifecycles. | `go-test-race`, `uber-goleak`, `go-deadlock` |
| **`perf-optimizer`** | High-Performance, Memory & GC Optimizer | Escape analysis (`-gcflags="-m"`), zero-alloc hot paths, slice preallocation, `sync.Pool`, struct alignment & cache padding. | `pprof`, `benchstat`, `trace`, `godebug` |
| **`api-engineer`** | Reliability, Error Handling & API Engineer | Go 1.13+ error wrapping (`%w`, `errors.Is`, `errors.As`), clean API surface, functional options, context timeouts on all I/O. | `golangci-lint`, `revive`, `staticcheck` |
| **`security-auditor`** | Security, SecSDLC & Cloud-Native Hardening | `govulncheck`, `go mod verify`, AST SQL/Command injection auditing, `crypto/rand`, non-root distroless containers (UID 65532). | `gosec`, `trivy`, `cyclonedx-gomod`, `gitleaks` |
| **`verifier-qa`** | Independent Adversarial Verification Agent | Independent gatekeeper with **strict veto power**. Enforces race freedom, leak freedom, linters, and native fuzz/mutation testing. | `go test -race`, `uber-goleak`, `go-mutesting` |

---

## 3. Operational CLI Protocols

Use `/home/npirela/go-master/bin/go-master` or the python driver `python3 /home/npirela/.agents/skills/go-master/scripts/go_master_cli.py`:

### A. Autonomous Orchestration (Worker + Verifier Loop)
Dispatches bounded functional slices to specialized domain agents followed by adversarial QA verification:
```bash
/home/npirela/go-master/bin/go-master orchestrate [--contract <path.json>]
```

### B. Independent Adversarial Verification Gate
Run Agent 5 (`verifier-qa`) directly against the target workspace:
```bash
/home/npirela/go-master/bin/go-master verify-slice
```

### C. Canonical Literature Search (Vectorless TF-IDF)
Retrieve exact line-accurate snippets, books, and chapters from authoritative Go references:
```bash
/home/npirela/go-master/bin/go-master search-corpus --query "happens-before channel"
```

### D. 38+ FOSS Toolchain Audit
Inspect installed status and recipes for all 40 canonical Go tools:
```bash
/home/npirela/go-master/bin/go-master toolchain-audit
```

### E. 30-Day Documentation Freshness Cadence
Check freshness status and refresh manifest:
```bash
/home/npirela/go-master/bin/go-master check-docs-cadence
/home/npirela/go-master/bin/go-master update-docs
```

### F. DevSecOps SecSDLC Quality Gate
Execute complete SecSDLC quality scorecard:
```bash
python3 /home/npirela/.agents/skills/devsecops-master/scripts/go_master_gate.py <project_path>
```

---

## 4. Progressive Disclosure References

- Detailed Contract Schema & FSM: [`references/agent_contracts.md`](references/agent_contracts.md)
- Complete 38+ Toolchain Matrix & Install Recipes: [`references/toolchain_matrix.md`](references/toolchain_matrix.md)
- Diagnostics & Self-Healing Runbooks: [`references/troubleshooting_playbook.md`](references/troubleshooting_playbook.md)
