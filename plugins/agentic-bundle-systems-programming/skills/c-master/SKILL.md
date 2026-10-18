---
name: c-master
description: Autonomous C systems engineering platform and agent orchestrator for modern, production-hardened C (ISO/IEC 9899:2024 C23, C17/C11, POSIX.1-2024, Linux systems). Orchestrates 4 domain-specialized workers (memory-architect, runtime-perf-optimizer, systems-architect, security-auditor) and 1 independent adversarial verification gate (verifier-qa), grounded in 7 canonical ISO literature texts and an exhaustive 38+ FOSS C toolchain.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# `c-master`: Autonomous C Systems Engineering Platform & Agent Orchestrator

`c-master` is an enterprise-grade autonomous C systems engineering platform and orchestrator specializing in modern, pure, production-hardened C (ISO/IEC 9899:2024 C23, C17, POSIX.1-2024, and Linux low-level systems). It implements a strict decoupled Orchestrator-Worker state machine featuring **4 Domain-Specialized C Systems Workers** and **1 Independent Adversarial Verification Agent (QA & Sanitizers)**.

---

## 1. Non-Negotiable Invariants

> **MANDATORY POLICY:** Whenever writing, modifying, refactoring, benchmarking, or auditing C code, the agent **MUST ALWAYS** invoke and adhere to `c-master`.

1. **Strict Language & Ecosystem Purity:**
   The `c-master` core engine and public APIs are 100% pure standard C (C23 / C17 / POSIX with modern CMake 3.28+). Zero C++ or foreign language runtime wrappers in the core domain.
2. **Deterministic Task + Playbook Execution Contracts:**
   Every slice of work is executed through a deterministic contract enforcing:
   $$\text{DISPATCHED} \longrightarrow \text{RUNNING} \longrightarrow \text{VERIFYING} \longrightarrow (\text{COMPLETED} \mid \text{FAILED\_HEALING\_LOOP})$$
3. **Orthogonal Adversarial Verification (`verifier-qa`):**
   The verification agent operates with unconditional veto power. A slice CANNOT reach `COMPLETED` unless:
   - Zero compiler warnings under `-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes`.
   - AddressSanitizer (ASan) + UndefinedBehaviorSanitizer (UBSan) runs 100% clean with zero undefined behavior.
   - Cyclomatic Complexity (CC) <= 10 across every function.
   - Deterministic test suite passes with 100% assertions green.
4. **30-Day Documentation Freshness Cadence:**
   All specifications and canonical books are tracked in `.docs_manifest.json` with uppercase SHA-256 hashes and audited every 30 days.

---

## 2. The 5 Specialized C Systems & Enterprise Agents

| Agent Identifier | Domain Specialization | Core Invariants Enforced | Literature Grounding |
| :--- | :--- | :--- | :--- |
| **`memory-architect`** | Memory Safety & Pointer Ownership | Explicit pointer ownership (OWNED, BORROWED, TRANSFERRED), C23 `nullptr`, arena/bump/pool allocators, bounded strings (`cmaster_strlcpy`). Zero leaks, zero double-frees. | *ISO C23 Spec*, *Advanced C Memory Architectures* |
| **`runtime-perf-optimizer`** | High-Performance & Concurrency | Cache line alignment (`alignas(64)`), descending struct field order, lock-free SPSC ring buffers, ISO C11/C23 `<stdatomic.h>` with acquire-release memory orderings, zero false sharing. | *Algorithms & Concurrency in C: Lock-Free & Atomics*, *High Performance Systems* |
| **`systems-architect`** | POSIX, Modular API & Clean Architecture | Opaque pointer handle encapsulation (PIMPL / ABI stability), independent headers, deterministic integer return codes with out-parameters, async-signal-safe handlers. | *Linux System Programming & POSIX.1-2024*, *Modern C (Gustedt)* |
| **`security-auditor`** | Security, Defect Prevention & MISRA/CERT | C23 `<stdckdint.h>` overflow-checked arithmetic, strict aliasing compliance, cryptographic zeroing (`cmaster_secure_zero`), constant-time memory compare, compiler hardening flags. | *SEI CERT C Coding Standard*, *MISRA C:2023 Guidelines* |
| **`verifier-qa`** | Independent Adversarial Verification | ASan, UBSan, TSan, LSan, Valgrind, Cppcheck, Clang-Tidy, unit tests (100% green), coverage-guided fuzzing targets. Unconditional veto gate. | Orthogonal Maker/Checker Adversarial Battery |

---

## 3. Operational CLI Protocols

The native CLI binary is located at `/home/npirela/c-master/bin/c-master`.

### A. Search Canonical C Literature
Query the offline vectorless BM25 literature search engine across 7 canonical texts:
```bash
/home/npirela/c-master/bin/c-master search-corpus --query "nullptr"
```

### B. Verify Documentation Cadence
Check the 30-day documentation freshness manifest for hash drift:
```bash
/home/npirela/c-master/bin/c-master check-docs-cadence
```

### C. Update Documentation Hashes
Refresh `.docs_manifest.json` with updated document timestamps and hashes:
```bash
/home/npirela/c-master/bin/c-master update-docs --force
```

### D. Probe 38+ FOSS C Enterprise Toolchain
Scan and report host availability for all 38+ tools across the 6 operational pillars:
```bash
/home/npirela/c-master/bin/c-master toolchain
```

### E. Run Full Orchestrator Goal Dispatch
Execute multi-agent bounded functional slicing and self-healing verification:
```bash
/home/npirela/c-master/bin/c-master orchestrate --goal "Build high-throughput network engine"
```

### F. Run Independent Adversarial Gate
Execute the verifier QA adversarial gate with unconditional veto:
```bash
/home/npirela/c-master/bin/c-master verify
```

---

## 4. References & Progressive Disclosure

- For detailed contract schemas and FSM transitions, see [agent_contracts.md](references/agent_contracts.md).
- For the full 38+ FOSS toolchain catalog with installation recipes, see [toolchain_matrix.md](references/toolchain_matrix.md).
- For root-cause diagnostics of ASan/UBSan errors and compiler warnings, see [troubleshooting_playbook.md](references/troubleshooting_playbook.md).
