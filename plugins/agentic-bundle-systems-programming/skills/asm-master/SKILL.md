---
name: asm-master
description: Autonomous Assembly engineering platform and low-level agent orchestrator across premier instruction set architectures (x86_64, AArch64, RISC-V RV64GC). Coordinates 4 domain-specialized workers (abi-register-architect, simd-perf-optimizer, systems-lowlevel-engineer, security-crypto-auditor) and 1 independent adversarial verification agent (verifier-qa), grounded in canonical microarchitecture manuals, 38+ FOSS assembly tools, and constant-time side-channel immunity.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
license: MIT
---

# `asm-master`: Autonomous Assembly Engineering Platform

This skill operationalizes the **`asm-master`** platform located at `/home/npirela/asm-master`. It provides agents with deterministic instructions, contracts, and workflows to orchestrate, execute, manage, and verify low-level assembly routines across **x86_64 [AMD64/Intel 64]**, **AArch64 [ARMv8-A/ARMv9-A]**, and **RISC-V [RV64GC]**.

---

## 1. Non-Negotiable Core Invariant

> **MANDATORY POLICY:** Whenever coding, reviewing, refactoring, vectorizing, or auditing code in Assembly (NASM, GAS) or low-level systems interfaces across x86_64, AArch64, or RISC-V, the agent **MUST ALWAYS** invoke and adhere to `asm-master`.

---

## 2. Frontier Orchestrator-Worker Architecture

`asm-master` rejects both the *Monolithic God-Agent* (context pollution, instruction drift) and the *Chatty Role-Playing Committee* (lossy conversational telephone, runaway token tax):

1. **Lead Orchestrator (Single Source of Truth):**
   - Coordinates execution across bounded functional slices (atomic leaf routines; zero bloated files).
   - Generates deterministic Task + Playbook Execution Contracts with self-healing runbooks.
   - Searches authoritative canonical literature via offline vectorless BM25/TF-IDF.
2. **4 Domain-Specialized Assembly Workers:**
   - Execute single-responsibility tasks under a strict token budget.
   - Return distilled executive summaries with deterministic diagnostics.
3. **Agent 5: Independent Adversarial Verification Gate (`verifier-qa`):**
   - Operates in a fresh context with **unconditional veto power** over all code integrations.
   - Validates multi-architecture emulation (QEMU x86_64, AArch64, RISC-V), 16-byte RSP stack alignment before CALL, non-executable stack (`-z noexecstack`), Intel CET `endbr64`, and constant-time timing leakage (`dudect` $|t| < 4.5$).

---

## 3. Specialized Assembly Enterprise Agents Directory

| Agent Identifier | Role | Primary Toolsets | Grounding Invariants |
| :--- | :--- | :--- | :--- |
| **`abi-register-architect`** | Calling Conventions, Stack Frames & Registers | `nasm`, `as`, `gdb`, `readelf` | System V AMD64, MS x64, AAPCS64; 16-byte RSP alignment before CALL; Red Zone leaf discipline |
| **`simd-perf-optimizer`** | SIMD, Vector & Microarchitectural Pipeline | `nasm`, `as`, `perf`, `llvm-mca` | AVX-512, AVX2, NEON, SVE2, RVV; 32B/64B aligned loads; branchless CMOV/CSEL; streaming stores |
| **`systems-lowlevel-engineer`** | Direct Syscalls, Bare-Metal & ELF Sections | `as`, `ld`, `readelf`, `strace` | Direct POSIX syscalls (`rax`/`x8`/`a7`); PIC RIP/PC-relative; ELF `.note.GNU-stack` noexec |
| **`security-crypto-auditor`** | Constant-Time Cryptography & Exploit Defense | `dudect`, `checksec`, `objdump` | Zero secret branches/lookups; Intel CET `endbr64`; ARM `bti c`/PAC; secret register scrubbing |
| **`verifier-qa`** | Independent Adversarial Verification Gate | `qemu-*`, `dudect`, `readelf` | Multi-arch emulation; 100% differential bitwise match vs reference C; veto loop |

---

## 4. Task + Playbook Execution Contract FSM

Every task delegated to any worker must strictly serialize and adhere to a deterministic JSON contract:

```
DISPATCHED ──► RUNNING ──► VERIFYING ──► (COMPLETED | FAILED_HEALING_LOOP)
```

- When verification passes: transition to `COMPLETED`.
- When verification fails: match error against `known_failure_modes`, extract `diagnostic_recipe`, enter `FAILED_HEALING_LOOP`, and retry until completed or retry budget is exhausted.
- Full contract schema: see [agent_contracts.md](file:///home/npirela/.agents/skills/asm-master/references/agent_contracts.md).

---

## 5. Canonical Literature Ingestion & Exact Standards Search

The platform ingests 8 authoritative offline manuals under `/home/npirela/asm-master/knowledge_base/books_markdown/`:
1. `intel_sdm_optimization.md`
2. `arm_armv8_armv9_architecture.md`
3. `system_v_abi_amd64.md`
4. `agner_fog_microarchitecture.md`
5. `riscv_isa_spec.md`
6. `hackers_delight_algorithms.md`
7. `crypto_assembly_sidechannels.md`
8. `microsoft_x64_abi.md`

Query the corpus using the vectorless BM25 search engine:
```bash
/home/npirela/asm-master/bin/asm-master search-corpus --query "<keyword>"
```

---

## 6. Common CLI Operations

```bash
# 1. Audit 30-day documentation freshness cadence
/home/npirela/asm-master/bin/asm-master check-docs-cadence

# 2. Inspect 38+ FOSS Assembly toolchain matrix
/home/npirela/asm-master/bin/asm-master toolchain-matrix

# 3. Execute a Task + Playbook Contract
/home/npirela/asm-master/bin/asm-master run-contract /path/to/contract.json

# 4. Run native and differential verification suites
/home/npirela/asm-master/bin/asm-master test

# 5. Run full DevSecOps SecSDLC quality gate
/home/npirela/asm-master/bin/asm-master run-gate /home/npirela/asm-master
```

---

## 7. Progressive Disclosure References

- [Agent Contracts & FSM Schema](file:///home/npirela/.agents/skills/asm-master/references/agent_contracts.md)
- [38+ FOSS Assembly Toolchain Matrix Guide](file:///home/npirela/.agents/skills/asm-master/references/toolchain_matrix.md)
- [Troubleshooting & Diagnostic Playbook](file:///home/npirela/.agents/skills/asm-master/references/troubleshooting_playbook.md)
