---
name: cpp-master
description: Use this skill whenever building, modifying, refactoring, optimizing, or auditing Modern C++ applications and libraries (C++20/C++23/C++26; GCC 14+ / Clang 18+). Orchestrates 4 domain-specialized C++ workers (modern-cpp-architect, perf-hardware-optimizer, systems-concurrency-engineer, security-safety-auditor) and 1 independent adversarial verification gate (verifier-qa), grounded in 7 canonical ISO literature texts and an exhaustive 40+ FOSS toolchain.
allowed-tools:
  - run_command
  - Bash
  - shell
  - view_file
  - replace_file_content
  - write_to_file
---

# `cpp-master`: Autonomous Modern C++ Engineering Platform

`cpp-master` is an enterprise-grade autonomous C++ engineering platform specializing in modern, pure, production-hardened ISO C++ (C++20/C++23/C++26). It orchestrates 4 domain-specialized workers under a strict Orchestrator-Worker state machine and enforces an independent adversarial verification gate (`verifier-qa`) with absolute veto power.

---

## 1. Non-Negotiable Invariants

> **MANDATORY POLICY:** Whenever writing, modifying, refactoring, benchmarking, or auditing C++ code, the agent **MUST ALWAYS** invoke and adhere to `cpp-master`.

1. **Ecosystem & Language Purity:**
   The C++ engine and public APIs are 100% pure modern C++ (C++20/C++23 with CMake 3.28+). Zero foreign-language build pollution (no Cargo, Go, or Python build steps inside the C++ engine).
2. **Deterministic Task + Playbook Contracts:**
   Every slice of work is executed through a deterministic contract enforcing:
   $$\text{DISPATCHED} \longrightarrow \text{RUNNING} \longrightarrow \text{VERIFYING} \longrightarrow (\text{COMPLETED} \mid \text{FAILED\_HEALING\_LOOP})$$
3. **Orthogonal Adversarial Verification (`verifier-qa`):**
   The verification agent operates with unconditional veto power. A slice CANNOT reach `COMPLETED` unless:
   - Zero compiler warnings under `-Wall -Wextra -Wpedantic -Werror`.
   - Compiler sanitizers battery (ASan, UBSan, TSan, MSan) runs 100% clean.
   - Cyclomatic Complexity (CC) <= 10 across every function/method.
   - Mutation Score Indicator (MSI) >= 80%.
4. **30-Day Documentation Freshness Cadence:**
   All specifications and literature are tracked in `.docs_manifest.json` with uppercase SHA-256 hashes and enforced every 30 days.

---

## 2. Specialized Agent Fleet

| Agent Identifier | Domain Specialization | Core Invariants Enforced | Literature Grounding |
| :--- | :--- | :--- | :--- |
| **`modern-cpp-architect`** | ISO C++20/23/26 Core Standards | Concepts (`requires`), Ranges, `constexpr`/`consteval`, monadic `std::expected`/`std::optional`, Rule of Zero/Five. Zero raw pointers/`malloc`/`free`. | *ISO/IEC 14882*, *Effective Modern C++*, *C++ Core Guidelines* |
| **`perf-hardware-optimizer`** | Microarchitecture & Zero-Overhead | Cache line alignment (`alignas(64)`), SoA vs AoS, branch hints (`[[likely]]`/`[[unlikely]]`), SIMD vectorization, zero-allocation hot paths. | *High Performance C++*, *Modern C++ Design* |
| **`systems-concurrency-engineer`** | Low-Level Systems & Memory Models | Acquire-release semantics (`std::memory_order`), lock-free ring buffers, `std::jthread`, coroutines (`co_await`), hermetic CMake targets. | *C++ Concurrency in Action*, *C++ Core Guidelines* |
| **`security-safety-auditor`** | Spatial/Temporal Memory Safety | Bounds safety (`std::span`), arithmetic overflow prevention (`std::cmp_equal`), constant-time cryptographic hygiene, rootless container (`USER appuser`). | *SEI CERT C++ Security Standard*, *OWASP C++* |
| **`verifier-qa`** | Independent Adversarial Verification | ASan, UBSan, TSan, MSan, Clang-Tidy, Cppcheck (`-warnings-as-errors=*`), mutation testing (MSI >= 80%), LibFuzzer. Unconditional veto. | Orthogonal Maker/Checker Verification Battery |

---

## 3. Operational CLI Protocols

The native CLI binary is located at `/home/npirela/cpp-master/build/bin/cpp-master`.

### A. Search Canonical C++ Literature
Query the offline BM25 literature search engine across 7 canonical texts:
```bash
/home/npirela/cpp-master/build/bin/cpp-master search-corpus "cache alignment false sharing" --limit 5
```

### B. Verify Documentation Cadence
Check the 30-day documentation freshness manifest for hash drift:
```bash
/home/npirela/cpp-master/build/bin/cpp-master check-docs-cadence
```

### C. Update Documentation Hashes
Refresh `.docs_manifest.json` with updated document timestamps and hashes:
```bash
/home/npirela/cpp-master/build/bin/cpp-master update-docs --force
```

### D. Inspect 40+ Toolchain Matrix
Inspect system tool readiness across all 6 operational categories:
```bash
/home/npirela/cpp-master/build/bin/cpp-master toolchain
```

### E. Run Autonomous Multi-Agent Orchestration
Execute the 4 domain slices and trigger adversarial QA verification:
```bash
/home/npirela/cpp-master/build/bin/cpp-master orchestrate "Implement lock-free ring buffer"
```

### F. Run DevSecOps SecSDLC Quality Gate
Execute the comprehensive DevSecOps Master gate:
```bash
python3 /home/npirela/.agents/skills/devsecops-master/scripts/cpp_master_gate.py /home/npirela/cpp-master
```

---

## 4. Progressive Disclosure References

For deep architecture specifications, schemas, and runbooks:
- [Agent Contracts & State Machine](references/agent_contracts.md): JSON schema and transition rules.
- [40+ FOSS Toolchain Matrix](references/toolchain_matrix.md): Exhaustive category catalog with commands.
- [Troubleshooting Playbook](references/troubleshooting_playbook.md): Diagnostic recipes for ASan, UBSan, TSan, cache line false sharing, and template bloat.
