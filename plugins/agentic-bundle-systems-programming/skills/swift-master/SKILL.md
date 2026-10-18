---
name: swift-master
description: Autonomous Swift systems engineering platform and agent orchestrator for modern, production-hardened Swift (Swift 6.0+/6.1+ with Complete Concurrency Checking, Region-Based Isolation, Noncopyable Types, and Typed Throws across Linux Server-Side and Apple Ecosystems). Orchestrates 4 domain-specialized workers (concurrency-actor-architect, domain-type-architect, systems-perf-engineer, security-sandbox-auditor) and 1 independent adversarial verification gate (verifier-qa), grounded in 8 canonical literature manuals and an exhaustive 38+ FOSS Swift toolchain.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# `swift-master`: Autonomous Swift Systems Engineering Platform & Agent Orchestrator

`swift-master` is an enterprise-grade autonomous Swift systems engineering platform and orchestrator specializing in modern, pure, production-hardened Swift (Swift 6.0+ / Swift 6.1+ with Complete Concurrency Checking, Compile-Time Data-Race Safety, Region-Based Isolation, Noncopyable Types, and Typed Throws across Linux Server-Side and Apple Ecosystems).

The platform enforces a decoupled Orchestrator-Worker state machine featuring **4 Domain-Specialized Swift Workers** and **1 Independent Adversarial Verification Agent (QA & Sanitizers)**.

---

## 1. Core Invariants & Governance

> **MANDATORY POLICY:** Whenever writing, modifying, refactoring, benchmarking, or auditing Swift code, the agent **MUST ALWAYS** invoke and adhere to `swift-master`.

1. **100% Pure Swift 6.0+ Implementation:**
   The `swift-master` core engine and domain systems are built exclusively in idiomatic Swift 6 using Swift Package Manager (`Package.swift`). Zero foreign build tool pollution.
2. **Swift 6 Complete Concurrency & Zero Data Races:**
   Mandatory compilation under `-swift-version 6` with Complete Concurrency Checking. Unvetted `@unchecked Sendable` is strictly prohibited. Zero data races tolerated under ThreadSanitizer (`swift test --sanitize=thread`).
3. **Deterministic Task + Playbook Execution Contracts:**
   Every slice of work is executed through a deterministic JSON contract enforcing:
   $$\text{DISPATCHED} \longrightarrow \text{RUNNING} \longrightarrow \text{VERIFYING} \longrightarrow (\text{COMPLETED} \mid \text{FAILED\_HEALING\_LOOP})$$
4. **Independent Adversarial Verification (`verifier-qa`):**
   Agent 5 holds unconditional veto power over code integration. Passing requires:
   - Zero compiler warnings under complete concurrency.
   - 100% pass rate in modern Swift Testing (`import Testing`, `@Test`, `@Suite`, `#expect`, `#require`).
   - Clean execution under ThreadSanitizer.
   - Clean linting with official `swift-format`.
5. **Complexity Discipline:**
   No function or method shall exceed a Cyclomatic Complexity (CC) of 10.
6. **30-Day Documentation Freshness Cadence:**
   All 8 canonical literature texts are indexed in `.docs_manifest.json` with SHA-256 hashes and verified against a 30-day review horizon.

---

## 2. The 5 Specialized Swift Enterprise Agents

| Agent Identifier | Domain Specialization | Core Invariants Enforced | Literature Grounding |
| :--- | :--- | :--- | :--- |
| **`concurrency-actor-architect`** | Swift 6 Complete Concurrency & Actor Isolation | Actor reentrancy mitigation, Region-Based Isolation (SE-0414), Sendable contracts, structured task groups with explicit cancellation (`Task.checkCancellation()`). | *Swift Concurrency Manifesto*, *The Swift Programming Language* |
| **`domain-type-architect`** | Protocol-Oriented Domain Modeling & Types | Noncopyable types (`~Copyable`) for linear systems resources, typed throws (`throws(DomainTradingError)`), Copy-on-Write (`isKnownUniquelyReferenced`), Value Objects. | *Advanced Swift: Modern Edition*, *Swift Clean Architecture & DDD* |
| **`systems-perf-engineer`** | Low-Latency Execution & Server-Side Systems | ARC overhead minimization (`borrowing` parameters), zero-allocation `Substring` parsing, `ContiguousArray` buffering, RAII unsafe pointer sandboxing, SwiftNIO & Hummingbird 2. | *High-Performance Swift: ARC Optimization*, *Server-Side Swift with SwiftNIO* |
| **`security-sandbox-auditor`** | Security, Cryptographic Hygiene & Sandbox | Modern cryptography (Swift Crypto/CryptoKit), constant-time byte comparisons (`constantTimeEquals`), App Sandbox least privilege, Privacy Manifests (`PrivacyInfo.xcprivacy`). | *Apple Platform Security & CryptoKit Specification* |
| **`verifier-qa`** | Independent Adversarial Verification | Unconditional veto gate: Complete Concurrency checking, ThreadSanitizer runtime verification, Swift Testing suite, self-healing diagnostic recipe extraction. | *Modern Swift Testing Guide*, Maker/Checker Verification Battery |

---

## 3. Operational CLI Protocols

The native CLI executable is located at `/home/npirela/swift-master/.build/release/swift-master` (or `.build/debug/swift-master`).

### A. Search Canonical Swift Literature
Query the offline vectorless BM25 literature search engine across 8 canonical texts:
```bash
/home/npirela/swift-master/.build/debug/swift-master search-corpus --query "Sendable"
```

### B. Audit 30-Day Documentation Cadence
Verify that canonical documentation is fresh:
```bash
/home/npirela/swift-master/.build/debug/swift-master check-docs-cadence
```

### C. Inspect 38+ FOSS Swift Enterprise Toolchain
Probe installed and available compilers, sanitizers, and frameworks:
```bash
/home/npirela/swift-master/.build/debug/swift-master toolchain-matrix
```

### D. Execute Task Contract via Orchestrator FSM
Run a deterministic task slice:
```bash
/home/npirela/swift-master/.build/debug/swift-master orchestrate --task task.json
```

### E. Run DevSecOps SecSDLC Quality Gate
Execute the comprehensive automated SecSDLC verification gate:
```bash
python3 /home/npirela/.agents/skills/devsecops-master/scripts/swift_master_gate.py --target /home/npirela/swift-master --strict
```

---

## 4. Progressive Disclosure References

For exhaustive schemas, playbooks, and catalogs, inspect:
- [Task Contracts & FSM Transitions](references/agent_contracts.md)
- [38+ FOSS Swift Enterprise Toolchain Matrix](references/toolchain_matrix.md)
- [Diagnostic & Troubleshooting Runbook](references/troubleshooting_playbook.md)
- [Agent CLI Helper Script](scripts/swift_master_cli.py)
