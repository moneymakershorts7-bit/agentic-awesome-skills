---
name: kotlin-master
description: Autonomous Kotlin engineering platform and agent orchestrator for modern, production-hardened Kotlin (Kotlin 2.0+/2.1+ powered by K2 compiler, Structured Concurrency with Coroutines & Reactive Flows, GraalVM Native Image compilation, Project Loom Virtual Thread integration, and Multiplatform [KMP] systems). Orchestrates 4 domain-specialized enterprise workers (coroutine-concurrency-architect, domain-type-architect, server-perf-systems-engineer, security-sandbox-auditor) and 1 independent adversarial verification agent (verifier-qa), grounded in 8 canonical literature manuals and an exhaustive 38+ FOSS Kotlin toolchain.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# `kotlin-master`: Autonomous Kotlin Engineering Platform & Agent Orchestrator

`kotlin-master` is an enterprise-grade autonomous Kotlin engineering platform and orchestrator specializing in modern, pure, production-hardened Kotlin (**Kotlin 2.0+ / Kotlin 2.1+** powered by the high-performance **K2 compiler**, Structured Concurrency with Coroutines & Reactive Flows, GraalVM Native Image compilation, Project Loom Virtual Thread integration, and Multiplatform [KMP] systems).

The platform enforces a decoupled Orchestrator-Worker state machine featuring **4 Domain-Specialized Kotlin Enterprise Workers** and **1 Independent Adversarial Verification Agent (QA, Konsist Architecture Testing & Mutation)**.

---

## 1. Core Invariants & Architectural Governance

> **MANDATORY POLICY:** Whenever writing, modifying, refactoring, compiling, or auditing Kotlin code across any project, the agent **MUST ALWAYS** invoke and adhere to `kotlin-master`.

1. **100% Pure Kotlin 2.0+ Implementation:**
   The `kotlin-master` core platform is built exclusively in idiomatic Kotlin 2.0+ using Gradle Kotlin DSL (`build.gradle.kts`). Zero foreign build wrappers.
2. **K2 Compiler Strictness & Explicit API Mode:**
   Mandatory compilation under Kotlin 2.0+ with `-Werror`, `-Xexplicit-api=strict` (explicit visibility and return types on all public APIs), and `-progressive`.
3. **Structured Concurrency Invariant:**
   Absolute prohibition of unconfined `GlobalScope.launch`. Every asynchronous task must be bound to a well-defined `CoroutineScope` with parent-child lifecycle propagation.
4. **Zero-Allocation Inline Value Classes:**
   Model identifiers, monetary values, and domain tokens as `@JvmInline value class` to guarantee zero runtime heap allocation overhead on the JVM.
5. **Deterministic Task + Playbook Execution Contracts:**
   Every slice of work is executed through a deterministic JSON contract enforcing:
   $$\text{DISPATCHED} \longrightarrow \text{RUNNING} \longrightarrow \text{VERIFYING} \longrightarrow (\text{COMPLETED} \mid \text{FAILED\_HEALING\_LOOP})$$
6. **Independent Adversarial Verification (`verifier-qa`):**
   Agent 5 holds unconditional veto power over code integration. Passing requires:
   - K2 compiler zero warnings under strict explicit API mode.
   - Konsist architectural layer and structural rule verification.
   - Detekt zero code smells (`maxIssues = 0`) and ktlint formatting compliance.
   - Pitest mutation testing score (MSI >= 80%).
   - Kotest & MockK property-based test battery with 100% green assertions.
7. **Complexity Discipline:**
   No function or method shall exceed a Cyclomatic Complexity (CC) of 10. Decompose multi-branch branching into private extension functions.
8. **30-Day Documentation Freshness Cadence:**
   All canonical literature is indexed in `.docs_manifest.json` with SHA-256 hashes and verified against a 30-day review horizon.

---

## 2. The 5 Specialized Kotlin Enterprise Agents

| Agent Identifier | Domain Specialization | Core Invariants Enforced | Literature Grounding |
| :--- | :--- | :--- | :--- |
| **`coroutine-concurrency-architect`** | Structured Concurrency & Reactive Flows | Ban unconfined GlobalScope, isolate thread dispatchers (Default for CPU, IO for blocking I/O), cooperative cancellation (`ensureActive()`, `NonCancellable`), Flow backpressure (`buffer`, `conflate`, `catch`). | *Kotlin Coroutines: Deep Dive* (Marcin Moskała) |
| **`domain-type-architect`** | K2 Type System & Rich Domain Modeling | Zero-allocation `@JvmInline value class`, exhaustive sealed ADTs without `else` fallbacks, immutable data structures, Kotlin Contracts API for smart casts, eradicate `!!`. | *Kotlin Programming Language Official Reference & K2*, *Effective Kotlin* |
| **`server-perf-systems-engineer`** | High-Performance Server & Systems | Zero-reflection serialization (`kotlinx.serialization`), inlining & reified type parameters, GraalVM Native Image (<50ms startup), Project Loom virtual thread dispatcher symbiosis. | *High-Performance Server-Side Kotlin* (Ktor & Loom) |
| **`security-sandbox-auditor`** | Security, SecSDLC & Supply Chain | Modern authenticated cryptography (AES-256-GCM, constant-time compare), SQL injection eradication via type-safe DSLs (Exposed/jOOQ), Gradle checksum verification, rootless OCI containers (`USER 1000:1000`). | *JVM & Kotlin Security Hardening Guide (OWASP)* |
| **`verifier-qa`** | Independent Adversarial Verification | Unconditional veto gate: K2 strictness (`-Werror`, `-Xexplicit-api=strict`), Konsist architecture governance, Detekt/ktlint, Pitest mutation testing (MSI >= 80%), Kotest runTest suite. | *Konsist Handbook*, *Modern Testing in Kotlin: Kotest & MockK* |

---

## 3. Operational CLI Protocols

The native CLI executable is located at `/home/npirela/kotlin-master/bin/kotlin-master` (symlinked in PATH as `kotlin-master`):

```bash
# 1. Orchestrate a task slice with worker execution and verifier QA loop:
kotlin-master orchestrate --task contract.json

# 2. Search canonical literature via vectorless BM25 / TF-IDF engine:
kotlin-master search-corpus --query "structured concurrency"

# 3. Verify 30-day documentation freshness cadence:
kotlin-master check-docs-cadence

# 4. Refresh documentation cadence hashes:
kotlin-master update-docs --force

# 5. Audit 38+ FOSS Kotlin toolchain matrix:
kotlin-master toolchain

# 6. Execute autonomous SecSDLC quality gate:
python3 ~/.agents/skills/devsecops-master/scripts/kotlin_master_gate.py /home/npirela/kotlin-master
```

---

## 4. Progressive Disclosure References

For exhaustive schemas, tool catalogs, and runbooks:
- **Agent Contracts & FSM Schema**: [`references/agent_contracts.md`](file:///home/npirela/.agents/skills/kotlin-master/references/agent_contracts.md)
- **38+ FOSS Toolchain Matrix**: [`references/toolchain_matrix.md`](file:///home/npirela/.agents/skills/kotlin-master/references/toolchain_matrix.md)
- **Troubleshooting & Diagnostic Playbook**: [`references/troubleshooting_playbook.md`](file:///home/npirela/.agents/skills/kotlin-master/references/troubleshooting_playbook.md)
- **Python CLI Orchestrator**: [`scripts/kotlin_master_cli.py`](file:///home/npirela/.agents/skills/kotlin-master/scripts/kotlin_master_cli.py)
