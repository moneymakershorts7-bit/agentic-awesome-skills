---
name: java-master
description: Enterprise-grade autonomous Java SE engineering platform and orchestrator harness. Coordinates 4 domain-specialized Java agents (loom-architect, jvm-optimizer, domain-architect, security-auditor) and 1 independent adversarial verification gate (verifier-qa), grounded in canonical literature and 38+ FOSS Java engineering tools.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# `java-master`: Autonomous Java SE Engineering Platform & Orchestrator Harness

`java-master` is an enterprise-grade autonomous engineering platform for Java SE (Java 21+ LTS / Java 25 LTS) applications, microservices, and system libraries located at `/home/npirela/java-master`. It eliminates both the *Monolithic God-Agent* and *Chatty Role-Playing Committee* anti-patterns through a strict **Orchestrator-Worker Architecture** with **Maker/Checker Orthogonality**.

---

## 1. Non-Negotiable Invariants

> [!IMPORTANT]
> Whenever designing, modifying, refactoring, profiling, auditing, or verifying code in the Java programming language, the agent **MUST ALWAYS** invoke and adhere to `java-master`.

1. **100% Pure Java Implementation**: Core engine is written in pure, idiomatic Java SE 21+ using Maven Wrapper (`pom.xml`, `mvnw`).
2. **Deterministic Compiler & AST Verification**: All changes must pass `javac --enable-preview -Werror`, Error Prone, and NullAway with zero warnings.
3. **Loom Pinning & Thread Concurrency**: Zero `synchronized` blocks inside virtual thread call stacks; enforce `ReentrantLock` or lock-free atomics. Bounded subtasks inside `StructuredTaskScope`.
4. **Architectural Purity**: Clean / Hexagonal domain layer isolation enforced by automated `ArchUnit` rule tests.
5. **Tool-First Literature Grounding**: All architectural claims and patterns must be grounded in canonical literature via vectorless BM25 / TF-IDF search.
6. **Cyclomatic Complexity Discipline**: No method shall exceed a Cyclomatic Complexity (CC) of 10. Decompose multi-branch logic into dedicated private helper methods.

---

## 2. Specialized Agent Directory

| Agent ID | Role | Core Domain & Invariants | Key Tools |
| :--- | :--- | :--- | :--- |
| **`loom-architect`** | Loom & High-Concurrency Architect | Virtual Threads, Structured Concurrency (`StructuredTaskScope`), Scoped Values (`ScopedValue`), Non-blocking I/O. Thread-per-request; strictly ban virtual thread pooling. Pinning avoidance. | `virtual-threads`, `structured-task-scope`, `jcmd-thread-dump`, `awaitility` |
| **`jvm-optimizer`** | High-Performance, JVM & Memory Optimizer | JMH, C2 JIT optimization, Low-Latency GC (ZGC / Shenandoah), Panama FFM (`Arena.ofConfined()`). Zero unneeded wrapper boxing; escape analysis scalar replacement. | `jmh`, `jol`, `async-profiler`, `jfr`, `gcviewer`, `javap` |
| **`domain-architect`** | Enterprise Domain & Architecture Engineer | Clean Architecture, Hexagonal / Ports & Adapters, DDD, Sealed interface ADTs, Records with compact validation constructors, exhaustive pattern matching. | `archunit`, `junit5`, `assertj`, `jdepend` |
| **`security-auditor`** | Security, SecSDLC & Cryptographic Auditor | Defensive coding, `ObjectInputFilter` pattern whitelisting, AES-256-GCM / ChaCha20-Poly1305, zero CVEs, distroless container non-root (`USER 65532:65532`). | `spotbugs`, `findsecbugs`, `dependency-check`, `cyclonedx`, `trivy` |
| **`verifier-qa`** | Independent Adversarial Verification Agent | Independent gatekeeper with **unconditional veto power**. Enforces AST nullability, SpotBugs 0 findings, PIT mutation score >= 80%, and ArchUnit rules. | `pitest`, `jazzer`, `nullaway`, `error-prone`, `archunit` |

---

## 3. Operational CLI Protocols

Use `java-master` (available globally in PATH) or the python driver `python3 /home/npirela/.agents/skills/java-master/scripts/java_master_cli.py`:

### A. Autonomous Orchestration (Worker + Verifier Loop)
Dispatches bounded functional slices to specialized domain agents followed by adversarial QA verification:
```bash
java-master orchestrate --goal "Build complete Java 21 enterprise backend with Loom, FFM, and Domain events"
```

### B. Independent Adversarial Verification Gate
Run Agent 5 (`verifier-qa`) directly against the target workspace:
```bash
java-master verify
```

### C. Canonical Literature Search (Vectorless BM25 / TF-IDF)
Retrieve exact line-accurate snippets, books, and chapters from authoritative Java specifications:
```bash
java-master search-corpus --query "virtual threads pinning synchronized"
```

### D. 38+ FOSS Toolchain Audit
Inspect installed status and recipes for all 38+ canonical Java enterprise tools:
```bash
java-master toolchain-matrix
```

### E. 30-Day Documentation Freshness Cadence
Check freshness status and refresh manifest:
```bash
java-master check-docs-cadence
java-master update-docs --force
```

### F. DevSecOps SecSDLC Quality Gate
Execute complete SecSDLC quality scorecard:
```bash
python3 /home/npirela/.agents/skills/devsecops-master/scripts/java_master_gate.py <project_path>
```

---

## 4. Progressive Disclosure References

- Detailed Contract Schema & FSM: [`references/agent_contracts.md`](references/agent_contracts.md)
- Complete 38+ Toolchain Matrix & Install Recipes: [`references/toolchain_matrix.md`](references/toolchain_matrix.md)
- Diagnostics & Self-Healing Runbooks: [`references/troubleshooting_playbook.md`](references/troubleshooting_playbook.md)
