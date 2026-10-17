---
name: csharp-master
description: Autonomous enterprise C# / .NET engineering platform and agent orchestrator specialized in modern high-performance C# (.NET 8 LTS / .NET 9 LTS / C# 12+), 4 domain enterprise workers, and 1 independent adversarial verification agent.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# csharp-master

`csharp-master` is an enterprise-grade autonomous C# and .NET engineering platform and agent orchestrator. The platform specializes in modern, high-performance C# (.NET 8 LTS / .NET 9 LTS / C# 12+), featuring 4 domain-specialized C# enterprise workers and 1 independent adversarial verification agent.

## Core Capabilities & Operational Modes

1. **Frontier Orchestrator-Worker Architecture**:
   - Strictly enforces decoupled Orchestrator-Worker state machine (`DISPATCHED` -> `RUNNING` -> `VERIFYING` -> `(COMPLETED | FAILED_HEALING_LOOP)`).
   - Rejects monolithic god-agents and chatty committees.
   - Enforces Bounded Functional Slicing with atomic slices and zero monolithic PRs.

2. **The 5 Specialized C# Enterprise Agents**:
   - `async-architect` (Agent 1): CancellationToken propagation, zero thread-pool starvation (`.Result`/`.Wait()` ban), `ValueTask<T>` allocation-free paths, bounded `System.Threading.Channels` with backpressure.
   - `runtime-optimizer` (Agent 2): Span-first parsing (`ReadOnlySpan<T>`, `Span<T>`), zero heap allocation in hot loops (`ArrayPool<T>`, `stackalloc`, `ref struct`), Native AOT trimming safety, `BenchmarkDotNet` memory diagnoser harness.
   - `domain-architect` (Agent 3): Modern C# 12 idioms (primary constructors, `[...]` collection expressions, positional records), Railway-Oriented Programming (`Result<T, Error>`), ArchUnitNET layer rules, EF Core query optimizations (`AsNoTracking()`, `Select()`).
   - `security-auditor` (Agent 4): Central Package Management (`Directory.Packages.props`), authenticated cryptography (AES-256-GCM, ChaCha20-Poly1305), deserialization defense (ban `BinaryFormatter`), rootless container hardening (`USER app` / UID 1654).
   - `verifier-qa` (Agent 5): Independent adversarial verifier with unconditional veto power; Roslyn compiler gate (`TreatWarningsAsErrors=true`, 0 warnings); Stryker mutation testing >= 80%; BenchmarkDotNet zero regression enforcement; automated self-healing runbooks.

3. **Canonical Literature Ingestion (Zero Hallucination Grounding)**:
   - 7 authoritative specifications and architectural treatises indexed with vectorless BM25/TF-IDF search:
     - `csharp_spec.md`: The C# Language Specification (C# 12/13 Edition)
     - `framework_design_guidelines.md`: Conventions, Idioms, Patterns for Reusable .NET Libraries
     - `dotnet_memory_management.md`: Pro .NET Memory Management (Konrad Kokosa)
     - `high_perf_dotnet.md`: Writing High-Performance .NET Code & Native AOT Guides
     - `dotnet_async_guidelines.md`: Microsoft .NET Async Guidance (David Fowler)
     - `dotnet_security.md`: Microsoft .NET Secure Coding Guidelines & Cryptography Architecture
     - `dotnet_clean_arch.md`: Clean Architecture & Domain-Driven Design in .NET

4. **Exhaustive 38+ FOSS Toolchain Matrix**:
   - 40 canonical FOSS .NET tools across Compilers, Architecture, Testing, Performance, Security, and Formatting.

5. **30-Day Freshness Cadence Governance**:
   - State manifest `.docs_manifest.json` with cryptographic SHA256 hashes and monthly automated audit triggers (`0 0 1 * *`).

## Quick Start & CLI Workflows

```bash
# 1. Search authoritative corpus
csharp-master search-corpus --query "Span ValueTask"

# 2. Check 30-day documentation freshness cadence
csharp-master check-docs-cadence

# 3. Force documentation manifest refresh
csharp-master update-docs --force

# 4. Audit 38+ FOSS .NET toolchain matrix
csharp-master audit-toolchain

# 5. Verify sample slice contract execution
csharp-master verify-slice

# 6. Execute DevSecOps SecSDLC quality gate
python3 ~/.agents/skills/devsecops-master/scripts/dotnet_master_gate.py <project_path>
```

## Progressive Disclosure References

- [`references/agent_contracts.md`](references/agent_contracts.md): TaskPlaybookContract schema, JSON structure, FSM state machine transitions, and self-healing runbook patterns.
- [`references/toolchain_matrix.md`](references/toolchain_matrix.md): Exhaustive guide to 40 .NET FOSS tools with install and invocation recipes.
- [`references/troubleshooting_playbook.md`](references/troubleshooting_playbook.md): Diagnostic runbooks for thread-pool starvation, allocation spikes, Stryker mutation survivors, and Native AOT trimming breaks.
- [`scripts/dotnet_master_cli.py`](scripts/dotnet_master_cli.py): Python helper script for orchestration, search, and gate execution.
