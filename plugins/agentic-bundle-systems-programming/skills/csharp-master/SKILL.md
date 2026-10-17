---
name: csharp-master
description: Autonomous enterprise C# / .NET engineering platform, MCP server, and agent orchestrator specialized in modern high-performance C# (.NET 8 LTS / .NET 9 / .NET 10 LTS / .NET 11 Preview / C# 13+), 4 domain enterprise workers, and 1 independent adversarial verification agent.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# csharp-master

`csharp-master` is an enterprise-grade autonomous C# and .NET engineering platform, MCP server, and agent orchestrator. The platform specializes in modern, high-performance C# (.NET 8 LTS / .NET 9 / .NET 10 LTS / .NET 11 Preview / C# 13+), featuring 4 domain-specialized C# enterprise workers, 1 independent adversarial verification agent, and native Model Context Protocol (MCP) server integration.

## Core Capabilities & Operational Modes

1. **Frontier Orchestrator-Worker Architecture**:
   - Strictly enforces decoupled Orchestrator-Worker state machine (`DISPATCHED` -> `RUNNING` -> `VERIFYING` -> `(COMPLETED | FAILED_HEALING_LOOP)`).
   - Rejects monolithic god-agents and chatty committees.
   - Enforces Bounded Functional Slicing with atomic slices and zero monolithic PRs.

2. **The 5 Specialized C# Enterprise Agents**:
   - `async-architect` (Agent 1): CancellationToken propagation, zero thread-pool starvation (`.Result`/`.Wait()` ban), `ValueTask<T>` allocation-free paths, bounded `System.Threading.Channels` with backpressure, modern `System.Threading.Lock` with `EnterScope()`, and multi-tier `HybridCache` stampede protection.
   - `runtime-optimizer` (Agent 2): Span-first parsing (`ReadOnlySpan<T>`, `Span<T>`), zero heap allocation in hot loops (`ArrayPool<T>`, `stackalloc`, `ref struct`), zero-alloc caller ergonomics via `params ReadOnlySpan<T>`, `allows ref struct` anti-constraints, hardware-accelerated `TensorPrimitives` SIMD math, and Native AOT trimming safety.
   - `domain-architect` (Agent 3): Modern C# 12/13/14 idioms (primary constructors, `[...]` collection expressions, positional records, `field` keyword in semi-auto properties, `partial` properties for source generators, `[OverloadResolutionPriority]`), Railway-Oriented Programming (`Result<T, Error>`), ArchUnitNET layer rules, EF Core query optimizations.
   - `security-auditor` (Agent 4): Central Package Management (`Directory.Packages.props`), Post-Quantum Cryptography (PQC) readiness (ML-KEM, ML-DSA), authenticated encryption (AES-256-GCM, ChaCha20-Poly1305), deserialization defense (ban `BinaryFormatter`), rootless container hardening (`USER app` / UID 1654).
   - `verifier-qa` (Agent 5): Independent adversarial verifier with unconditional veto power; Roslyn compiler gate (`TreatWarningsAsErrors=true`, 0 warnings); TFM and LangVersion validation (`net10.0`, `net11.0`, C# 13/14/15); Stryker mutation testing >= 80%; BenchmarkDotNet zero regression enforcement; automated self-healing runbooks.

3. **Model Context Protocol (MCP) Server Integration**:
   - High-performance JSON-RPC 2.0 stdio MCP server compatible with any host (Antigravity CLI, VS Code Copilot, Claude Desktop).
   - Exposes 6 enterprise tools (`csharp_master_search_corpus`, `csharp_master_verify_slice`, `csharp_master_audit_toolchain`, `csharp_master_check_docs_cadence`, `csharp_master_decompose_task`, `csharp_master_agent_invariants`).
   - Exposes resources (`csharp-master://manifest`, `csharp-master://cadence`, `csharp-master://toolchain`) and prompt templates (`csharp-code-review`, `zero-alloc-audit`, `async-deadlock-check`, `net10-modernization-audit`, `pqc-crypto-readiness`).
   - Stderr-only logging isolation guaranteeing zero stdout JSON-RPC stream pollution.

4. **Canonical Literature Ingestion (Zero Hallucination Grounding)**:
   - 10 authoritative specifications and architectural treatises indexed with vectorless BM25/TF-IDF search:
     - `csharp_spec.md`: The C# Language Specification (C# 12/13 Edition)
     - `framework_design_guidelines.md`: Conventions, Idioms, Patterns for Reusable .NET Libraries
     - `dotnet_memory_management.md`: Pro .NET Memory Management (Konrad Kokosa)
     - `high_perf_dotnet.md`: Writing High-Performance .NET Code & Native AOT Guides
     - `dotnet_async_guidelines.md`: Microsoft .NET Async Guidance (David Fowler)
     - `dotnet_security.md`: Microsoft .NET Secure Coding Guidelines & Cryptography Architecture
     - `dotnet_clean_arch.md`: Clean Architecture & Domain-Driven Design in .NET
     - `dotnet_mcp_spec.md`: Microsoft .NET AI and Model Context Protocol (MCP) Architecture & Implementation Specification
     - `dotnet_10_spec.md`: .NET 10 LTS & C# 13/14 Authoritative Specification and Architecture Guide
     - `dotnet_11_spec.md`: .NET 11 & C# 14/15 Preview, Roadmap & Next-Gen Cloud Architecture Specification

5. **Exhaustive 38+ FOSS Toolchain Matrix**:
   - 40 canonical FOSS .NET tools across Compilers, Architecture, Testing, Performance, Security, and Formatting.

6. **30-Day Freshness Cadence Governance**:
   - State manifest `.docs_manifest.json` with cryptographic SHA256 hashes and monthly automated audit triggers (`0 0 1 * *`).

## Quick Start & CLI Workflows

```bash
# 1. Search authoritative corpus with BM25
csharp-master search-corpus --query "Model Context Protocol Span"

# 2. Start MCP server over stdio for AI hosts
csharp-master serve-mcp

# 3. Check 30-day documentation freshness cadence
csharp-master check-docs-cadence

# 4. Force documentation manifest refresh
csharp-master update-docs --force

# 5. Audit 38+ FOSS .NET toolchain matrix
csharp-master audit-toolchain

# 6. Verify sample slice contract execution
csharp-master verify-slice

# 7. Execute DevSecOps SecSDLC quality gate
python3 ~/.agents/skills/devsecops-master/scripts/dotnet_master_gate.py <project_path>
```

## Progressive Disclosure References

- [`references/agent_contracts.md`](references/agent_contracts.md): TaskPlaybookContract schema, JSON structure, FSM state machine transitions, and self-healing runbook patterns.
- [`references/net10_net11_features.md`](references/net10_net11_features.md): .NET 10 LTS & .NET 11 architecture, C# 13/14 language features, Lock, params Span, allows ref struct, HybridCache, PQC, and TensorPrimitives.
- [`references/toolchain_matrix.md`](references/toolchain_matrix.md): Exhaustive guide to 40 .NET FOSS tools with install and invocation recipes.
- [`references/troubleshooting_playbook.md`](references/troubleshooting_playbook.md): Diagnostic runbooks for thread-pool starvation, allocation spikes, Stryker mutation survivors, and Native AOT trimming breaks.
- [`scripts/dotnet_master_cli.py`](scripts/dotnet_master_cli.py): Python helper script for orchestration, search, and gate execution.
