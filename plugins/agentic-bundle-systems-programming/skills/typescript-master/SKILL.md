---
name: typescript-master
description: Enterprise-grade autonomous TypeScript engineering platform and agent orchestrator. Coordinates 4 domain-specialized TypeScript workers (type-architect, runtime-optimizer, api-engineer, security-auditor) and 1 independent adversarial verification gate (verifier-qa), grounded in canonical literature and 38+ FOSS TypeScript tools.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
license: Apache-2.0
---

# `typescript-master`: Autonomous TypeScript Engineering Platform & Orchestrator

`typescript-master` is an enterprise-grade autonomous engineering platform and agent orchestrator for modern, production-hardened TypeScript (TS 5.5+ / Node 22+ LTS or Bun) located at `/home/npirela/typescript-master`. It eliminates both the *Monolithic God-Agent* and *Chatty Role-Playing Committee* anti-patterns through a strict **Orchestrator-Worker Architecture** with **Maker/Checker Orthogonality**.

---

## 1. Non-Negotiable Invariants

> [!IMPORTANT]
> Whenever designing, modifying, refactoring, profiling, auditing, or verifying code in TypeScript, the agent **MUST ALWAYS** invoke and adhere to `typescript-master`.

1. **100% Pure TypeScript Implementation**: Core engine is written in pure, idiomatic TypeScript (TS 5.5+) using native ESM and pnpm 12.14.0.
2. **Total Prohibition of `any`**: The `any` type is strictly forbidden. Unspecified types must use `unknown` accompanied by user-defined type guards (`is`) or Zod/Valibot boundary schema parsers.
3. **Parse, Don't Validate**: Domain entities must be parsed and brand-typed at system boundaries; no unvalidated primitives in domain core.
4. **Cancellation Invariant**: Every asynchronous function performing I/O, network requests, or long-running computations MUST accept an `AbortSignal` and listen to the `abort` event.
5. **Monomorphism & Hidden Classes**: Preserve object property initialization order inside constructors/factories to prevent V8 hidden class de-optimizations.
6. **Strict Module Boundaries**: Standardize on Native ESM (`"type": "module"`, `"moduleResolution": "NodeNext"`) with explicit `.js` extensions on relative imports and `isolatedDeclarations: true`.
7. **Adversarial Gate with Veto Power**: Agent 5 (`verifier-qa`) holds unconditional veto power over all integration PRs.
8. **Cyclomatic Complexity Discipline**: No method or function shall exceed a Cyclomatic Complexity (CC) of 10. Decompose multi-branch logic into small, pure helper functions.

---

## 2. Specialized Agent Directory

| Agent ID | Role | Core Domain & Invariants | Key Tools |
| :--- | :--- | :--- | :--- |
| **`type-architect`** | Type-Level Architect & Domain Modeler | Advanced type system, nominal branding (`unique symbol`), structural pattern matching, discriminated unions with `never`-exhaustiveness, deep immutability (`Readonly<T>`). | `typescript`, `zod`, `valibot`, `arktype`, `ts-pattern` |
| **`runtime-optimizer`** | High-Perf, V8 & Async Optimizer | V8 hidden class stabilization, inline cache monomorphism, event loop starvation defense, `AbortSignal` cancellation, leak elimination (`WeakMap`/`WeakSet`). | `v8-profiler-next`, `clinic`, `0x`, `p-limit`, `p-queue` |
| **`api-engineer`** | API, Modules & Monorepos | Clean API boundaries, Native ESM with explicit `.js` extensions, `isolatedDeclarations: true`, tsconfig Project References (`tsc --build`), zero circular leaks. | `tsc`, `tsdown`, `oxc`, `knip`, `dependency-cruiser` |
| **`security-auditor`** | Security, SecSDLC & Cloud Hardening | Prototype pollution defense (`Object.create(null)`, `Map`), ReDoS mitigation (`safe-regex2`), frozen lockfiles, CycloneDX SBOM, rootless container execution (`USER node:node`). | `socket`, `pnpm-audit`, `safe-regex2`, `cyclonedx`, `trivy` |
| **`verifier-qa`** | Independent Adversarial QA Gatekeeper | Independent gatekeeper with **unconditional veto power**. Enforces `tsc --noEmit` 0 errors, Knip 0 dead code, Biome 0 warnings, Stryker score >= 80%, and fast-check property tests. | `tsc`, `vitest`, `stryker`, `fast-check`, `biome`, `knip` |

---

## 3. Operational CLI Protocols

Use `typescript-master` (available globally in PATH) or the Python helper `python3 ~/.agents/skills/typescript-master/scripts/typescript_master_cli.py`:

### A. Autonomous Orchestration (Worker + Verifier Loop)
Dispatches bounded functional slices to specialized domain workers followed by adversarial verification:
```bash
typescript-master orchestrate --goal "RATE-LIMITER"
```

### B. Independent Adversarial Verification Gate
Executes compiler, AST suppression inspection, and adversarial quality gates:
```bash
typescript-master verify
```

### C. Corpus Literature BM25 Search
Performs vectorless BM25 exact search across ingested canonical literature returning line-accurate citations:
```bash
typescript-master search-corpus --query "isolatedDeclarations"
typescript-master search-corpus --query "hidden classes monomorphic"
```

### D. Toolchain Matrix & Environment Detection
Inspects 38+ FOSS tools across 6 operational categories and detects installed packages:
```bash
typescript-master toolchain
```

### E. 30-Day Documentation Freshness Cadence
Audits and refreshes the deterministic documentation state manifest:
```bash
typescript-master check-docs-cadence
typescript-master update-docs --force
```

---

## 4. Mandatory Task + Playbook Execution Contracts

Every delegated task adheres to a deterministic JSON contract:
```json
{
  "task_id": "SLICE-001-TOKEN-BUCKET",
  "assigned_agent": "runtime-optimizer",
  "scope": {
    "files_target": ["src/limiter/TokenBucket.ts"],
    "interfaces": ["RateLimiter", "LimiterOptions"]
  },
  "functional_invariants": [
    "Accepts AbortSignal and aborts immediately when signal.aborted is true",
    "Zero floating point drift in token refill rate calculations"
  ],
  "playbook": {
    "verification_commands": ["pnpm exec vitest run", "pnpm exec tsc --noEmit"],
    "known_failure_modes": [
      {
        "pattern": "UnhandledPromiseRejection: AbortError",
        "diagnostic_recipe": "Catch and wrap AbortError or ensure caller handles cancellation gracefully."
      }
    ]
  }
}
```

State Machine: `DISPATCHED` ──► `RUNNING` ──► `VERIFYING` ──► (`COMPLETED` | `FAILED_HEALING_LOOP`)

---

## 5. Progressive Disclosure References

- [`references/agent_contracts.md`](references/agent_contracts.md): Full schema definitions, FSM transition matrices, and sample payloads.
- [`references/toolchain_matrix.md`](references/toolchain_matrix.md): Exhaustive guide to 38+ FOSS TypeScript tools across all 6 operational categories.
- [`references/troubleshooting_playbook.md`](references/troubleshooting_playbook.md): Diagnostic runbooks for type inference blowups, V8 memory leaks, Stryker survivors, and ReDoS alerts.
- [`scripts/typescript_master_cli.py`](scripts/typescript_master_cli.py): Universal agent driver script.
