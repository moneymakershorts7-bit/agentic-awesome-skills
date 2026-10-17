---
name: javascript-master
description: Autonomous enterprise JavaScript engineering platform and agent orchestrator specialized in modern pure ECMAScript (ES2024+ / Node.js 22+ LTS or Bun), 4 domain workers, 1 independent adversarial verification agent, JSDoc static typing (tsc --checkJs), V8 optimization, 40+ FOSS toolchain, and 30-day documentation cadence.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# javascript-master: Enterprise Autonomous JavaScript Engineering Platform

`javascript-master` is an autonomous enterprise JavaScript engineering platform and agent orchestrator specialized in modern, pure, production-hardened JavaScript (ES2024+ / Node.js 22+ LTS or Bun). Built on the **Frontier Orchestrator-Worker Standard**, it rejects both the Monolithic God-Agent and the Chatty Role-Playing Committee anti-patterns.

---

## 1. Architectural Foundations

The platform enforces a decoupled Orchestrator-Worker state machine in idiomatic, pure ECMAScript (Native ESM):
- **Lead Orchestrator**: Manages Bounded Functional Slicing (atomic, decoupled work units with zero monolithic PRs), Task + Playbook Contract generation with self-healing runbooks, offline corpus ingestion with line-accurate BM25/TF-IDF search, and 30-day documentation freshness cadence.
- **Finite State Machine**:
  `DISPATCHED` ──► `RUNNING` ──► `VERIFYING` ──► (`COMPLETED` | `FAILED_HEALING_LOOP`)
- **Self-Healing Runbooks**: In case of verification failure, the orchestrator pattern-matches failure traces against the contract's `known_failure_modes`, applies diagnostic recipes, and re-executes tests before committing changes.

For full contract specifications and JSON schemas, see [Agent Contracts Reference](file:///home/npirela/.agents/skills/javascript-master/references/agent_contracts.md).

---

## 2. The 5 Specialized JavaScript Enterprise Agents

### Agent 1: ECMAScript Standards & JSDoc Type Architect (`ecma-architect`)
- **Domain**: Modern ECMAScript (ES2024+), class private fields (`#`), top-level await, Temporal API, `Promise.withResolvers()`, and transpiler-free type safety.
- **Invariants**:
  - Transpiler-Free Type Safety: 100% of methods, parameters, and return types fully annotated with strict JSDoc tags (`@param`, `@returns`, `@typedef`, `@template`), verified by `tsc --noEmit --checkJs`.
  - True Private State: Enforce hard runtime encapsulation using `#privateField` and `#privateMethod` rather than fragile underscore conventions (`_prop`).
  - Immutability First: Domain states and value objects frozen via `Object.freeze()` or `deepFreeze()`; ban in-place mutation.
  - Pattern Matching & Functional Grouping: Utilize `Object.groupBy()`, `Map.groupBy()`, and tagged unions for clean domain state machines.

### Agent 2: High-Performance, V8 & Async Optimizer (`runtime-optimizer`)
- **Domain**: V8 engine internals, memory layout, hidden class stability, and resilient asynchronous event loops.
- **Invariants**:
  - V8 Shape Preservation: Initialize all object properties inside constructors in identical order to preserve monomorphic hidden classes and avoid de-optimization bails.
  - Cancellation Invariant: Every asynchronous function performing I/O, network requests, or long-running computations must accept an `AbortSignal` and handle `abort` events deterministically.
  - Event Loop Protection: Zero synchronous CPU blocking in the primary event loop thread. Delegate compute-heavy tasks to `node:worker_threads`.
  - Memory Leak Eradication: Always detach event listeners, cancel timers (`clearTimeout`), and use `WeakMap` / `WeakSet` / `FinalizationRegistry` for object-bound metadata.

### Agent 3: Native ESM, Modules & Clean API Engineer (`api-engineer`)
- **Domain**: Native ECMAScript Modules (ESM), clean package exports, boundary parsing, and standard library leverage.
- **Invariants**:
  - Native ESM Exclusivity: Mandate `"type": "module"`. All relative imports must contain explicit `.js` extensions. Strictly ban CommonJS (`require`, `module.exports`).
  - Standard Library Leverage: Prioritize Node.js 22+ built-in modules (`node:fs/promises`, `node:test`, `node:crypto`, `node:util`) over third-party micro-dependencies.
  - Subpath Imports & Clean Exports: Use `#internal/` subpath imports and clean `package.json` `"exports"` maps to prevent consumer access to private internals.
  - Boundary Parsing: Validate untrusted inputs at network/API boundaries using lightweight schema parsers before reaching domain core.

### Agent 4: Security, Prototype Hardening & SecSDLC Auditor (`security-auditor`)
- **Domain**: Prototype pollution elimination, ReDoS defense, cryptographic safety, and rootless containerization.
- **Invariants**:
  - Prototype Pollution Defense: Enforce `Object.create(null)` or `Map` for arbitrary key-value dictionaries. Strictly ban recursive `Object.assign` or deep-clones that accept untrusted `__proto__` or `constructor` keys.
  - ReDoS Immunity: All regular expressions executed against untrusted inputs must be verified with `safe-regex2` or enforce strict input length bounds.
  - Cryptographic Hygiene: Use `node:crypto` (`crypto.randomBytes()`, `crypto.subtle`); strictly ban `Math.random()` for security contexts and insecure legacy hashes (MD5, SHA-1).
  - Supply Chain & Rootless Deployment: Enforce `--frozen-lockfile` (npm/pnpm), `socket` vulnerability scanning, and rootless container execution (`USER node:node` / UID 1000).

### Agent 5: Independent Adversarial Verification Agent (`verifier-qa`)
- **Domain**: Independent verification gate with unconditional veto power over all code integrations.
- **Invariants**:
  - JSDoc Type Gate: `tsc --noEmit --allowJs --checkJs` must pass with zero errors under `strict: true`.
  - Dead Code Gate: `knip` must confirm zero dead code, orphaned exports, or unlisted dependencies.
  - Mutation Testing Gate: Stryker Mutator score >= 80% on critical domain and algorithmic logic.
  - Generative Property Gate: `fast-check` property tests verifying state machine invariants across generated edge-case inputs.
  - Quality & Linter Gate: Biome or ESLint strict ECMAScript configuration with zero warnings.

---

## 3. Canonical Literature Ingestion & Line-Accurate Search

The platform ingests 7 authoritative ECMAScript and Node.js texts in `knowledge_base/books_markdown/`:
1. `ecma_spec.md`: The ECMAScript 2024/2025 Language Specification (ECMA-262).
2. `definitive_guide_js.md`: JavaScript: The Definitive Guide (Modern JavaScript Core & Idioms).
3. `ydkjsy_series.md`: You Don't Know JS Yet (2nd Edition Series).
4. `nodejs_diagnostics.md`: Node.js 22+ LTS Documentation & Diagnostics Architecture.
5. `v8_perf_internals.md`: V8 Engine Internals & JavaScript Performance Guide.
6. `owasp_js_security.md`: OWASP JavaScript / Node.js Secure Coding Cheat Sheet.
7. `jsdoc_type_guide.md`: JSDoc Reference Specification & Type-Checking Standards.

Query the literature directly via line-accurate TF-IDF/BM25:
```bash
python3 ~/.agents/skills/javascript-master/scripts/javascript_master_cli.py search-corpus --query "prototype pollution"
```

---

## 4. 40+ FOSS JavaScript Toolchain Matrix

Covers 6 operational categories: Static Analysis (`tsc`, `biome`, `eslint`, `knip`), Testing & Mutation (`node:test`, `vitest`, `stryker`, `fast-check`, `c8`), Profiling (`clinic`, `0x`, `v8-profiler-next`, `autocannon`), Security (`socket`, `npm-audit`, `safe-regex2`, `trivy`), Formatting (`prettier`, `oxc`, `sort-package-json`), and Concurrency (`valibot`, `zod`, `p-limit`).

For installation and execution recipes, see [Toolchain Matrix Reference](file:///home/npirela/.agents/skills/javascript-master/references/toolchain_matrix.md).

---

## 5. 30-Day Documentation Freshness Cadence

Audited via deterministic state manifest `.docs_manifest.json`:
```bash
# Check cadence compliance
python3 ~/.agents/skills/javascript-master/scripts/javascript_master_cli.py check-docs-cadence

# Force refresh manifest
python3 ~/.agents/skills/javascript-master/scripts/javascript_master_cli.py update-docs
```

---

## 6. Troubleshooting Runbooks

For diagnostic recipes on prototype pollution traps, event loop starvation, Stryker mutation survivors, and V8 shape de-optimizations, see [Troubleshooting Playbook](file:///home/npirela/.agents/skills/javascript-master/references/troubleshooting_playbook.md).
