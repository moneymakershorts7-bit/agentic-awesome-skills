---
name: ruby-master
description: Autonomous Ruby engineering platform and agent orchestrator for modern, production-hardened Ruby (Ruby 3.3+/3.4+ powered by YJIT compiler, Ractor actor-model concurrency, Prism parser, AST-level static typing via RBS/Steep or Sorbet, and modular architecture across Hanami 2.2+ and Rails 8.0+ ecosystems). Orchestrates 4 domain-specialized workers (domain-type-architect, yjit-concurrency-optimizer, api-systems-engineer, security-secsdlc-auditor) and 1 independent adversarial verification gate (verifier-qa), grounded in 8 canonical literature manuals and an exhaustive 38+ FOSS Ruby toolchain.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# `ruby-master`: Enterprise Autonomous Ruby Engineering Platform & Agent Orchestrator

`ruby-master` is an enterprise-grade autonomous Ruby engineering platform and orchestrator specializing in modern, pure, production-hardened Ruby (**Ruby 3.3+ / Ruby 3.4+** powered by the **YJIT** compiler, Ractor actor-model concurrency, Prism parser, AST-level static typing via **RBS & Steep** or **Sorbet**, and modular architecture across Hanami 2.2+ and Rails 8.0+ ecosystems).

The platform rejects monolithic single-agent designs and chatty committees in favor of a strict, decoupled Orchestrator-Worker state machine featuring **4 Domain-Specialized Ruby Workers** and **1 Independent Adversarial Verification Agent (QA, Packwerk Boundaries, Brakeman & Mutation)**.

---

## 1. Core Invariants & Governance

> **MANDATORY POLICY:** Whenever writing, modifying, refactoring, benchmarking, or auditing Ruby code, the agent **MUST ALWAYS** invoke and adhere to `ruby-master`.

1. **100% Pure Ruby 3.3+ Implementation:**
   The `ruby-master` core engine and domain systems are built exclusively in idiomatic Ruby 3.3+ using Bundler (`Gemfile`, `Gemfile.lock`). Zero foreign build tool pollution.
2. **Mandatory Frozen Strings & Immutability:**
   Every Ruby file must begin with `# frozen_string_literal: true` as the first line. Value Objects and Domain Events must use immutable `Data.define` or `dry-struct`. Mutable open structs (`OpenStruct`) are strictly banned.
3. **Deterministic Task + Playbook Execution Contracts:**
   Every slice of work is executed through a deterministic JSON contract enforcing:
   $$\text{DISPATCHED} \longrightarrow \text{RUNNING} \longrightarrow \text{VERIFYING} \longrightarrow (\text{COMPLETED} \mid \text{FAILED\_HEALING\_LOOP})$$
4. **Independent Adversarial Verification (`verifier-qa`):**
   Agent 5 holds unconditional veto power over code integration. Passing requires:
   - Zero type errors under Steep (`steep check`) or Sorbet (`srb tc`).
   - Zero High/Medium warnings under Brakeman (`brakeman -z --no-pager`).
   - Zero privacy or dependency leaks under Packwerk (`packwerk check`).
   - Mutant mutation score indicator (MSI) >= 80%.
   - 100% passing examples in RSpec test suite.
5. **Complexity Discipline:**
   No method shall exceed a Cyclomatic Complexity (CC) or Flog score of 10.
6. **30-Day Documentation Freshness Cadence:**
   All 8 canonical literature texts are tracked in `.docs_manifest.json` with SHA-256 hashes and verified against a 30-day review horizon.

---

## 2. The 5 Specialized Ruby Enterprise Agents

| Agent Identifier | Domain Specialization | Core Invariants Enforced | Literature Grounding |
| :--- | :--- | :--- | :--- |
| **`domain-type-architect`** | Type-Level Architecture & Domain Modeling | `# frozen_string_literal: true`, immutable `Data.define`, strict RBS signatures (`sig/`), `Dry::Monads[:result, :do]`, pattern matching (`case ... in`). | *The Ruby Programming Language*, *POODR (Sandi Metz)* |
| **`yjit-concurrency-optimizer`** | YJIT, Ractors & Memory Concurrency | YJIT inline-cache hit rate protection, ban runtime `alias_method`, Ractor actor isolation (`Ractor.make_shareable`), Fiber async I/O (`Async`), `GC.compact`, jemalloc. | *High Performance Ruby: YJIT, Memory & Profiling*, *Polished Ruby Programming* |
| **`api-systems-engineer`** | Rack 3, Clean APIs & Modular Slices | Rack 3 lowercase headers, streaming response bodies, decoupled domain core, Packwerk boundary governance, fast JSON serialization, idempotent background jobs. | *Layered Design for Ruby on Rails & Hanami Architecture* |
| **`security-secsdlc-auditor`** | Security, SecSDLC & Cryptography | Safe deserialization (`YAML.safe_load`), ban dynamic `eval()`/`send()`, 100% parameterized queries, OpenSSL AES-256-GCM, BCrypt/Argon2, rootless container (`USER ruby`). | *OWASP Ruby & Rails Secure Coding Guide* |
| **`verifier-qa`** | Independent Adversarial Verification | Unconditional veto gate: Steep/Sorbet type check, RuboCop strict, Brakeman -z, Packwerk boundary check, Mutant MSI >= 80%, RSpec 100% pass, self-healing loop execution. | Maker/Checker Verification Battery |

---

## 3. Operational CLI Protocols

The native CLI executable is located at `/home/npirela/ruby-master/bin/ruby-master` (aliased as `ruby-master` in PATH).

### 3.1 Vectorless BM25 Corpus Search
```bash
ruby-master search-corpus --query "Ractor make_shareable"
ruby-master search-corpus --query "YJIT inline cache" --limit 3
```

### 3.2 30-Day Documentation Cadence Audit
```bash
# Check freshness against 30-day review horizon
ruby-master check-docs-cadence

# Refresh manifest with updated SHA-256 signatures
ruby-master update-docs --force
```

### 3.3 Toolchain Matrix Inspection
```bash
ruby-master toolchain-matrix
ruby-master toolchain-matrix --category "Static Typing & Interface Verification"
```

### 3.4 Bounded Functional Slicing & Task Contract Execution
```bash
# Decompose a feature goal into TaskPlaybook contracts
ruby-master decompose-goal --goal "Build payment transaction domain model with RBS"

# Dispatch and execute contract through FSM and Verifier QA
ruby-master execute-contract --file contract.json
```

---

## 4. Progressive Disclosure References

- [Agent Contracts & State Machine Schema](references/agent_contracts.md): Complete JSON contract schema and FSM transitions.
- [38+ FOSS Ruby Toolchain Matrix](references/toolchain_matrix.md): Installation and invocation recipes for all tools.
- [Troubleshooting & Diagnostic Playbook](references/troubleshooting_playbook.md): Root-cause resolution guides for YJIT invalidation, Packwerk violations, and Brakeman warnings.
