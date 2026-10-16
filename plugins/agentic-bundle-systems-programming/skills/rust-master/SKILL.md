---
name: rust-master
description: Use this skill whenever building, modifying, refactoring, optimizing, or auditing Rust applications and libraries. Orchestrates 4 domain-specialized Rust agents (systems-architect, perf-optimizer, safety-auditor, api-engineer) and an independent adversarial verification gate (verifier-qa), grounded in 497+ canonical literature documents and 38+ FOSS verification tools.
allowed-tools:
  - run_command
  - Bash
  - shell
  - view_file
  - replace_file_content
  - write_to_file
---

# `rust-master`: Autonomous Rust Engineering Skill

This skill operationalizes the **`rust-master`** platform located at `/home/npirela/rust-master`. It provides agents with deterministic instructions, contracts, and workflows to orchestrate, execute, manage, and extend the 4 domain-specialized Rust workers and the independent adversarial verification gate.

---

## 1. Non-Negotiable Invariant

> **MANDATORY POLICY:** Whenever coding, reviewing, refactoring, benchmarking, or auditing code in the Rust programming language, the agent **MUST ALWAYS** invoke and adhere to `rust-master`.

---

## 2. Frontier Orchestrator-Worker Architecture

`rust-master` eliminates both the *Monolithic God-Agent* (context pollution, instruction drift) and the *Chatty Role-Playing Committee* (lossy conversational telephone, runaway token tax):

1. **Lead Orchestrator (Single Source of Truth):**
   - Coordinates execution across bounded functional slices.
   - Maintains roadmap and state deterministically on disk in `CURRENT_TASK.md`.
2. **Bounded Ephemeral Workers:**
   - Execute single-responsibility tasks under a strict token budget.
   - Return distilled executive summaries (<300 tokens) with deterministic diagnostics.
3. **Independent Adversarial Verification Gate (`rust-verifier-qa`):**
   - Operates in a fresh context with **zero confirmation bias** (Maker/Checker orthogonality).
   - Validates format, compiler strictness, 100% test pass, AST unsafe hygiene, and mutation resilience before declaring any slice completed.

---

## 3. Specialized Agent Squad Directory

| Agent Identifier | Role | Primary Toolsets | Grounding Sources |
| :--- | :--- | :--- | :--- |
| **`rust-systems-architect`** | Concurrency, Atomics & Boundaries | `AstAnalyzer`, `CargoRunner`, `CorpusIndexer` | `idiomatic_rust`, `rust_async_book`, `little_book_of_rust_macros` |
| **`rust-perf-optimizer`** | Memory Layout, SIMD & Latency | `BenchmarkRunner`, `CargoRunner`, `CorpusIndexer` | `rust_perf_book`, `[profile.release]` compiler tuner |
| **`rust-safety-auditor`** | Memory Safety, Miri & Unsafe Audit | `AstAnalyzer`, `CargoRunner (audit, geiger)`, `CorpusIndexer` | `anssi_rust_security`, `rust_nomicon`, `rust_formal_verification` |
| **`rust-api-engineer`** | Idiomatic Crate APIs & Pedantic Lint | `CargoRunner (clippy, fmt, machete, semver)`, `AstAnalyzer` | `rust_api_guidelines`, `rust_reference` |
| **`rust-verifier-qa`** | Independent Adversarial Verification | `CargoRunner (test, nextest)`, `MutationRunner`, `AstAnalyzer` | Orthogonal Maker/Checker verification gate |

---

## 4. Operational Execution Protocols

### A. Full Autonomous Orchestration
Execute all 4 specialized slices through the Lead Orchestrator with adversarial QA verification:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- orchestrate
```

### B. Trigger Adversarial Verification Gate
Run independent verification against a target crate or workspace:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- verify --target <path>
```

### C. Direct Worker Invocation
Invoke an individual specialized worker on a bounded task contract:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- run-agent \
  --name rust-safety-auditor \
  --task-id slice_safety_audit
```

### D. AST Safety & Unsafe Invariant Audit
Scan any `.rs` file to count structs, traits, functions, and enforce mandatory `// SAFETY:` justifications:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- audit-ast \
  --file <path_to_source.rs>
```

### E. Literature Grounding Search
Query the 497+ ingested canonical markdown books and specifications:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- search-corpus \
  --query "stacked borrows aliasing miri" \
  --limit 5
```

### F. Monthly Documentation Freshness Cadence
Check if documentation has exceeded its 30-day freshness lifespan:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- check-docs-cadence
```
To refresh the manifest and stamp a new 30-day window:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- update-docs
```

### G. FOSS Toolchain Inventory
Display all 38+ supported FOSS safety, reliability, and optimization tools:
```bash
cargo run --manifest-path /home/npirela/rust-master/Cargo.toml -- list-tools
```

---

## 5. Implementing & Extending New Agents / Slices

To implement a new specialized task slice or agent:

1. **Define the Contract & Playbook:**
   ```rust
   let contract = TaskPlaybookContract::new(
       "slice_domain_id",
       "rust-systems-architect",
       "Slice Title",
       "Unambiguous functional objective",
       vec!["src/domain/module.rs".to_string()],
       vec!["Invariant 1".to_string(), "Invariant 2".to_string()],
       Playbook {
           verification_commands: vec!["cargo test".to_string(), "cargo clippy".to_string()],
           timeout_seconds: 60,
           expected_failure_modes: vec!["Borrow checker conflict".to_string()],
           self_healing_recipes: vec!["Refactor lifetimes or use Arc/Mutex".to_string()],
       },
   );
   ```
2. **Implement the `Agent` Trait:**
   ```rust
   impl Agent for MyCustomAgent {
       fn name(&self) -> &'static str { "rust-custom-worker" }
       fn role(&self) -> &'static str { "Specialized Domain Worker" }
       fn execute(&self, contract: &TaskPlaybookContract) -> Result<ExecutionResult, AgentError> {
           // 1. Ground against knowledge base
           // 2. Execute verification commands from playbook
           // 3. Return bounded ExecutionResult (<300 token summary)
       }
   }
   ```
3. **Register with the Orchestrator:**
   ```rust
   let mut orchestrator = Orchestrator::new(workspace_path)?;
   orchestrator.register_task(contract)?;
   let result = orchestrator.execute_slice("slice_domain_id", &worker, &verifier)?;
   ```

---

## 6. DevSecOps & SecSDLC Integration

`rust-master` is the canonical Rust engine for `devsecops-master`:
```bash
python3 ~/.agents/skills/devsecops-master/scripts/rust_master_gate.py <crate_path>
```
The gate checks:
- **SAST**: Pedantic Clippy pass (`cargo clippy -- -D warnings -W clippy::pedantic`).
- **SCA**: Deterministic `Cargo.lock` dependency pinning and `cargo audit`.
- **Memory Safety**: AST analysis of unsafe blocks for missing `// SAFETY:` invariants.
- **Testing**: 100% test suite pass rate with zero failures.

---

## 7. Progressive Disclosure References

- [`references/agent_contracts.md`](references/agent_contracts.md): Complete specifications for contracts, state transitions, and execution payloads.
- [`references/toolchain_matrix.md`](references/toolchain_matrix.md): Exhaustive guide to the 38+ FOSS verification, fuzzing, and optimization tools.
- [`references/troubleshooting_playbook.md`](references/troubleshooting_playbook.md): Diagnostic runbooks for borrow-checker conflicts, memory alignment, and unsafe soundness.
