# Playbook 07: Rust Master Autonomous SecSDLC Quality Gate

This playbook details how to operationalize `rust-master` as the official Rust security, memory safety, and architectural assurance engine within the `devsecops-master` framework.

---

## 1. Overview & Architectural Role

`rust-master` serves as the specialized Rust SecSDLC engine within `devsecops-master`. It implements an Orchestrator-Worker architecture featuring 4 specialized developer agents and 1 independent QA/Security verification gate:

```
┌────────────────────────────────────────────────────────┐
│             Lead Orchestrator (Single Source of Truth) │
└───────────────────────────┬────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌───────────────────────────────┐     ┌───────────────────────────────┐
│  Bounded Worker Execution     │     │ Independent Verification Gate │
│  - Systems Architect (Zero-UB)│     │ (Agent 5: QA & SecSDLC)       │
│  - Performance (Cache/SIMD)   │     │ - Clippy Pedantic & Rustfmt   │
│  - Safety Auditor (// SAFETY:)│     │ - Cargo Audit & Cargo Deny    │
│  - API Engineer (API Rules)   │     │ - AST Safety & Miri Invariants│
└───────────────────────────────┘     └───────────────────────────────┘
```

---

## 2. Running the Rust Master Quality Gate

Execute the bundled deterministic quality gate script:

```bash
python3 ~/.agents/skills/devsecops-master/scripts/rust_master_gate.py [target_dir]
```

### Automated Battery Checks:
1. **SAST Analysis:** `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic` ensures zero compiler or linter warnings.
2. **SCA Dependency Audit:** `cargo audit` cross-references `Cargo.lock` against the RustSec Advisory Database.
3. **Unsafe AST & Memory Invariants:** `rust-master audit-ast` scans all `.rs` files and ensures every `unsafe` block includes an explicit `// SAFETY:` justification comment.
4. **Deterministic Testing:** `cargo test --all-targets --all-features` validates 100% test suite pass rate.
5. **Mutation & Property Testing:** `cargo mutants` and `proptest` verify test suite resilience against subtle mutant injection.

---

## 3. Integrating into CI/CD Pipelines

Add the gate as a blocking step in `.github/workflows/security-gate.yml`:

```yaml
      - name: Rust Master SecSDLC Quality Gate
        run: |
          python3 ~/.agents/skills/devsecops-master/scripts/rust_master_gate.py . --format markdown
```

The gate returns exit code `0` on clean verification and exit code `1` if any critical blocker is encountered.

---

## 4. Scorecard & Blocking Invariants

| Category | Blocker Condition | Corrective Playbook Action |
| :--- | :--- | :--- |
| **SAST** | Any Clippy pedantic warning or error | Run `cargo clippy --fix` and resolve remaining linter diagnostics. |
| **SCA** | Known CVE or unpinned dependency | Run `cargo update` or patch affected crates in `Cargo.toml`. |
| **Memory Safety** | Unsafe block lacking `// SAFETY:` comment | Document the safety invariants or refactor to safe primitives. |
| **Testing** | Any test failure or mutation leakage | Fix broken assertions or add property-based edge-case tests. |
