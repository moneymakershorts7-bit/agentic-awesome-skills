# Full 38+ FOSS Rust Toolchain Matrix & Usage Reference

## 1. Safety, Sanitizers & Formal Verification

| Tool | CLI Command | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`miri`** | `cargo miri test` | UB Detection | Detects Stacked/Tree Borrows violations, unaligned memory, data races, leaks | `rustup component add miri` |
| **`kani`** | `cargo kani` | SMT Model Checker | Formally proves zero panics, bounds violations, and arithmetic overflows | `cargo install --locked kani-verifier && cargo kani setup` |
| **`loom`** | `cargo test --features loom` | Concurrency State-Space | Permutation testing of thread interleavings under C11 atomic memory models | Add `loom = "0.7"` to `Cargo.toml` |
| **`prusti`** | `cargo-prusti` | Deductive Verification | Viper-based separation logic verification for functional correctness | `cargo install prusti-server prusti-driver` |
| **`creusot`** | `creusot-rustc` | Deductive Verification | Translates Rust into Why3 logic formulas for machine checking | GitHub: `creusot-rs/creusot` |
| **`verus`** | `verus` | SMT Systems Verification | Formal verification of systems Rust using Z3 SMT solver | GitHub: `verus-lang/verus` |
| **`careful`** | `cargo careful test` | Sanitizer Wrapper | Executes tests under ASAN/MSAN and extra standard library debug assertions | `cargo install cargo-careful` |

---

## 2. Reliability, Fuzzing & Testing

| Tool | CLI Command | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`mutants`** | `cargo mutants --no-shuffle` | Mutation Testing | Injects function mutations to detect untested execution paths | `cargo install cargo-mutants` |
| **`fuzz`** | `cargo fuzz run <target>` | LLVM libFuzzer | Coverage-guided continuous fuzz testing | `cargo install cargo-fuzz` |
| **`afl`** | `cargo afl fuzz` | Genetic Fuzzing | American Fuzzy Lop genetic fuzz testing integration | `cargo install cargo-afl` |
| **`bolero`** | `cargo bolero test` | Unified Property/Fuzz | Unified facade for property testing, Kani, and fuzzing | `cargo install cargo-bolero` |
| **`proptest`** | `cargo test` | Generative Testing | Generates pseudo-random, shrinking counterexamples for edge cases | Add `proptest = "1.5"` to `[dev-dependencies]` |
| **`nextest`** | `cargo nextest run` | Test Runner | Parallel, isolated test runner with retries and timeout enforcement | `cargo install cargo-nextest` |
| **`llvm-cov`** | `cargo llvm-cov` | Source Code Coverage | Accurate LLVM-based line and branch coverage | `cargo install cargo-llvm-cov` |
| **`tarpaulin`**| `cargo tarpaulin` | Native Code Coverage | Linux ptrace-based source coverage reporting | `cargo install cargo-tarpaulin` |

---

## 3. Linting, Formatting & API Quality

| Tool | CLI Command | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`clippy`** | `cargo clippy -- -D warnings -W clippy::pedantic` | Static Analysis | 700+ lints across correctness, style, perf, and pedantic rules | `rustup component add clippy` |
| **`fmt`** | `cargo fmt -- --check` | AST Formatter | Deterministic code style standard | `rustup component add rustfmt` |
| **`semver-checks`**| `cargo semver-checks check-release` | API SemVer Linter | Detects unintended breaking changes in public crate interfaces | `cargo install cargo-semver-checks` |
| **`machete`** | `cargo machete` | Dependency Hygiene | Detects unused crates listed in `Cargo.toml` | `cargo install cargo-machete` |
| **`deny`** | `cargo deny check` | Dependency Gate | Enforces license compatibility, security advisories, and crate bans | `cargo install cargo-deny` |
| **`spellcheck`**| `cargo spellcheck` | Documentation Linter | Validates spelling and documentation formatting in doc comments | `cargo install cargo-spellcheck` |
| **`modules`** | `cargo modules structure` | Architecture Visualizer | Visualizes crate module tree and visibility boundaries | `cargo install cargo-modules` |
| **`diet`** | `cargo diet` | Packaging Optimizer | Calculates lean package payloads before crates.io publication | `cargo install cargo-diet` |

---

## 4. Optimization, Profiling & Benchmarking

| Tool | CLI Command | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`bloat`** | `cargo bloat --release --crates` | Binary Size Analysis | Breaks down binary size by crate, struct, and function | `cargo install cargo-bloat` |
| **`llvm-lines`**| `cargo llvm-lines` | Monomorphization Linter | Counts LLVM IR lines generated per generic function instantiation | `cargo install cargo-llvm-lines` |
| **`pgo`** | `cargo pgo build` | Profile-Guided Optimization | Automates PGO instrumentation, training data collection, and BOLT | `cargo install cargo-pgo` |
| **`wizard`** | `cargo wizard` | Profile Configuration | Configures optimal `[profile.release]` settings for size and speed | `cargo install cargo-wizard` |
| **`criterion`** | `cargo bench` | Micro-Benchmarking | Statistical benchmarking with outlier analysis and confidence intervals | Add `criterion = "0.5"` to `[dev-dependencies]` |
| **`divan`** | `cargo bench` | Allocation Benchmarking | Fast modern benchmarking measuring CPU cycles and heap allocations | Add `divan = "0.1"` to `[dev-dependencies]` |
| **`show-asm`** | `cargo asm <symbol>` | Machine Code Inspection | Shows disassembled assembly, machine code, and LLVM IR | `cargo install cargo-show-asm` |
| **`flamegraph`**| `cargo flamegraph` | CPU Profiling | Generates interactive SVG flamegraphs using Linux `perf` or macOS `dtrace`| `cargo install flamegraph` |
| **`dhat`** | `cargo test` (dhat) | Dynamic Heap Analysis | Measures allocation volume, peak heap size, and temporary churn | Add `dhat = "0.3"` to `Cargo.toml` |

---

## 5. Supply Chain Security & SBOM

| Tool | CLI Command | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`audit`** | `cargo audit` | CVE Vulnerability Scan | Scans `Cargo.lock` against RustSec Advisory Database | `cargo install cargo-audit` |
| **`geiger`** | `cargo geiger` | Unsafe Code Auditor | Audits crate dependencies for `unsafe` usage statistics | `cargo install cargo-geiger` |
| **`vet`** | `cargo vet` | Supply Chain Vetting | Mozilla tool auditing supply chain before dependency upgrades | `cargo install cargo-vet` |
| **`crev`** | `cargo crev verify` | Web of Trust | Cryptographically verifiable code reviews from peer developers | `cargo install cargo-crev` |
| **`cyclonedx`** | `cargo cyclonedx --format json` | SBOM Generator | Generates CycloneDX compliant Software Bill of Materials | `cargo install cargo-cyclonedx` |
| **`auditable`** | `cargo auditable build` | Binary Provenance | Embeds dependency metadata into compiled ELF/Mach-O binaries | `cargo install cargo-auditable` |
