# Agent Contracts & Verification Architecture Specification

## 1. Core Contract Definitions

In `rust-master`, communication between the Lead Orchestrator and specialized workers is governed by immutable, strongly typed Rust structs defined in `src/core/contracts.rs`.

### A. `TaskPlaybookContract`
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPlaybookContract {
    pub task_id: String,
    pub role: String,
    pub title: String,
    pub description: String,
    pub inputs: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub playbook: Playbook,
}
```
- **`task_id`**: Globally unique slug (e.g., `slice_systems_concurrency`).
- **`role`**: Specialized agent role matching worker registration (`rust-systems-architect`, `rust-perf-optimizer`, `rust-safety-auditor`, `rust-api-engineer`, `rust-verifier-qa`).
- **`inputs`**: Target source files, modules, or directories scoped to the slice.
- **`acceptance_criteria`**: Deterministic, non-negotiable success conditions.
- **`playbook`**: Self-healing execution runbook.

### B. `Playbook` (Self-Healing Runbook)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub verification_commands: Vec<String>,
    pub timeout_seconds: u64,
    pub expected_failure_modes: Vec<String>,
    pub self_healing_recipes: Vec<String>,
}
```
Every playbook equips the worker with:
1. Exact terminal verification commands (e.g. `cargo check`, `cargo test`, `cargo clippy`).
2. Known failure modes (e.g. `E0502: cannot borrow *x as mutable because it is also borrowed as immutable`).
3. Concrete self-healing actions so the worker fixes errors deterministically rather than cycling in speculative loops.

### C. `ExecutionResult`
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub task_id: String,
    pub role: String,
    pub status: TaskStatus,
    pub pruned_summary: String,
    pub artifacts: Vec<String>,
    pub diagnostics: Vec<String>,
    pub completed_at: DateTime<Utc>,
}
```
- **Bounded Slicing Token Control**: Workers MUST keep `pruned_summary` under 300 tokens to preserve the Orchestrator's context window.

---

## 2. State Machine & Task Status Lifecycle

```
[Registered] ───► [InProgress] ───► [Worker Complete]
                                           │
                                           ▼
                             [Adversarial Verification Gate]
                                    │               │
                               (PASS)              (FAIL)
                                    ▼               ▼
                             [VerifiedPass]  [VerificationFailed]
                                                    │
                                                    ▼
                                           [Self-Healing Loop]
```

Statuses:
- `TaskStatus::Registered`: Task contract registered in `Orchestrator`.
- `TaskStatus::InProgress`: Worker executing slice logic.
- `TaskStatus::VerifiedPass`: Passed both worker execution and Independent Adversarial QA Gate.
- `TaskStatus::ExecutionFailed`: Worker failed playbook commands or preconditions.
- `TaskStatus::VerificationFailed`: Adversarial gate detected a test failure, AST violation, or mutant survivor.
