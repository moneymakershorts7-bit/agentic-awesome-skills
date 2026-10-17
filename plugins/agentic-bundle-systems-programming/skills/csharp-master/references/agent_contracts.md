# Agent Execution Contracts & State Machine Specification

## 1. Task + Playbook Deterministic JSON Contract

Every task slice dispatched by the Lead Orchestrator must serialize to and validate against this JSON contract:

```json
{
  "task_id": "SLICE-001-CHANNEL-DISPATCHER",
  "assigned_agent": "async-architect",
  "scope": {
    "files_target": ["src/CSharpMaster.Core/Dispatching/ChannelDispatcher.cs"],
    "interfaces": ["IDispatcher", "IDispatcherPolicy"]
  },
  "functional_invariants": [
    "Propagates CancellationToken across all channel reads and writes",
    "Bounded channel drops or waits per policy; zero unbounded memory buffering",
    "Uses ValueTask<bool> on synchronous write checks to eliminate Task allocation"
  ],
  "playbook": {
    "verification_commands": [
      "dotnet test --filter FullyQualifiedName~ChannelDispatcherTests",
      "dotnet build /warnaserror",
      "dotnet stryker --mutate src/CSharpMaster.Core/Dispatching/ChannelDispatcher.cs"
    ],
    "known_failure_modes": [
      {
        "pattern": "System.Threading.Tasks.TaskCanceledException",
        "diagnostic_recipe": "Catch OperationCanceledException and verify clean cancellation teardown."
      },
      {
        "pattern": "Stryker mutant survived in boundary check",
        "diagnostic_recipe": "Add boundary condition unit test for channel capacity = 0 and full buffer backpressure."
      }
    ]
  }
}
```

## 2. Finite State Machine (FSM) Lifecycle

```
┌──────────────┐
│  DISPATCHED  │ ──► Assigned agent validated; inputs isolated
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   RUNNING    │ ──► Worker agent executes slice invariants
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  VERIFYING   │ ──► VerifierQaAgent applies 5 adversarial verification gates
└──────┬───────┘
       │
       ├─────────────────────────────────┐
       │ (Pass)                          │ (Fail)
       ▼                                 ▼
┌──────────────┐             ┌──────────────────────┐
│  COMPLETED   │             │ FAILED_HEALING_LOOP  │
└──────────────┘             └──────────┬───────────┘
                                        │
                                        ▼
                             Extract Diagnostic Recipe
                             from Playbook Known Failures
```

## 3. Worker Agent Responsibilities

1. **`async-architect`**:
   - Accepts task slices involving asynchronous workflows, channels, and pipelines.
   - Audits source files for `CancellationToken` propagation.
   - Enforces `.ConfigureAwait(false)` in non-UI libraries.
   - Rejects `.Result`, `.Wait()`, and `Task.Run().Wait()` unconditionally.

2. **`runtime-optimizer`**:
   - Accepts low-level parsing, memory manipulation, and serialization tasks.
   - Mandates `ReadOnlySpan<T>` and `Span<T>` for zero-copy slicing.
   - Mandates `ArrayPool<T>.Shared` and `stackalloc` for buffers.
   - Enforces Native AOT source generation and zero trimmer warnings.

3. **`domain-architect`**:
   - Accepts domain entities, aggregates, and value object modeling.
   - Enforces modern C# 12 idioms (primary constructors, records, collection expressions).
   - Enforces Railway-Oriented Programming (`Result<T, Error>`) over exception control flow.
   - Enforces ArchUnitNET hexagonal architectural governance.

4. **`security-auditor`**:
   - Accepts cryptography, containerization, and dependency management tasks.
   - Verifies Central Package Management in `Directory.Packages.props`.
   - Enforces authenticated symmetric encryption (AES-256-GCM, ChaCha20-Poly1305).
   - Bans legacy binary deserializers (`BinaryFormatter`).
   - Enforces non-root execution (`USER app` / UID 1654) on chiseled container images.

5. **`verifier-qa`**:
   - Unconditional veto authority over code integration.
   - Runs Roslyn compiler gate (`TreatWarningsAsErrors=true`).
   - Runs ArchUnitNET layer leak tests.
   - Runs Stryker mutation score checks (>= 80%).
   - Runs BenchmarkDotNet zero-regression checks.
