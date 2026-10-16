# Decision Tree Patterns for Grill-Me Protocol

When an agent enters a grilling session, it maps the user's intent as a **Design Tree**. A decision tree partitions ambiguity into hierarchical decision branches where deeper technical details depend on higher-level architectural decisions.

```
                         [ USER GOAL / PROMPT ]
                                    │
               ┌────────────────────┴────────────────────┐
               ▼                                         ▼
      [ Level 1: Scope & Boundaries ]           [ Level 1: Data Contracts ]
               │                                         │
       ┌───────┴───────┐                         ┌───────┴───────┐
       ▼               ▼                         ▼               ▼
  [In-Tree Mod]   [New Standalone]          [Pydantic/TS]     [Raw Dict/JSON]
       │               │                         │               │
       └───────┬───────┘                         └───────┬───────┘
               ▼                                         ▼
      [ Level 2: Tech Stack ]                   [ Level 2: Error Handling ]
               │                                         │
       ┌───────┴───────┐                         ┌───────┴───────┐
       ▼               ▼                         ▼               ▼
  [Stdlib / Low]  [External Lib]            [Fail-Fast]       [Graceful Fallback]
```

---

## 1. Feature Implementation Archetype

When the user asks to implement a new feature, decompose the tree in this exact order:

1. **Frontier Round 1: Scope & Integration Boundary**
   - *Question:* Is this an extension of an existing module or an isolated new component?
   - *Recommendation:* Extend existing module if related logic exists; isolate if distinct domain.
   - *Prerequisite settled:* Target directory and file names.

2. **Frontier Round 2: Data Model & Contracts**
   - *Question:* What schema or typing standard should be enforced?
   - *Recommendation:* Strict Pydantic models (Python) or TypeScript strict interfaces.
   - *Prerequisite settled:* Input/output data structures.

3. **Frontier Round 3: Execution Runtime & Stack**
   - *Question:* What runtime dependencies are permitted?
   - *Recommendation:* Zero external dependencies (stdlib + existing project packages).
   - *Prerequisite settled:* Dependency footprint.

4. **Frontier Round 4: Verification & Acceptance Gates**
   - *Question:* How should completion be proven deterministically?
   - *Recommendation:* Automated unit tests + zero linter/security violations.

---

## 2. Refactoring & Optimization Archetype

When the user asks to refactor, speed up, or clean code:

1. **Frontier Round 1: Invariant Preservation**
   - *Question:* Are existing external public APIs and CLI signatures strictly immutable?
   - *Recommendation:* Yes, maintain 100% backwards compatibility; modify internals only.

2. **Frontier Round 2: Performance Target vs Simplicity**
   - *Question:* Is the priority maximum throughput (e.g. multi-threading/C-bindings) or code readability/maintainability?
   - *Recommendation:* Readability first, applying algorithmic optimizations (e.g., hash maps over nested loops) before concurrent complexity.

---

## 3. DevOps & Infrastructure Archetype

1. **Frontier Round 1: Environment Scope**
   - *Question:* Is this configuration meant for local development, staging, or production?
   - *Recommendation:* Production-hardened with local dev fallbacks.

2. **Frontier Round 2: Secrets & Security Posture**
   - *Question:* Where do environment credentials originate?
   - *Recommendation:* Environment variables / secret manager; strict prohibition of hardcoded strings.
