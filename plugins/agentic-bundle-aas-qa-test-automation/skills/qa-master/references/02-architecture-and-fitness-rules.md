# Architecture & System Integrity Rules: ISO 25010, ISO 5055 & Fitness Functions

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                      ISO/IEC 25010 & ISO/IEC 5055 ARCHITECTURAL ENGINE                  │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ Standards: ISO 25010 (SQuaRE) | ISO 5055 (CISQ 148 Code Rules) | IEEE 1016:2009         │
│            C4 Architecture Model | OpenAPI 3.1 / AsyncAPI | Architecture Fitness Rules  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. ISO/IEC 5055:2021 Automated Source Code Quality Measures

ISO/IEC 5055 defines 148 machine-verifiable rules derived from the Consortium for Information & Software Quality (CISQ), mapped directly to the Common Weakness Enumeration (CWE).

### 1.1 Reliability Pillar (CISQ-REL)
- **REL-01 (CWE-404 / CWE-775): Resource Leak Prevention:**
  - Every allocated operating system resource (file descriptors, sockets, database connections, locks) must be released along every execution path (including exceptions and early returns).
  - *Automated AST Rule:* Ensure all I/O handles are wrapped in contextual resource managers (`with`, `try-with-resources`, `defer`, `using`).
- **REL-02 (CWE-391): Unchecked Error Conditions:**
  - Prohibition of empty catch/except blocks or ignored error return values (e.g. `_ = err` in Go, `except: pass` in Python).
- **REL-03 (CWE-362 / CWE-820): Thread Synchronization & Race Conditions:**
  - Shared mutable state accessed concurrently must be guarded by mutual exclusion primitives or channeled via thread-safe abstractions.

### 1.2 Security Pillar (CISQ-SEC)
- **SEC-01 (CWE-89 / CWE-78 / CWE-77): Injection Prevention:**
  - All SQL, shell command, LDAP, or template queries must use parameterized interfaces and strict input sanitization.
- **SEC-02 (CWE-798 / CWE-259): Hardcoded Credentials:**
  - Zero hardcoded passwords, API keys, or private keys in source code AST or string literals.
- **SEC-03 (CWE-120 / CWE-119): Buffer Bounds Safety:**
  - For C/C++ components: Prohibition of unbounded functions (`strcpy`, `sprintf`, `gets`). Mandatory use of length-checked alternatives (`strncpy`, `snprintf`).

### 1.3 Performance Efficiency Pillar (CISQ-PERF)
- **PERF-01 (CWE-1050): Excessive Algorithmic Complexity in Loops:**
  - Nested loops performing repetitive database queries (the $N+1$ query anti-pattern).
- **PERF-02 (CWE-834): Unbounded Iteration / Infinite Loops:**
  - Loop termination conditions must be provably monotonic and bounded.
- **PERF-03: Blocking I/O on Event Loops:**
  - In asynchronous runtimes (Node.js, asyncio, Go goroutines), no synchronous, blocking system calls (`time.sleep`, synchronous disk reads) are permitted on the main event thread.

### 1.4 Maintainability Pillar (CISQ-MAINT)
- **MAINT-01: Cyclomatic Complexity (McCabe CC):**
  - McCabe Cyclomatic Complexity must be $\le 10$ for any function or method. Functions exceeding 10 must be partitioned into modular helper functions.
- **MAINT-02: Cognitive Complexity:**
  - Cognitive Complexity must be $\le 15$ per function.
- **MAINT-03: Maximum Nesting Depth:**
  - Control flow indentation must not exceed 4 levels.
- **MAINT-04: Maximum File Length:**
  - Source files must not exceed 500 lines of code (LOC), enforcing bounded functional decomposition.

---

## 2. Architecture Documentation & The C4 Model (IEEE 1016:2009)

IEEE 1016:2009 requires documenting systems across 10 formal viewpoints: Context, Composition, Logical, Dependency, Information, Patterns, Interface, Structure, Interaction, and State Dynamics.

### The C4 Model Levels
1. **Level 1: System Context Diagram:**
   - Visualizes how the system interacts with external users, actors, and other enterprise systems.
2. **Level 2: Container Diagram:**
   - Decomposes the system into deployable units (applications, microservices, databases, caches, message queues).
3. **Level 3: Component Diagram:**
   - Decomposes a single container into modular internal components, controllers, domain services, and repositories.
4. **Level 4: Code Diagram:**
   - Class and interface hierarchy diagrams showing method signatures and inheritance (typically generated on-demand).

### Architectural Decision Records (ADRs)
Every architectural change must be recorded in `docs/adr/ADR-XXXX.md` using the standard structure:
- **Title & Status:** [PROPOSED | ACCEPTED | SUPERSEDED]
- **Context & Problem Statement:** What trade-offs require a decision?
- **Decision Outcome:** What was decided, with exact rationale.
- **Consequences:** Positive and negative downstream impacts.

---

## 3. Architecture Fitness Functions & Boundary Governance

Architecture fitness functions are automated tests that verify architectural constraints remain intact over time:

1. **Layered Isolation Rule:**
   - Presentation/API layer may depend on Domain Services.
   - Domain Services may depend on Domain Entities and Repository Interfaces.
   - Domain Entities **must never** depend on Database Drivers, HTTP frameworks, or Infrastructure SDKs.
2. **Circular Dependency Prohibition:**
   - Package/module dependency graphs must form a Directed Acyclic Graph (DAG).
3. **Interface Contract Adherence:**
   - Public APIs must strictly conform to their OpenAPI 3.1 or AsyncAPI schemas. Schema changes that remove fields or change types without major version bumps are rejected by the CI gate.
