# .NET 10 LTS & .NET 11 Architecture, Modern Idioms & Agent Invariants

This reference guide specifies the modern language features, runtime advancements, cryptographic standards, and agent verification invariants implemented in `csharp-master`.

---

## 1. Modern Language Invariants (C# 13, C# 14, C# 15)

### 1.1 `System.Threading.Lock` vs Legacy Synchronization
* **Invariant:** Legacy `lock (object)` or `Monitor.Enter` is deprecated in .NET 10.
* **Modern Pattern:** Use `System.Threading.Lock` with `lock (lockObj)` or explicit `using (lockObj.EnterScope())`.
* **Benefit:** Reduces synchronization overhead, avoids syncblock table lookups, and provides deterministic zero-allocation scope disposal.

### 1.2 `params ReadOnlySpan<T>` Caller Ergonomics
* **Invariant:** Public and high-throughput APIs must prefer `params ReadOnlySpan<T>` over `params T[]`.
* **Benefit:** Callers passing literals, arrays, or stack-allocated buffers incur **0 B heap allocations**, avoiding ephemeral garbage collection pressure.

### 1.3 `allows ref struct` Anti-Constraints
* **Invariant:** Generic interfaces and algorithms operating over memory spans must declare `allows ref struct`.
* **Benefit:** Allows `ReadOnlySpan<T>` and custom ref structs to implement interfaces and participate in generic pipelines without heap boxing.

### 1.4 `field` Contextual Keyword in Semi-Auto Properties
* **Invariant:** Use the `field` keyword to access property backing storage without declaring manual private fields.
* **Benefit:** Reduces boilerplate while retaining validation, logging, and property change notifications.

### 1.5 `[OverloadResolutionPriority]` for High-Performance Evolution
* **Invariant:** Mark modern span-based overloads with `[OverloadResolutionPriority(1)]` to prefer high-performance paths without breaking binary backward compatibility.

---

## 2. Runtime & Cloud-Native Primitives

### 2.1 Multi-Tier `HybridCache` with Stampede Protection
* **Invariant:** Distributed caching architectures must utilize `HybridCache` rather than raw dual-layer `IMemoryCache` + `IDistributedCache`.
* **Benefit:** Automatic stampede locking (concurrent requests await the single in-flight factory task) and transparent L1 (in-process) + L2 (out-of-process) coordination.

### 2.2 Post-Quantum Cryptography (PQC) Readiness
* **Invariant:** Long-term security domains must prepare for Shor's algorithm by adopting quantum-resistant cryptographic algorithms:
  - `ML-KEM` (Module-Lattice-based Key-Encapsulation Mechanism, NIST FIPS 203) for key exchange.
  - `ML-DSA` (Module-Lattice-based Digital Signature Algorithm, NIST FIPS 204) for digital signatures.
* **Deprecation:** Flags unauthenticated classical ciphers and single-round RSA/ECDSA in high-security scopes.

### 2.3 SIMD Acceleration via `TensorPrimitives`
* **Invariant:** Vectorized mathematical, embedding, and machine learning array computations must leverage `System.Numerics.Tensors.TensorPrimitives`.
* **Benefit:** Automatically vectorizes operations across AVX-512, Arm Neon, and AVX10.2 hardware instructions.

### 2.4 Next-Generation Server GC (Dynamic Regions)
* **Invariant:** In .NET 11, configure dynamic region-based Server GC for multi-gigabyte memory heaps to achieve near-zero pause times and eliminate segment fragmentation.

---

## 3. Agent Diagnostic Runbook & Failure Codes

| Diagnostic Code | Description | Automated Self-Healing Runbook Recipe |
|---|---|---|
| **CS9216** | Lock statement cannot use `System.Threading.Lock` as a monitor | Replace legacy `Monitor` call with `lock (lockObj)` or `using (lockObj.EnterScope())`. |
| **CS8773** | Feature 'params collections' is not available in C# 12 | Upgrade csproj to `<LangVersion>13</LangVersion>` or `<LangVersion>latest</LangVersion>`. |
| **CS9244** | Type may not be a ref struct or parameter allowing ref structs | Add `where T : allows ref struct` anti-constraint to generic signature. |
| **PQC-001** | Classical RSA/ECDSA key exchange detected in long-term scope | Migrate to hybrid Post-Quantum Cryptography (ML-KEM / ML-DSA). |
| **CACHE-002** | Cache stampede vulnerability in concurrent factory | Migrate to `HybridCache.GetOrCreateAsync()`. |
