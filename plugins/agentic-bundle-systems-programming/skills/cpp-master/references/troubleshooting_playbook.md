# `cpp-master` Self-Healing Troubleshooting Playbook

Deterministic runbooks and corrective recipes for Modern C++ failures.

---

## 1. AddressSanitizer (ASan) Failures

### A. Heap/Stack Buffer Overflow
- **Signature:** `ERROR: AddressSanitizer: heap-buffer-overflow` / `stack-buffer-overflow`.
- **Root Cause:** Indexing past container bounds, raw pointer arithmetic without length bounds.
- **Diagnostics:**
  ```bash
  ASAN_OPTIONS=abort_on_error=1:symbolize=1 ./build/bin/target
  gdb --args ./build/bin/target
  ```
- **Corrective Action:**
  1. Replace raw arrays or pointers with `std::span<T>` or `std::vector<T>`.
  2. Use `std::ranges::subrange` or `std::span::subspan` with explicit extent verification.
  3. Enforce bounds checking via `.at()` in debug builds or `gsl::at` / bounds assertions.

### B. Use-After-Free (UAF) & Dangling References
- **Signature:** `ERROR: AddressSanitizer: heap-use-after-free`.
- **Root Cause:** Capturing temporary references in lambdas, dangling `std::string_view`, invalidating iterators during container reallocation.
- **Corrective Action:**
  1. Enforce strict RAII ownership via `std::unique_ptr<T>` or `std::shared_ptr<T>`.
  2. Ensure lambda captures pass by value `[=]` or explicitly capture owned pointers.
  3. Never return `std::string_view` pointing to a local temporary `std::string`.

---

## 2. UndefinedBehaviorSanitizer (UBSan) Failures

### A. Signed Integer Overflow
- **Signature:** `runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'`.
- **Diagnostics:**
  ```bash
  UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./build/bin/target
  ```
- **Corrective Action:**
  1. Use standard safe comparison utilities: `std::cmp_equal`, `std::cmp_less`.
  2. Switch to explicit modular unsigned arithmetic (`uint64_t`) where wrap-around is intended.
  3. Check arithmetic boundaries before operations: `if (a > std::numeric_limits<int>::max() - b)`.

### B. Misaligned Memory Load
- **Signature:** `runtime error: load of misaligned address 0x... for type 'const uint64_t'`.
- **Corrective Action:**
  1. Use `alignas(alignof(T))` on memory buffers.
  2. For packed protocol parsing, use `std::memcpy` into local variables rather than casting raw byte pointers.

---

## 3. ThreadSanitizer (TSan) Failures

### A. Data Race on Unprotected Memory
- **Signature:** `WARNING: ThreadSanitizer: data race (Write of size 8 at 0x... by thread T1 and Read of size 8 by thread T2)`.
- **Corrective Action:**
  1. Replace naked shared variables with `std::atomic<T>`.
  2. Audit atomic memory orders: use `std::memory_order_release` on stores and `std::memory_order_acquire` on loads. Avoid indiscriminate `std::memory_order_relaxed`.
  3. Protect compound read-modify-write sequences with `std::scoped_lock`.

### B. Lock Order Inversion / Deadlock
- **Signature:** `WARNING: ThreadSanitizer: lock-order-inversion (potential deadlock)`.
- **Corrective Action:**
  1. Always acquire multiple mutexes atomically using `std::scoped_lock lock(mtx_a, mtx_b);`.
  2. Never call third-party callbacks or unknown virtual methods while holding a lock.

---

## 4. Microarchitecture & Performance Bottlenecks

### A. False Sharing on Multi-Threaded Hot Paths
- **Signature:** Severe multi-core scaling degradation; high L1/L2 cache invalidate traffic in `perf stat`.
- **Diagnostics:**
  ```bash
  perf c2c record -- ./build/bin/target && perf c2c report
  ```
- **Corrective Action:**
  1. Align thread-local or per-core structures to cache lines using `alignas(std::hardware_destructive_interference_size)` (or 64 bytes).
  2. Pad structures to prevent separate core writes hitting the same 64-byte cache line.

### B. Branch Misprediction & Pipeline Stalls
- **Diagnostics:** `perf stat -e branches,branch-misses,cycles,instructions ./build/bin/target`.
- **Corrective Action:**
  1. Annotate asymmetric branch likelihoods with `[[likely]]` / `[[unlikely]]`.
  2. Convert switch statements or polymorphic dispatch to branchless table lookups or `std::visit` over `std::variant`.

---

## 5. Build & Compilation Failures

### A. Template Bloat & Long Compile Times
- **Diagnostics:** Compile with Clang `-ftime-trace` and inspect JSON in Speedscope.
- **Corrective Action:**
  1. Separate template declarations from definitions using explicit template instantiation (`extern template class ...`).
  2. Move non-templated helper logic out of template class bodies.
  3. Adopt C++20 Modules (`export module ...; import ...;`) to eliminate repetitive textual header inclusion.
