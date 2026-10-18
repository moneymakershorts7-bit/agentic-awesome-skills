# Self-Healing Troubleshooting Playbook

This playbook provides automated diagnostic recipes and patterns for resolving common compiler, sanitizer, static analysis, and runtime failures encountered by `c-master` worker agents.

---

## 1. AddressSanitizer (ASan) Errors

### A. Heap-Use-After-Free (UAF)
- **Error Pattern**: `ERROR: AddressSanitizer: heap-use-after-free on address ...`
- **Root Cause**: Reading or writing through a pointer after `free()` has already been invoked on that memory block.
- **Diagnostic Recipe**:
  1. Identify where `free(ptr)` was called in the stack trace.
  2. Implement single-exit cleanup discipline (`goto cleanup;`) so pointers are only freed once.
  3. Immediately set pointer to `nullptr` after `free(ptr); ptr = nullptr;`.
  4. Alternatively, use an Arena Allocator (`arena_t`) where objects are never individually freed.

### B. Global/Stack/Heap Buffer Overflow
- **Error Pattern**: `ERROR: AddressSanitizer: global-buffer-overflow` or `heap-buffer-overflow`
- **Root Cause**: Indexing beyond array bounds or writing strings without reserving space for `\0`.
- **Diagnostic Recipe**:
  1. Replace unbounded string functions (`strcpy`, `strcat`, `sprintf`) with `cmaster_strlcpy`, `cmaster_strlcat`, or `snprintf`.
  2. In ring buffers or arrays, verify the mask operation `idx & (capacity - 1)` uses a strictly power-of-two capacity.
  3. Ensure loop bounds terminate at `< size` rather than `<= size`.

---

## 2. UndefinedBehaviorSanitizer (UBSan) Errors

### A. Misaligned Address Member Access
- **Error Pattern**: `runtime error: member access within misaligned address ...`
- **Root Cause**: Casting a byte buffer or pointer to a struct/type that requires stricter natural alignment (e.g. 8 bytes) than the pointer provides.
- **Diagnostic Recipe**:
  1. In custom allocators, round the bump offset up using:
     `offset = (offset + align - 1) & ~(align - 1);`
  2. Align critical structs to cache-line boundaries: `alignas(64) struct my_struct { ... };`.
  3. Use `memcpy` instead of direct pointer casting to copy unaligned bytes into aligned structures.

### B. Signed Integer Overflow
- **Error Pattern**: `runtime error: signed integer overflow: ...`
- **Root Cause**: Arithmetic addition, subtraction, or multiplication exceeding `INT64_MAX` or falling below `INT64_MIN`.
- **Diagnostic Recipe**:
  1. In C23, use `<stdckdint.h>` (`ckd_add`, `ckd_sub`, `ckd_mul`).
  2. In pre-C23, use `checked_add_i64` and `checked_mul_i64` from `cmaster/security_auditor.h`.
  3. Verify integer bounds before performing operations that could wrap.

---

## 3. ThreadSanitizer (TSan) Data Races

### A. Concurrent Read/Write Without Synchronization
- **Error Pattern**: `WARNING: ThreadSanitizer: data race ...`
- **Root Cause**: Two threads accessing the same memory location concurrently where at least one access is a write.
- **Diagnostic Recipe**:
  1. Replace plain variables with atomic types (`_Atomic uint64_t`).
  2. Use explicit memory orderings:
     - Producer writes data, then updates `head` with `atomic_store_explicit(&head, val, memory_order_release)`.
     - Consumer loads `head` with `atomic_load_explicit(&head, memory_order_acquire)`, then reads data.
  3. Ensure distinct thread variables are padded by 64 bytes (`alignas(64)`) to eliminate false sharing.

---

## 4. Compiler Warnings as Errors (`-Werror`)

### A. Implicit Conversion Warnings (`-Wconversion`)
- **Error Pattern**: `error: conversion from 'size_t' to 'uint32_t' may alter its value [-Werror=conversion]`
- **Diagnostic Recipe**:
  1. Verify the integer range can safely fit in the target type.
  2. Insert an explicit cast: `(uint32_t)size`.

### B. Missing Prototypes (`-Wmissing-prototypes`)
- **Error Pattern**: `error: no previous prototype for 'my_func' [-Werror=missing-prototypes]`
- **Diagnostic Recipe**:
  1. If `my_func` is internal to the translation unit, declare it `static`.
  2. If `my_func` is part of the public API, declare its prototype in the corresponding `.h` header.
