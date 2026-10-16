# Troubleshooting & Self-Healing Playbook for Rust Agents

This playbook provides deterministic diagnosis and repair recipes for common Rust engineering failures encountered by agents.

---

## 1. Borrow Checker & Lifetime Failures

### Symptom: `E0502: cannot borrow *x as mutable because it is also borrowed as immutable`
- **Root Cause**: Scope of immutable reference overlaps with mutable borrow.
- **Diagnostic Recipe**: Inspect the AST with `rust-master audit-ast` or identify if the immutable reference is held across a method call that requires `&mut self`.
- **Self-Healing Action**:
  1. Restrict the lexical scope of the immutable borrow using explicit blocks `{ ... }`.
  2. Clone small values before mutation (`let cloned = val.clone();`).
  3. Decompose large structs into smaller, independent structs so distinct fields can be borrowed independently.

### Symptom: `E0499: cannot borrow *x as mutable more than once at a time`
- **Diagnostic Recipe**: Multiple concurrent mutable borrows in loops or closures.
- **Self-Healing Action**: Use iterator methods (`iter_mut()`, `chunks_mut()`, `split_at_mut()`) rather than manual indexing or overlapping references.

---

## 2. Unsafe Soundness & Miri Failures

### Symptom: `Stacked Borrows violation: trying to reborrow <tag> for SharedReadOnly, but tag is Unique`
- **Root Cause**: Creating a raw pointer from a `&mut`, then reading through the original reference while raw pointer is active.
- **Diagnostic Recipe**: Run `cargo miri test`. Ground in `knowledge_base/books_markdown/rust_nomicon/` via `rust-master search-corpus --query "stacked borrows raw pointers"`.
- **Self-Healing Action**: Use `std::ptr::addr_of!` / `std::ptr::addr_of_mut!` instead of converting references `&T as *const T` or `&mut T as *mut T`.

### Symptom: AST Audit Reject: `Missing // SAFETY: comment`
- **Root Cause**: `rust-master` enforces zero unannotated unsafe blocks or unsafe functions.
- **Self-Healing Action**: Prepend an explicit justification comment directly above the `unsafe` keyword:
  ```rust
  // SAFETY: The caller guarantees that `ptr` is non-null, properly aligned,
  // and points to an initialized instance of `T` valid for the lifetime 'a.
  unsafe { ... }
  ```

---

## 3. Performance & Layout Regressions

### Symptom: False Sharing / Cache Line Thrashing
- **Root Cause**: Multiple atomic variables accessed concurrently by different threads reside on the same 64-byte L1 cache line.
- **Diagnostic Recipe**: Check struct layout.
- **Self-Healing Action**: Align atomic counters to 64 bytes:
  ```rust
  #[repr(align(64))]
  pub struct PaddedAtomicU64(pub std::sync::atomic::AtomicU64);
  ```

### Symptom: Binary Size Monomorphization Bloat
- **Root Cause**: Heavy generic functions instantiated across dozens of concrete types.
- **Diagnostic Recipe**: Run `cargo llvm-lines` or `cargo bloat --release --crates`.
- **Self-Healing Action**: Apply the "Inner Function Pattern" (extract non-generic logic into a private non-generic helper that operates on type-erased pointers or slices).

---

## 4. Clippy Pedantic & Nursery Lints

### Symptom: `clippy::cast_precision_loss` / `clippy::cast_possible_truncation`
- **Root Cause**: Lossy numeric conversion using `as`.
- **Self-Healing Action**: Replace `as` with `TryFrom` / `TryInto`:
  ```rust
  let count: u32 = u32::try_from(len).map_err(|_| Error::Overflow)?;
  ```

### Symptom: `clippy::missing_errors_doc`
- **Root Cause**: Public function returning `Result` lacks an `# Errors` documentation section.
- **Self-Healing Action**: Add explicit `# Errors` markdown header documenting each failure mode.
