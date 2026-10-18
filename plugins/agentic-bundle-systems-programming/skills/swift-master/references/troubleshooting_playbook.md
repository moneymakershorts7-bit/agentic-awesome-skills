# Swift 6 Systems Troubleshooting & Diagnostics Runbook

## 1. Swift 6 Data Race & Sendable Errors

### Error: `non-sendable type 'T' cannot be passed across actor boundary`
- **Root Cause**: An instance of type `T` is crossing an isolation domain (e.g., passed as an argument to an actor method or returned from a concurrent task), but `T` does not satisfy `Sendable`.
- **Diagnostic Recipe**:
  1. Inspect whether `T` has value semantics (struct or enum with `Sendable` stored properties). If yes, declare `struct T: Sendable`.
  2. If `T` is a class, determine whether mutable state is strictly necessary. If immutable, mark `final class T: Sendable` and declare all stored properties `let`.
  3. If mutable state is required across threads, wrap state inside an `actor` or synchronize using `OSAllocatedUnfairLock`.
  4. Never apply `@unchecked Sendable` unless encapsulating an audited OS lock primitive.

### Error: `mutation of captured var in concurrently-executing code`
- **Root Cause**: A closure executing in a concurrent task or detached block is mutating a local `var` belonging to the enclosing function scope.
- **Diagnostic Recipe**:
  1. Refactor the mutation into a return value accumulated through `withTaskGroup`.
  2. If state must be updated asynchronously, isolate the state in an actor and call an asynchronous mutating method on the actor.

---

## 2. Actor Reentrancy Corruption

### Warning: `actor-isolated property mutated after await`
- **Root Cause**: In Swift, actors suspend at `await` calls. Between the suspension and resumption, other tasks can interleave messages that modify actor state. Assumptions checked before `await` may no longer hold after resumption.
- **Diagnostic Recipe**:
  1. Re-validate all state preconditions immediately after the `await` resumption point:
     ```swift
     let result = try await externalService.fetch()
     // Re-check invariants:
     guard self.activeTasks < MAX_TASKS else { throw ReentrancyError.capacityExceeded }
     self.store(result)
     ```
  2. Ensure multi-step state mutations are atomic: either stage them in local immutable values before the `await`, or wrap multi-step transactions in an internal transaction lock.

---

## 3. ThreadSanitizer (TSan) Runtime Detections

### Finding: `WARNING: ThreadSanitizer: data race ... Write of size 8 at 0x... by thread T2:`
- **Root Cause**: Two threads accessed the same memory location concurrently, and at least one access was a write, without synchronization.
- **Diagnostic Recipe**:
  1. Check if an `@unchecked Sendable` class was used. Verify its internal locking mechanism.
  2. If using POSIX threads or C interoperability, ensure all access to shared pointers is guarded by `os_unfair_lock` or wrapped in `SynchronizedState<T>`.
  3. Ensure `swift test --sanitize=thread` returns 0 data races.

---

## 4. Noncopyable Types (`~Copyable`) Lifetimes

### Error: `cannot use 'resource' after consuming call`
- **Root Cause**: A function or method annotated with `consuming` took ownership of a noncopyable type instance, invalidating subsequent uses in the caller.
- **Diagnostic Recipe**:
  1. If the caller needs continued access to the resource, change the method signature from `consuming` to `borrowing`.
  2. If consumption was intentional (e.g., `close()` or `commit()`), ensure all access to the resource precedes the consuming call.
  3. Noncopyable types must not be stored in standard `Array` or collection types unless the collection itself supports `~Copyable` element types.
