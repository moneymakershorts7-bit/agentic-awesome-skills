# Go Engineering Troubleshooting Playbook & Self-Healing Runbooks

This playbook details systematic diagnostic and self-healing recipes for the most common failure modes encountered in concurrent, high-throughput Go engineering.

---

## 1. Data Races (`DATA RACE`)

### Diagnostic Signature
```
WARNING: DATA RACE
Read at 0x00c00010a040 by goroutine 7:
  github.com/npirela/app.(*Pipeline).Consume()
      /path/to/pipeline.go:42 +0x64

Previous write at 0x00c00010a040 by goroutine 6:
  github.com/npirela/app.(*Pipeline).Produce()
      /path/to/pipeline.go:28 +0x88
```

### Root Cause Analysis
Two or more goroutines accessed the same memory location simultaneously without synchronization barriers, and at least one access was a write.

### Self-Healing Recipes
1. **Atomics**: For primitive counters, flags, or pointers, replace unsynchronized access with `sync/atomic` (e.g. `atomic.Int64`, `atomic.Pointer[T]`, `atomic.Bool`).
2. **Mutex Guarding**: Protect the shared struct fields using `sync.Mutex` or `sync.RWMutex`. In structs containing mutexes, always pass by pointer (`*T`) to prevent copying lock state.
3. **Channel Handoff**: Follow the Go proverb: *"Do not communicate by sharing memory; instead, share memory by communicating."* Pass ownership of data via channels.

---

## 2. Goroutine Leaks (`goleak: found lingering goroutine`)

### Diagnostic Signature
```
goleak: Errors on test teardown:
goroutine 18 [chan receive]:
github.com/npirela/app.workerPool.func1(0xc0000ba060)
    /path/to/worker.go:55 +0x8a
```

### Root Cause Analysis
A spawned goroutine is blocked indefinitely on a channel send, channel receive, or network I/O with no cancellation path.

### Self-Healing Recipes
1. **Context Cancellation Propagation**: Ensure the worker loop listens on `ctx.Done()`:
   ```go
   select {
   case <-ctx.Done():
       return
   case msg := <-ch:
       process(msg)
   }
   ```
2. **Buffered Channel for Senders**: If a sender goroutine produces a result for a receiver that might time out, use a buffered channel of size 1 so the sender can exit without blocking.
3. **Closing Channels**: Deterministically close input channels from the producer goroutine to signal EOF to consumers.

---

## 3. High GC Pressure & Excessive Heap Allocations

### Diagnostic Signature
High GC pause times reported by `GODEBUG=gctrace=1` or `go test -benchmem`:
```
BenchmarkProcess-8    100000    12400 ns/op    4820 B/op    42 allocs/op
```

### Root Cause Analysis
Excessive heap allocations in hot paths causing frequent garbage collection sweeps and pointer tracing overhead.

### Self-Healing Recipes
1. **Slice Preallocation**: Replace dynamic `append` in loops with `make([]T, 0, capacity)` when size is known or bounded.
2. **sync.Pool**: Pool and reuse frequently allocated buffers (`*bytes.Buffer`, `[]byte`). Always `Reset()` upon acquisition and bound the max capacity stored in the pool.
3. **Struct Padding Optimization**: Order struct fields from largest to smallest (8-byte pointers/ints -> 4-byte ints/floats -> 2-byte -> 1-byte bools) to eliminate alignment padding.
4. **Escape Analysis Inspection**: Run `go build -gcflags="-m"` to determine why variables escape to the heap (e.g. boxing into `interface{}` or returning addresses of local variables).

---

## 4. Nil Interface & Error Traps

### Diagnostic Signature
`if err != nil` evaluates to `true` even when the underlying concrete pointer is `nil`:
```go
var err *CustomError = nil
return err // Returns (*CustomError, nil) which is NOT equal to nil error!
```

### Self-Healing Recipe
Never assign a typed `nil` pointer to an `error` interface return value. Return explicit `nil`:
```go
if condition {
    return &CustomError{...}
}
return nil
```
