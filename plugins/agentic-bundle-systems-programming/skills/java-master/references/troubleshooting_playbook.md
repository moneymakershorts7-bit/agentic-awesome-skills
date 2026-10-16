# Troubleshooting & Diagnostic Playbook (`java-master`)

This playbook provides actionable diagnostic recipes and self-healing runbooks for common Java SE enterprise failure patterns.

---

## 1. Virtual Thread Carrier Pinning

### Pattern / Symptom
```
[CarrierPinned] Virtual thread #42 is pinned on carrier ForkJoinPool-1-worker-3
    at com.example.LegacyService.process(LegacyService.java:45) - inside synchronized
```

### Root Cause
A virtual thread executed a blocking operation (I/O, sleep, lock acquisition) while holding an intrinsic monitor lock (`synchronized` block or method), preventing the runtime from unmounting the virtual thread from its carrier OS thread.

### Diagnostic Recipe
1. Enable pinning tracing at startup:
   ```bash
   java -Djdk.tracePinnedThreads=full -jar app.jar
   ```
2. Take a thread dump with `jcmd`:
   ```bash
   jcmd <PID> Thread.dump_to_file -format=json threads.json
   ```

### Self-Healing Remedy
- Replace `synchronized` blocks with `java.util.concurrent.locks.ReentrantLock`:
  ```java
  // INCORRECT (Pins Carrier Thread):
  public synchronized void doWork() { blockingIo(); }

  // CORRECT (Carrier-Friendly Unmounting):
  private final ReentrantLock lock = new ReentrantLock();
  public void doWork() {
      lock.lock();
      try {
          blockingIo();
      } finally {
          lock.unlock();
      }
  }
  ```
- Avoid blocking calls inside native methods or JNI wrappers.

---

## 2. JFR Allocation Spikes & GC Pressure

### Pattern / Symptom
High allocation rate in young generation causing excessive minor GC cycles and latency degradation:
```
[GC] Pause Young (Normal) (G1 Evacuation Pause) 18.2ms
```

### Root Cause
Autoboxing primitive types (`int` -> `Integer`, `long` -> `Long`), inefficient record allocation in hot loops that fail escape analysis, or string concatenation inside loops.

### Diagnostic Recipe
1. Record allocation profiling with JFR:
   ```bash
   java -XX:StartFlightRecording=duration=30s,settings=profile,filename=alloc.jfr -jar app.jar
   ```
2. Inspect `jdk.ObjectAllocationInNewTLAB` and `jdk.ObjectAllocationOutsideTLAB` events using JMC or `jfr print`.

### Self-Healing Remedy
- Eliminate wrapper boxing on hot execution paths; use primitive arrays or Panama FFM `MemorySegment`.
- Pre-size collections (`new ArrayList<>(capacity)`) to avoid internal array resizing copies.
- Leverage compact record constructors and ensure allocations do not escape the local method scope to allow C2 JIT scalar replacement.

---

## 3. PIT Mutation Testing Survivors

### Pattern / Symptom
```
>> Generated 12 mutants Killed 8 (66%)
>> KILLED 8 SURVIVED 4
>> Mutation score: 66% (FAILED: threshold is 80%)
```

### Root Cause
Test suite exercises the code but lacks assertions on boundary conditions (e.g. `<= 0` mutated to `< 0`, or arithmetic operators negated).

### Diagnostic Recipe
1. Generate detailed Pitest HTML report:
   ```bash
   ./mvnw pitest:mutationCoverage
   ```
2. Open `target/pit-reports/index.html` and inspect the surviving mutant's line number and mutation operator (e.g., `negated conditional`, `replaced return value`).

### Self-Healing Remedy
- Add parameterized unit tests targeting boundary edge cases (`0`, `Long.MAX_VALUE`, `Double.NaN`, empty string, boundary limits).
- Use AssertJ fluent assertions to assert intermediate state rather than solely checking method return values.

---

## 4. NullAway Compile-Time AST Violations

### Pattern / Symptom
```
[NullAway] dereferenced expression order.items() is @Nullable
    List<Item> items = order.items();
    items.size(); // Compile error
```

### Root Cause
A method or record component return type is marked `@Nullable` (or unannotated in strict mode) and dereferenced without an explicit null check or optional unwrapping.

### Diagnostic Recipe
1. Run compilation with Error Prone & NullAway:
   ```bash
   ./mvnw compile -Xep:NullAway:ERROR
   ```

### Self-Healing Remedy
- Enforce compact constructors with `Objects.requireNonNull(arg, "name must not be null")`.
- Wrap optional results in `Optional<T>` return types rather than returning nulls.
- Annotate parameters and fields with `@NonNull` and `@Nullable` explicitly.
