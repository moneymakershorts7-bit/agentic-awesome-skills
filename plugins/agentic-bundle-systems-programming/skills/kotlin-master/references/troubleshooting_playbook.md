# Troubleshooting & Self-Healing Playbook for `kotlin-master`

This runbook documents deterministic diagnostic recipes, failure patterns, root cause analysis, and corrective actions for the `kotlin-master` agent fleet.

---

## 1. Coroutine Concurrency & Flow Failures

### 1.1 Unconfined Coroutine Leaks (`GlobalScope.launch`)
- **Symptom:** Unbounded memory growth, uncancelled background coroutines surviving request lifecycles, non-deterministic test teardowns.
- **Root Cause:** Coroutines launched in `GlobalScope` or non-hierarchical scopes bypass structured concurrency lifecycles.
- **Diagnostic Recipe:**
  ```bash
  grep -rn "GlobalScope" src/
  ```
- **Corrective Action:**
  Replace with structured scopes injected via constructor or bound to component lifecycles:
  ```kotlin
  // Anti-pattern
  GlobalScope.launch { executeTask() }

  // Idiomatic Structured Concurrency
  class TaskCoordinator(
      private val scope: CoroutineScope,
      private val dispatcher: CoroutineDispatcher = Dispatchers.Default
  ) {
      fun start() = scope.launch(dispatcher) {
          executeTask()
      }
  }
  ```

### 1.2 Swallowed `CancellationException`
- **Symptom:** Coroutines fail to cancel when parent job is cancelled or timeout expires (`withTimeoutOrNull`).
- **Root Cause:** Catching `Exception` or `Throwable` without rethrowing `CancellationException`.
- **Diagnostic Recipe:**
  Look for `catch (e: Exception)` blocks around suspending invocations.
- **Corrective Action:**
  Always rethrow `CancellationException` or catch specific domain exceptions:
  ```kotlin
  try {
      suspendingNetworkCall()
  } catch (e: CancellationException) {
      throw e // Mandatory: propagate cancellation to parent job
  } catch (e: IOException) {
      logger.error(e) { "I/O error during network call" }
  }
  ```

### 1.3 Uncooperative CPU-Bound Loops
- **Symptom:** Cancellation signals are ignored during heavy mathematical or serialization computation.
- **Root Cause:** Suspending functions only cancel at suspension points; CPU loops without suspension points run to completion.
- **Corrective Action:**
  Inject `ensureActive()` or `yield()` inside iteration boundaries:
  ```kotlin
  for (item in massiveDataset) {
      coroutineContext.ensureActive() // Cooperatively check cancellation
      process(item)
  }
  ```

### 1.4 Flow Backpressure & Concurrency Bottlenecks
- **Symptom:** Fast emitter causes slow collector memory exhaustion or execution stall.
- **Corrective Action:**
  Apply explicit buffering, conflation, or debounce operators:
  ```kotlin
  upstreamFlow
      .buffer(capacity = 64, onBufferOverflow = BufferOverflow.SUSPEND)
      .flowOn(Dispatchers.IO)
      .collect { process(it) }
  ```

---

## 2. Konsist Architecture & Structural Invariants

### 2.1 Domain Layer Architectural Leakage
- **Symptom:** Konsist test fails: `classes in domain layer must not depend on infrastructure layer`.
- **Root Cause:** Domain model or business logic imported SQL/Database (Exposed, jOOQ), HTTP (Ktor, Spring), or external SDKs directly.
- **Diagnostic Command:**
  ```bash
  ./gradlew test --tests "*KonsistArchitectureTest*"
  ```
- **Corrective Action:**
  Invert dependency using Hexagonal/Ports-and-Adapters architecture: define repository interfaces in `domain` and implement them in `infrastructure`.

### 2.2 Missing `@JvmInline` on Value Classes
- **Symptom:** Konsist test flags domain ID types as plain classes or allocation overhead detected in heap profiling.
- **Root Cause:** Domain identifiers (e.g., `UserId`, `OrderId`) defined as standard data classes instantiate objects on the JVM heap.
- **Corrective Action:**
  ```kotlin
  @JvmInline
  public value class UserId(public val value: String) {
      init {
          require(value.isNotBlank()) { "UserId cannot be blank" }
      }
  }
  ```

---

## 3. K2 Compiler Strictness & Smart Cast Anomalies

### 3.1 Smart Cast Invalidation on Mutable / Open Properties
- **Symptom:** K2 compiler error: `Smart cast to 'X' is impossible, because 'y' is a mutable property that could have been changed by this time`.
- **Root Cause:** In multi-threaded environments, `var` properties or `open val` properties cannot be guaranteed immutable across read instructions.
- **Corrective Action:**
  Capture the mutable state into a local immutable `val`:
  ```kotlin
  val current = state
  if (current != null) {
      current.execute() // Smart cast succeeds deterministically
  }
  ```

### 3.2 Kotlin Contracts API for Custom Predicates
- **Symptom:** Custom validation helpers (`validateInput(x)`) do not smart cast `x` to non-null in calling scope.
- **Corrective Action:**
  Declare Kotlin Contracts:
  ```kotlin
  import kotlin.contracts.ExperimentalContracts
  import kotlin.contracts.contract

  @OptIn(ExperimentalContracts::class)
  public fun requireNotNullOrBlank(value: String?) {
      contract {
          returns() implies (value != null)
      }
      require(!value.isNullOrBlank()) { "Value must not be null or blank" }
  }
  ```

---

## 4. Detekt & Cyclomatic Complexity Discipline

### 4.1 Method Cyclomatic Complexity > 10
- **Symptom:** Detekt / Verifier QA flags: `CyclomaticComplexity: Method exceeds maximum complexity threshold of 10`.
- **Root Cause:** Deeply nested `when`, `if-else` cascades, and loops within a single method.
- **Corrective Action:**
  Decompose complex branches into private, single-responsibility helper or extension functions:
  ```kotlin
  // Before: CC = 14
  fun process(event: Event) { /* 14 branches */ }

  // After: CC <= 5 each
  fun process(event: Event) = when (event) {
      is UserEvent -> handleUserEvent(event)
      is OrderEvent -> handleOrderEvent(event)
      is SystemEvent -> handleSystemEvent(event)
  }
  ```

### 4.2 Wildcard Imports & Formatting Violations
- **Symptom:** `ktlint` or `detekt` fails on `NoWildcardImports`.
- **Corrective Action:**
  Configure IDE to never use wildcard imports (`import foo.bar.*`). Run formatter:
  ```bash
  ./gradlew ktlintFormat
  ```

---

## 5. Mutation Testing (Pitest) Deficiencies

### 5.1 Mutants Survived (MSI < 80%)
- **Symptom:** Pitest reports mutation score below 80% threshold.
- **Root Cause:** Unit tests assert happy paths but fail to assert boundary conditions (e.g. `<` vs `<=`, off-by-one, empty strings, null fallbacks).
- **Corrective Action:**
  1. Inspect the generated Pitest report: `build/reports/pitest/index.html`.
  2. Locate survived mutants (e.g., conditional boundary mutated to false).
  3. Write targeted Kotest property-based tests asserting edge and boundary values:
  ```kotlin
  "should reject invalid port numbers at exact boundaries" {
      forAll(Exhaustive.of(-1, 0, 65536, 70000)) { invalidPort ->
          shouldThrow<IllegalArgumentException> {
              ServerConfig(port = invalidPort)
          }
      }
  }
  ```

---

## 6. GraalVM Native Image & Project Loom Integration

### 6.1 Reflection Failures in Native Image
- **Symptom:** `ClassNotFoundException` or serialization runtime failure inside GraalVM native binary.
- **Root Cause:** Reflection used without explicit reachability metadata.
- **Corrective Action:**
  Use `kotlinx.serialization` (compiler-generated serializers without reflection) and declare runtime reflection configs:
  ```kotlin
  @Serializable
  public data class ServicePayload(val id: String, val timestamp: Long)
  ```

### 6.2 Loom Virtual Threads Coroutine Dispatcher
- **Symptom:** Thread pool starvation during high-concurrency blocking I/O calls.
- **Corrective Action:**
  Bridge Loom Virtual Threads as a structured `CoroutineDispatcher`:
  ```kotlin
  val LoomDispatcher: CoroutineDispatcher =
      Executors.newVirtualThreadPerTaskExecutor().asCoroutineDispatcher()

  // Use within coroutine context
  withContext(LoomDispatcher) {
      blockingIoCall()
  }
  ```
