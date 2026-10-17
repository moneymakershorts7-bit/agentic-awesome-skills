# Troubleshooting & Self-Healing Playbook

## 1. Thread-Pool Starvation & Sync-Over-Async Deadlocks
### Symptom
- Throughput drops to 0 requests/sec under high concurrent load.
- ThreadPool queue count increases exponentially while CPU usage remains low.
- Stack traces show threads blocked in `Task.Wait()`, `Task.Result`, or `Task.GetAwaiter().GetResult()`.

### Diagnostic Recipe
1. Execute `dotnet-counters monitor --counters System.Runtime --process-id <PID>` and observe `threadpool-queue-length` and `threadpool-thread-count`.
2. Inspect codebase with Roslyn analyzer rule or search:
   ```bash
   grep -rnE "\.(Result|Wait\(\)|GetAwaiter\(\)\.GetResult\(\))" src/
   ```
3. Refactor all blocking calls to asynchronous equivalents (`await ...`).
4. Append `.ConfigureAwait(false)` in class libraries.

---

## 2. Allocation Spikes and GC Latency in Hot Paths
### Symptom
- Frequent Gen 2 / LOH collections causing latency spikes (stop-the-world pauses).
- High memory churn reported by `dotnet-counters`.

### Diagnostic Recipe
1. Run a `BenchmarkDotNet` microbenchmark with `[MemoryDiagnoser]`:
   ```csharp
   [MemoryDiagnoser]
   public class HotPathBenchmark { ... }
   ```
2. Identify allocations: string concatenations (`+`), `string.Split()`, `string.Substring()`, LINQ closures, boxing of structs.
3. Apply Span-first refactoring:
   - Replace `string.Substring()` with `ReadOnlySpan<char>`.
   - Replace temporary buffers with `ArrayPool<byte>.Shared.Rent(size)`.
   - Use `stackalloc` for buffers < 1 KB.

---

## 3. Stryker.NET Mutation Testing Survivors
### Symptom
- Stryker mutation score falls below 80% threshold (`MutationScore < 80.0%`).
- Mutant survived on boundary condition checks (`<` vs `<=`, `==` vs `!=`).

### Diagnostic Recipe
1. Open Stryker HTML report:
   ```bash
   dotnet stryker --open-report
   ```
2. Locate the line with the surviving mutant.
3. Add targeted boundary tests:
   - Zero capacity boundary.
   - Buffer full / overflow boundary.
   - Null / empty collection boundary.
   - Cancellation token already cancelled before call.

---

## 4. Native AOT Trimming Breaks (ILLink Warnings)
### Symptom
- Build or publish fails with `IL2026` (`RequiresUnreferencedCode`) or `IL3050` (`RequiresDynamicCode`).
- Runtime `MissingMethodException` or `TypeInitializationException` in published AOT binary.

### Diagnostic Recipe
1. Run publish with trimming analysis:
   ```bash
   dotnet publish -c Release -r linux-x64 --self-contained /p:PublishAot=true
   ```
2. Replace dynamic reflection (`Type.GetType()`, `Activator.CreateInstance()`) with Roslyn compile-time source generation:
   - For JSON: `[JsonSerializable(typeof(TargetType))]`.
   - For Regex: `[GeneratedRegex("pattern")]`.
