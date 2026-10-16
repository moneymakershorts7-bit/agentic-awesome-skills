# TypeScript Master Troubleshooting & Diagnostic Playbook

This playbook provides actionable diagnostic recipes for recurring failure patterns across TypeScript compilation, V8 runtime execution, mutation testing, and security gates.

---

## 1. Type Inference Blowup & TS Server Hangs

### Symptoms
- `tsc` or `tsserver` consumes > 4GB of RAM and crashes with `FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory`.
- VSCode or IDE becomes unresponsive during type evaluation.

### Root Causes
- Deeply nested recursive conditional types or unconstrained template literal types generating exponential permutations.
- Massive intersection types (`A & B & C & ...`) with overlapping discriminant keys.

### Diagnostic & Remediation Recipe
1. Run `tsc --diagnostics --extendedDiagnostics` to inspect total type count and instantiate memory:
   ```bash
   pnpm exec tsc --extendedDiagnostics --noEmit
   ```
2. Identify slow files using `tsc --generateTrace traceDir`:
   ```bash
   pnpm exec tsc --generateTrace traceDir
   ```
3. Break recursive type expansions using tail-call optimization with depth accumulators:
   ```typescript
   // Anti-pattern: Exponential expansion
   type DeepTuple<T, N extends number> = ...;

   // Remediation: Depth accumulator limit
   type DeepTuple<T, N extends number, Acc extends unknown[] = []> =
     Acc["length"] extends N ? Acc : DeepTuple<T, N, [...Acc, T]>;
   ```
4. Replace complex intersection types with explicit interfaces.

---

## 2. V8 Hidden Class De-optimizations & Memory Leaks

### Symptoms
- Profiler flamegraphs show hotspot execution in `KeyedLoadIC_Megamorphic` or `KeyedStoreIC_Megamorphic`.
- Process memory grows continuously over time without leveling off.

### Root Causes
- Property initialization order divergence across object instances.
- Use of `delete obj.prop` which converts fast Shapes into slow dictionary mode (hash tables).
- Unbounded global caches or dangling EventEmitter listeners.

### Diagnostic & Remediation Recipe
1. Audit object instantiations to ensure identical key creation sequence:
   ```typescript
   // Anti-pattern:
   const o1 = {}; o1.a = 1; o1.b = 2;
   const o2 = {}; o2.b = 2; o2.a = 1; // Divergent Shapes!

   // Remediation:
   interface Schema { readonly a: number; readonly b: number; }
   function createObject(a: number, b: number): Schema {
     return { a, b }; // Monomorphic shape
   }
   ```
2. Replace `delete obj.key` with `obj.key = undefined` or construct a new clean object.
3. Clean up event listeners using `AbortSignal` with `{ signal }` or explicit `.removeListener()`.

---

## 3. Stryker Mutation Testing Survivors

### Symptoms
- Stryker Mutator score drops below the mandatory 80% threshold (`Mutation score < 80%`).
- Mutants survived in domain boundary logic or arithmetic operators (`+` mutated to `-`, `>` mutated to `>=`).

### Root Causes
- Unit tests only test "happy path" without testing boundary off-by-one conditions.
- Missing assertion on error conditions or state transitions.

### Diagnostic & Remediation Recipe
1. Inspect the Stryker HTML report:
   ```bash
   pnpm exec stryker run --mutate src/domain/Logic.ts
   ```
2. For boundary survivors (e.g. `availableTokens >= tokens`), introduce property-based generative testing with `fast-check`:
   ```typescript
   import fc from "fast-check";

   it("property: tokens cannot be negative", () => {
     fc.assert(
       fc.property(fc.integer({ min: 1, max: 100 }), (tokens) => {
         const limiter = new TokenBucketRateLimiter({ capacity: 10, refillRatePerSecond: 10 });
         return limiter.getAvailableTokens() >= 0;
       })
     );
   });
   ```

---

## 4. ReDoS (Catastrophic Backtracking) Alerts

### Symptoms
- `safe-regex2` or security linter flags a regex pattern as unsafe.
- Node.js event loop blocks for seconds on untrusted user strings.

### Root Causes
- Nested or overlapping quantifiers: `(a+)+`, `(a|aa)+`, `([a-zA-Z]+)*`.

### Diagnostic & Remediation Recipe
1. Test pattern against `safe-regex2`:
   ```typescript
   import safeRegex from "safe-regex2";
   if (!safeRegex(userPattern)) {
     throw new Error("Rejected potentially vulnerable regular expression");
   }
   ```
2. Rewrite with atomic grouping or possessive semantics, or enforce strict input length limits (`input.slice(0, 256)`).
3. Replace regex with string primitives (`includes`, `startsWith`, `indexOf`) wherever possible.

---

## 5. Native ESM & Module Resolution Pitfalls

### Symptoms
- `Error [ERR_MODULE_NOT_FOUND]: Cannot find module ... imported from ...`
- Bundler works, but Node.js runtime crashes on import.

### Root Causes
- Missing explicit `.js` extensions on relative imports in Native ESM (`"type": "module"`).
- TypeScript does not rewrite import specifiers during compilation.

### Diagnostic & Remediation Recipe
1. Always write explicit `.js` in relative imports even when authoring `.ts` source files:
   ```typescript
   // Correct in Native ESM:
   import { TaskContract } from "./types.js";
   ```
2. Run `api-engineer` audit:
   ```bash
   typescript-master orchestrate --goal "AUDIT-MODULES"
   ```
