# Troubleshooting Playbook: Self-Healing Runbooks

This playbook provides diagnostic recipes and automated resolution procedures for common enterprise JavaScript runtime, security, and verification failure modes.

---

## 1. Prototype Pollution Traps

### Symptom
- Linter, test, or security auditor flags untrusted dictionary property assignment or recursive merge processing `__proto__` or `constructor`.
- State contamination across unrelated object instances.

### Root Cause
Unvalidated bracket notation `target[key] = val` or recursive merge on plain JavaScript objects inheriting from `Object.prototype`.

### Diagnostic Recipe
1. Replace plain object `{}` dictionaries with null-prototype maps:
   ```javascript
   const safeMap = Object.create(null);
   ```
2. If keys originate from untrusted external sources (JSON request bodies, URL query parameters), use ES6 `Map`:
   ```javascript
   const safeRegistry = new Map();
   ```
3. Use `safeMerge()` from `@agents/security-auditor` which explicitly rejects `__proto__`, `constructor`, and `prototype` keys.
4. Call `Object.freeze(Object.prototype)` during application initialization.

---

## 2. Event-Loop Starvation & Latency Spikes

### Symptom
- Clinic.js or 0x profiles show high event loop delay (`el_delay > 50ms`).
- Inbound HTTP requests or timers experience unbounded queuing latency.

### Root Cause
Synchronous CPU-intensive computation (large JSON parsing, heavy cryptographic algorithms, recursive graph search, compression) running on the primary event loop thread.

### Diagnostic Recipe
1. Profile call sites using `node --prof` and generate flamegraph with `0x`:
   ```bash
   0x -- node src/index.js
   ```
2. Delegate synchronous CPU-heavy work to `node:worker_threads`:
   ```javascript
   import { Worker } from 'node:worker_threads';
   const worker = new Worker(new URL('./computeWorker.js', import.meta.url));
   worker.postMessage({ chunk });
   ```
3. If chunking a large array on the main thread, yield execution to the event loop between iterations:
   ```javascript
   await new Promise((resolve) => setImmediate(resolve));
   ```

---

## 3. Stryker Mutation Survivors

### Symptom
- Stryker Mutator reports Mutation Score Indicator (MSI) < 80%:
  `Mutation testing score: 74.2% (below threshold of 80.0%)`
  `Mutant survived: EqualityOperator replacement (=== to !==) in validateTimeout()`

### Root Cause
Unit tests rely on "happy path" assertions without testing boundary values (e.g. `0`, `-1`, `Number.MAX_SAFE_INTEGER`, empty strings, null).

### Diagnostic Recipe
1. Identify the surviving mutant location from `reports/mutation/mutation.html` or terminal logs.
2. Formulate generative property-based tests using `fast-check` to test the entire domain boundary:
   ```javascript
   import fc from 'fast-check';
   test('property: timeout must reject non-positive integers', () => {
     fc.assert(
       fc.property(fc.integer({ max: 0 }), (invalidTimeout) => {
         assert.throws(() => new CircuitBreaker({ timeout: invalidTimeout }));
       })
     );
   });
   ```
3. Re-execute Stryker targeting the specific file:
   ```bash
   pnpm exec stryker run --mutate lib/resilience/CircuitBreaker.js
   ```

---

## 4. V8 Shape Polymorphism & De-optimization Bailouts

### Symptom
- High execution time in tight loops; V8 trace shows `deopt: shape mismatch` or `IC megamorphic`.

### Root Cause
Properties added dynamically to class instances outside the constructor or in different orders across instantiation call sites.

### Diagnostic Recipe
1. Inspect constructor functions to ensure all instance properties are declared and initialized in identical order:
   ```javascript
   // Correct monomorphic pattern:
   class SocketConnection {
     constructor(host, port) {
       this.host = host;
       this.port = port;
       this.connected = false;
       this.lastError = null; // Declare early even if null
     }
   }
   ```
2. Ban `delete obj.prop` which transitions objects into slow dictionary mode; set `obj.prop = null` or use `Map.delete()` instead.
3. Keep argument types consistent at hot function call sites to maintain Monomorphic Inline Caches.

---

## 5. JSDoc Static Typing Mismatches (`tsc --checkJs`)

### Symptom
- `tsc --noEmit --allowJs --checkJs` reports errors:
  `TS2322: Type 'string' is not assignable to type 'number'`

### Root Cause
Implicit `any` in function signatures or untyped callback parameters.

### Diagnostic Recipe
1. Annotate all exported parameters, return values, and typedefs with full JSDoc syntax:
   ```javascript
   /**
    * @param {string} endpoint
    * @param {Object} [options]
    * @param {AbortSignal} [options.signal]
    * @returns {Promise<ResponseEnvelope>}
    */
   ```
2. For object dictionaries with variable keys, declare `@typedef` or `Record<string, unknown>`.
3. Use `@template T` for generic higher-order functions.
