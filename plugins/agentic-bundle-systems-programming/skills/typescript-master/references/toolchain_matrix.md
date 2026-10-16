# Exhaustive 38+ FOSS TypeScript Enterprise Toolchain Matrix

This reference documents the 47 canonical FOSS TypeScript tools integrated into `typescript-master` across 6 operational domains.

---

## Category 1: Type Checking & Compilers
1. **tsc** (Canonical TypeScript Compiler)
   - *Install*: `pnpm add -D typescript`
   - *Recipe*: `pnpm exec tsc --noEmit`
2. **tsdown** (Next-gen Fast Bundler & Declaration Generator)
   - *Install*: `pnpm add -D tsdown`
   - *Recipe*: `pnpm exec tsdown src/index.ts`
3. **oxc** (Rust-based JS/TS parser and toolchain)
   - *Install*: `pnpm add -D oxc-parser`
   - *Recipe*: `pnpm exec oxc src/`
4. **esbuild** (Extremely Fast Bundler in Go)
   - *Install*: `pnpm add -D esbuild`
   - *Recipe*: `pnpm exec esbuild src/index.ts --bundle --outfile=dist/bundle.js`
5. **swc** (Rust-based Platform for Compilation)
   - *Install*: `pnpm add -D @swc/core`
   - *Recipe*: `pnpm exec swc src -d dist`
6. **tsx** (Zero-Config TypeScript Executor)
   - *Install*: `pnpm add -D tsx`
   - *Recipe*: `pnpm exec tsx src/index.ts`
7. **ts-node** (TypeScript Execution Engine & REPL)
   - *Install*: `pnpm add -D ts-node`
   - *Recipe*: `pnpm exec ts-node --esm src/index.ts`
8. **jiti** (Runtime TypeScript & ESM support)
   - *Install*: `pnpm add -D jiti`
   - *Recipe*: `pnpm exec jiti src/index.ts`

---

## Category 2: Static Analysis, Linters & Formatters
9. **Biome** (Rust-based Fast Linter and Formatter)
   - *Install*: `pnpm add -D @biomejs/biome`
   - *Recipe*: `pnpm exec biome check src/`
10. **ESLint** (Configurable AST Linter)
   - *Install*: `pnpm add -D eslint`
   - *Recipe*: `pnpm exec eslint src/`
11. **@typescript-eslint** (Strict Type-Aware Linting)
   - *Install*: `pnpm add -D @typescript-eslint/eslint-plugin @typescript-eslint/parser`
   - *Recipe*: `pnpm exec eslint --rule '@typescript-eslint/strict-type-checked: error'`
12. **Prettier** (Deterministic Code Formatter)
   - *Install*: `pnpm add -D prettier`
   - *Recipe*: `pnpm exec prettier --check src/`
13. **Knip** (Unused Exports, Dead Code & Orphan Dependency Finder)
   - *Install*: `pnpm add -D knip`
   - *Recipe*: `pnpm exec knip`
14. **dependency-cruiser** (Module Dependency Graph and Cycle Detection)
   - *Install*: `pnpm add -D dependency-cruiser`
   - *Recipe*: `pnpm exec depcruise --validate src/`
15. **oxlint** (Fast Rust-based Linter)
   - *Install*: `pnpm add -D oxlint`
   - *Recipe*: `pnpm exec oxlint src/`
16. **publint** (Package.json & Exports Packaging Linter)
   - *Install*: `pnpm add -D publint`
   - *Recipe*: `pnpm exec publint`
17. **Are The Types Wrong? (attw)** (Declaration Resolution Auditor)
   - *Install*: `pnpm add -D @arethetypeswrong/cli`
   - *Recipe*: `pnpm exec attw --pack`
18. **ts-prune** (Unused Export Finder)
   - *Install*: `pnpm add -D ts-prune`
   - *Recipe*: `pnpm exec ts-prune`

---

## Category 3: Mutation, Property & Unit Testing
19. **Vitest** (Native ESM Unit and Integration Test Runner)
   - *Install*: `pnpm add -D vitest`
   - *Recipe*: `pnpm exec vitest run`
20. **Stryker Mutator** (Mutation Testing Platform for TS)
   - *Install*: `pnpm add -D @stryker-mutator/core @stryker-mutator/vitest-runner`
   - *Recipe*: `pnpm exec stryker run`
21. **fast-check** (Property-Based Generative Testing Framework)
   - *Install*: `pnpm add -D fast-check`
   - *Recipe*: `pnpm exec vitest run tests/properties/`
22. **Playwright** (Cross-Browser E2E Automation)
   - *Install*: `pnpm add -D @playwright/test`
   - *Recipe*: `pnpm exec playwright test`
23. **Supertest** (API Boundary HTTP Assertions)
   - *Install*: `pnpm add -D supertest @types/supertest`
   - *Recipe*: `pnpm exec vitest run tests/api/`
24. **c8** (V8-Powered Code Coverage)
   - *Install*: `pnpm add -D c8`
   - *Recipe*: `pnpm exec c8 vitest run`
25. **Istanbul / nyc** (JavaScript Test Coverage)
   - *Install*: `pnpm add -D nyc`
   - *Recipe*: `pnpm exec nyc vitest run`
26. **Jest** (Classic JS/TS Test Runner)
   - *Install*: `pnpm add -D jest ts-jest @types/jest`
   - *Recipe*: `pnpm exec jest`

---

## Category 4: Runtime Parsing & Validation
27. **Zod** (TypeScript-First Schema Validation)
   - *Install*: `pnpm add zod`
   - *Recipe*: `import { z } from 'zod';`
28. **Valibot** (Ultra-Lightweight Modular Schema Library)
   - *Install*: `pnpm add valibot`
   - *Recipe*: `import * as v from 'valibot';`
29. **ArkType** (1:1 TypeScript Runtime Validation)
   - *Install*: `pnpm add arktype`
   - *Recipe*: `import { type } from 'arktype';`
30. **ts-pattern** (Exhaustive Pattern Matching)
   - *Install*: `pnpm add ts-pattern`
   - *Recipe*: `import { match } from 'ts-pattern';`
31. **Typia** (Compiler-Generated Superfast Validation)
   - *Install*: `pnpm add typia`
   - *Recipe*: `import typia from 'typia';`
32. **Superstruct** (Composable Data Validation)
   - *Install*: `pnpm add superstruct`
   - *Recipe*: `import { assert, object, string } from 'superstruct';`
33. **TypeBox** (JSON Schema Type Builder with Static Inference)
   - *Install*: `pnpm add @sinclair/typebox`
   - *Recipe*: `import { Type } from '@sinclair/typebox';`

---

## Category 5: Security, Supply Chain & SecSDLC
34. **Socket.dev CLI** (Supply Chain Attack Detection)
   - *Install*: `pnpm add -D @socketsecurity/cli`
   - *Recipe*: `pnpm exec socket cdxgen`
35. **pnpm audit** (Advisory CVE Scanner)
   - *Install*: `Built-in to pnpm`
   - *Recipe*: `pnpm audit --audit-level=high`
36. **npm audit** (Vulnerability Scanner)
   - *Install*: `Built-in to npm`
   - *Recipe*: `npm audit --omit=dev`
37. **safe-regex2** (ReDoS Catastrophic Backtracking Detector)
   - *Install*: `pnpm add safe-regex2`
   - *Recipe*: `import safe = require('safe-regex2');`
38. **@cyclonedx/cyclonedx-npm** (CycloneDX SBOM Generator)
   - *Install*: `pnpm add -D @cyclonedx/cyclonedx-npm`
   - *Recipe*: `pnpm exec cyclonedx-npm --output-file bom.json`
39. **Trivy** (Container and Root Filesystem Scanner)
   - *Install*: `apt-get install trivy || brew install trivy`
   - *Recipe*: `trivy fs . --severity HIGH,CRITICAL`
40. **Gitleaks** (Secret and Credential Scanner)
   - *Install*: `brew install gitleaks`
   - *Recipe*: `gitleaks detect --source . --verbose`

---

## Category 6: Diagnostics, Memory & Profiling
41. **Clinic.js** (Doctor, Flame, Bubbleprof)
   - *Install*: `pnpm add -D clinic`
   - *Recipe*: `pnpm exec clinic doctor -- node dist/index.js`
42. **0x** (Single-Command Flamegraph Profiler)
   - *Install*: `pnpm add -D 0x`
   - *Recipe*: `pnpm exec 0x dist/index.js`
43. **v8-profiler-next** (CPU & Heap Profiling for V8)
   - *Install*: `pnpm add -D v8-profiler-next`
   - *Recipe*: `import v8Profiler from 'v8-profiler-next';`
44. **p-limit** (Concurrency Throttler)
   - *Install*: `pnpm add p-limit`
   - *Recipe*: `import pLimit from 'p-limit';`
45. **p-queue** (Priority Promise Queue)
   - *Install*: `pnpm add p-queue`
   - *Recipe*: `import PQueue from 'p-queue';`
46. **autocannon** (High-Throughput HTTP Benchmark)
   - *Install*: `pnpm add -D autocannon`
   - *Recipe*: `pnpm exec autocannon http://localhost:3000`
47. **heapdump** (V8 Heap Snapshot Dumper)
   - *Install*: `pnpm add -D heapdump`
   - *Recipe*: `import heapdump from 'heapdump';`
