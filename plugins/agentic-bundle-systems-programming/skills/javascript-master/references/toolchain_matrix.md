# Exhaustive 40+ FOSS JavaScript Toolchain Matrix

This document catalogs the 40 canonical open-source tools integrated into the `javascript-master` engineering platform, structured across 6 operational categories.

---

## 1. Static Analysis & Type Checking

| Tool | Purpose | Install Command | Canonical Invocation |
| :--- | :--- | :--- | :--- |
| **`tsc`** | JSDoc transpiler-free static type checking with zero code emit | `pnpm add -D typescript` | `tsc --noEmit --allowJs --checkJs` |
| **`biome`** | Ultra-fast Rust-based linter and formatter | `pnpm add -D @biomejs/biome` | `biome check src/` |
| **`eslint`** | Extensible AST-based ECMAScript pattern linter | `pnpm add -D eslint @eslint/js` | `eslint "src/**/*.js"` |
| **`knip`** | Unused files, dead code, orphan exports, and unlisted dependencies | `pnpm add -D knip` | `knip` |
| **`dependency-cruiser`** | Architectural boundary rules and circular import detector | `pnpm add -D dependency-cruiser` | `depcruise --validate .dependency-cruiser.cjs src/` |
| **`oxlint`** | Rust-based high-performance zero-configuration JavaScript linter | `pnpm add -D oxlint` | `oxlint` |

---

## 2. Mutation, Property & Unit Testing

| Tool | Purpose | Install Command | Canonical Invocation |
| :--- | :--- | :--- | :--- |
| **`node:test`** | High-performance native Node.js test runner | Built-in (Node.js 20+ / 22+ LTS) | `node --test "tests/**/*.test.js"` |
| **`vitest`** | Ultra-fast ESM-first unit and component test runner | `pnpm add -D vitest` | `vitest run` |
| **`stryker`** | Automated mutation testing to evaluate test suite resilience (MSI >= 80%) | `pnpm add -D @stryker-mutator/core` | `stryker run` |
| **`fast-check`** | Property-based generative testing framework discovering edge cases | `pnpm add -D fast-check` | `node -e "import fc from 'fast-check';"` |
| **`c8`** | Native V8 code coverage reporter without code instrumentation | `pnpm add -D c8` | `c8 node --test "tests/**/*.test.js"` |
| **`playwright`** | End-to-end browser automation and integration testing | `pnpm add -D @playwright/test` | `playwright test` |
| **`k6`** | Developer-centric load testing tool running JavaScript test scripts | `apt-get install -y k6 \|\| brew install k6` | `k6 run script.js` |
| **`artillery`** | Cloud-scale performance and functional API load testing | `pnpm add -D artillery` | `artillery run load-test.yml` |

---

## 3. Performance, Profiling & Memory Analysis

| Tool | Purpose | Install Command | Canonical Invocation |
| :--- | :--- | :--- | :--- |
| **`clinic`** | Diagnoses CPU bottlenecks, memory leaks, and event-loop lag | `pnpm add -D clinic` | `clinic doctor -- node src/index.js` |
| **`0x`** | Single-command interactive flamegraph profiler for Node.js | `pnpm add -D 0x` | `0x -- node src/index.js` |
| **`v8-profiler-next`** | Programmatic CPU and memory heap profiler for V8 engines | `pnpm add -D v8-profiler-next` | `node -e "import v8Prof from 'v8-profiler-next';"` |
| **`autocannon`** | High-speed HTTP/1.1 benchmarking tool in pure Node.js | `pnpm add -D autocannon` | `autocannon -c 100 -d 10 http://localhost:3000` |
| **`heapdump`** | Takes V8 heap snapshots on signal for Chrome DevTools analysis | `pnpm add -D heapdump` | `kill -USR2 <pid>` |
| **`benchmark.js`** | Robust statistical microbenchmarking suite for JavaScript | `pnpm add -D benchmark` | `node bench/suite.js` |
| **`node:perf_hooks`** | High-resolution performance measurement API in Node.js stdlib | Built-in (Node.js) | `node -e "import { performance } from 'node:perf_hooks';"` |

---

## 4. Security, Supply Chain & SecSDLC

| Tool | Purpose | Install Command | Canonical Invocation |
| :--- | :--- | :--- | :--- |
| **`socket`** | Detects supply-chain attacks, typosquatting, and malicious scripts | `pnpm add -D @socketsecurity/cli` | `socket cdi` |
| **`npm-audit`** | Official vulnerability audit against known CVE security advisories | Built-in (npm) | `npm audit --audit-level=high` |
| **`pnpm-audit`** | Scans pnpm lockfile for known security vulnerabilities | Built-in (pnpm) | `pnpm audit --audit-level=high` |
| **`safe-regex2`** | Detects catastrophic backtracking patterns in regular expressions (ReDoS) | `pnpm add -D safe-regex2` | `node -e "import safe from 'safe-regex2';"` |
| **`cyclonedx-npm`** | Generates standardized CycloneDX Software Bill of Materials (SBOM) | `pnpm add -D @cyclonedx/cyclonedx-npm` | `cyclonedx-npm --output-file bom.json` |
| **`trivy`** | Container and filesystem vulnerability scanner for SecSDLC gates | `apt-get install -y trivy \|\| brew install trivy` | `trivy fs .` |
| **`semgrep`** | Fast static analysis engine for code vulnerabilities | `pip install semgrep` | `semgrep scan --config auto` |
| **`gitleaks`** | Audits git repository and staging area for leaked secrets and API keys | `brew install gitleaks` | `gitleaks detect --no-git -v` |

---

## 5. Formatting & Code Cleanliness

| Tool | Purpose | Install Command | Canonical Invocation |
| :--- | :--- | :--- | :--- |
| **`prettier`** | Deterministic opinionated code formatter | `pnpm add -D prettier` | `prettier --check "src/**/*.js"` |
| **`oxc`** | High-speed Rust-based parser and tool suite for JavaScript | `pnpm add -D oxc-parser` | `oxc_lint` |
| **`sort-package-json`** | Enforces deterministic standard ordering of package.json keys | `pnpm add -D sort-package-json` | `sort-package-json --check` |
| **`publint`** | Verifies package.json exports, ESM/CJS compatibility, and entry points | `pnpm add -D publint` | `publint` |
| **`attw`** | Are The Types Wrong? Verifies TypeScript / JSDoc type compatibility | `pnpm add -D @arethetypeswrong/cli` | `attw --pack .` |
| **`size-limit`** | Performance budget and bundle size monitor for continuous delivery | `pnpm add -D size-limit` | `size-limit` |

---

## 6. Concurrency & Boundary Parsing

| Tool | Purpose | Install Command | Canonical Invocation |
| :--- | :--- | :--- | :--- |
| **`valibot`** | Modular, ultra-lightweight schema library for runtime boundary validation | `pnpm add valibot` | `node -e "import * as v from 'valibot';"` |
| **`zod`** | TypeScript-first runtime schema declaration and boundary parser | `pnpm add zod` | `node -e "import { z } from 'zod';"` |
| **`p-limit`** | Limits concurrency of asynchronous tasks to protect system resources | `pnpm add p-limit` | `node -e "import pLimit from 'p-limit';"` |
| **`p-retry`** | Exponential backoff and deterministic retry wrapper for network operations | `pnpm add p-retry` | `node -e "import pRetry from 'p-retry';"` |
| **`debug`** | Small debugging utility modeled on Node.js core debugging technique | `pnpm add debug` | `DEBUG=* node src/index.js` |
