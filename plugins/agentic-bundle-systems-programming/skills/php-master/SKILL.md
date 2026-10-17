---
name: php-master
description: Autonomous enterprise PHP engineering platform and agent orchestrator specialized in modern high-performance PHP (PHP 8.3+ / PHP 8.4+), 4 domain enterprise workers, and 1 independent adversarial verification agent.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# php-master: Enterprise-Grade Autonomous PHP Engineering Platform

`php-master` is an autonomous enterprise PHP engineering platform and agent orchestrator specialized in modern, production-hardened PHP (PHP 8.3+ / PHP 8.4+). Built upon the **Frontier Orchestrator-Worker Standard**, it rejects both the Monolithic God-Agent and the Chatty Role-Playing Committee anti-patterns.

---

## 1. Architectural Foundations

The platform enforces a decoupled Orchestrator-Worker state machine in idiomatic, pure PHP:
- **Lead Orchestrator**: Manages Bounded Functional Slicing (atomic, decoupled work units with zero monolithic PRs), Task + Playbook Contract generation with self-healing runbooks, offline corpus ingestion with BM25/TF-IDF search, and 30-day documentation freshness cadence.
- **State Machine**:
  `DISPATCHED` ──► `RUNNING` ──► `VERIFYING` ──► (`COMPLETED` | `FAILED_HEALING_LOOP`)
- **Self-Healing Runbooks**: In case of verification failure, the orchestrator pattern-matches failure traces against the contract's `known_failure_modes`, applies diagnostic recipes, and re-executes tests before committing changes.

For full contract specifications and JSON schemas, see [Agent Contracts Reference](file:///home/npirela/.agents/skills/php-master/references/agent_contracts.md).

---

## 2. The 5 Specialized PHP Enterprise Agents

### Agent 1: Type-Level Architecture & Domain Modeler (`domain-architect`)
- **Domain**: Modern PHP 8.3/8.4 type system, strict typing, Domain-Driven Design (DDD), and rich object modeling.
- **Invariants**:
  - Mandatory Strict Types: Every file begins with `declare(strict_types=1);` as the first statement.
  - Immutability First: Mandate `readonly` classes, readonly properties, and constructor property promotion for all Value Objects and Domain Events.
  - PHP 8.4 Modernity: Asymmetric visibility (`public private(set)`), property hooks (`get`/`set`), and Disjunctive Normal Form (DNF) types `(A&B)|C`.
  - Type-Safe Enums: Replace magic strings/constants with backed Enums implementing custom business methods.
  - Ban Primitive Obsession: Wrap raw integers/strings into strongly-typed Value Objects with self-contained boundary validation.

### Agent 2: High-Performance, Workers & Runtime Optimizer (`runtime-optimizer`)
- **Domain**: Long-running process execution (FrankenPHP, RoadRunner, Swoole), OPcache & JIT tuning, and memory leak eradication.
- **Invariants**:
  - Worker Mode State Isolation: Zero static variable accumulation; stateless worker loops.
  - Memory Leak Prevention: Explicit circular reference decoupling, listener detachment, and Doctrine ORM `$em->clear()` between cycles.
  - Generator-First Streaming: `Generator` (`yield`) for high-volume files and database iterations preserving $O(1)$ memory.
  - OPcache Preloading: Preloading-compliant code without dynamic class loading or `eval()`.

### Agent 3: PSR, Clean APIs & Systems Engineer (`api-engineer`)
- **Domain**: PHP-FIG PSR standards, Hexagonal Architecture (Ports and Adapters), and modular API design.
- **Invariants**:
  - Full PSR Compliance: PSR-4 (Autoloading), PSR-7 (HTTP messages), PSR-11 (Container), PSR-14 (Event Dispatcher), PSR-15 (Middleware), PSR-18 (HTTP Client).
  - Port & Adapter Isolation: Zero framework or persistence dependencies in the Domain layer.
  - Deptrac Layer Enforcement: Architectural assertions guaranteeing the domain layer never references infrastructure.
  - Resilient HTTP Contracts: Middleware pipelines enforcing timeouts, structured error envelopes, and idempotency.

### Agent 4: Security, SecSDLC & Cryptographic Auditor (`security-auditor`)
- **Domain**: Web application security, cryptographic hygiene, supply chain verification, and rootless containerization.
- **Invariants**:
  - Deserialization Defense: Strict prohibition of native `unserialize()`; mandate `json_decode(..., true, 512, JSON_THROW_ON_ERROR)`.
  - SQL Injection Eradication: 100% parameter-bound PDO statements; zero string interpolation.
  - Modern Cryptography: `sodium_crypto_*` (libsodium) for encryption; Argon2id (`PASSWORD_ARGON2ID`) for password hashing.
  - Supply Chain & Container Hardening: `composer audit`, locked deterministic trees, and rootless container execution (`USER www-data`).

### Agent 5: Independent Adversarial Verification Agent (`verifier-qa`)
- **Domain**: Independent verification gate with unconditional veto power over all code integrations.
- **Invariants**:
  - Static Analysis Gate: PHPStan Level Max/9 with 0 errors; Psalm Level 1 with `--taint-analysis`.
  - Mutation Testing Gate: Infection PHP MSI >= 80% on all domain algorithms.
  - Test Suite Gate: Pest / PHPUnit 11 with 100% passing tests and zero untested assertions.
  - Style Gate: PHP-CS-Fixer passing cleanly against PER-CS 2.0 / PSR-12.

For diagnostics and troubleshooting recipes, see [Troubleshooting Playbook](file:///home/npirela/.agents/skills/php-master/references/troubleshooting_playbook.md).

---

## 3. Authoritative Literature Corpus (Zero Hallucination Grounding)

The platform features an offline, line-accurate corpus indexed with BM25/TF-IDF search in `knowledge_base/books_markdown/`:
1. `php_manual.md`: The Official PHP 8.4 Language Reference & Manual
2. `php_fig_psr.md`: PHP-FIG Standards (PSR-1, 4, 7, 11, 12, 14, 15, 18, PER-CS 2.0)
3. `ddd_in_php.md`: Domain-Driven Design with Modern PHP
4. `clean_php_architecture.md`: Object Design Style Guide & Clean Architecture in PHP
5. `owasp_php_security.md`: OWASP PHP Security & Secure Coding Guide
6. `high_perf_php.md`: High Performance PHP: Worker Engines (RoadRunner, FrankenPHP, Swoole)
7. `php_the_right_way.md`: PHP The Right Way (Modern Production Guide)

Search command:
```bash
python3 scripts/php_master_cli.py search-corpus --query "<keyword>"
```

---

## 4. 38+ FOSS PHP Enterprise Toolchain Matrix

The platform integrates and auto-detects canonical FOSS PHP ecosystem tools across 6 operational categories:
1. **Static Analysis & Linters**: PHPStan, Psalm, Rector, PHP_CodeSniffer, PHP-CS-Fixer, PHPMD, Phan.
2. **Architecture & Structural Governance**: Deptrac, phpat, Arkitect, PhpMetrics, phpda.
3. **Mutation, Unit & Property Testing**: Infection PHP, Pest PHP, PHPUnit 11, Mockery, Eris / QuickCheck, FakerPHP, ParaTest, Kahlan.
4. **Performance, Profiling & Worker Runtimes**: FrankenPHP, RoadRunner, Swoole, Blackfire CLI, Tideways CLI, phpbench, SPX Profiler.
5. **Security, Supply Chain & SecSDLC**: composer audit, local-php-security-checker, Roave/SecurityAdvisories, CycloneDX PHP Composer Plugin, Trivy, Enlightn.
6. **Dependency & Workspace Hygiene**: composer-normalize, composer-unused, parallel-lint, PHP Insights, composer-require-checker, CaptainHook.

For full installation and invocation recipes, see [Toolchain Matrix Reference](file:///home/npirela/.agents/skills/php-master/references/toolchain_matrix.md).

---

## 5. 30-Day Documentation Freshness Cadence

- State manifest: `.docs_manifest.json` tracking document SHA-256 signatures and expiration dates.
- Verification CLI: `python3 scripts/php_master_cli.py check-docs-cadence`.
- Refresh CLI: `python3 scripts/php_master_cli.py update-docs --force`.
- Automated CI: `.github/workflows/docs-cadence.yml` running on cron `0 0 1 * *`.

---

## 6. Helper CLI Commands

```bash
# Search authoritative corpus
python3 scripts/php_master_cli.py search-corpus --query "<keyword>"

# Check 30-day documentation freshness cadence
python3 scripts/php_master_cli.py check-docs-cadence

# Update documentation timestamps and manifest
python3 scripts/php_master_cli.py update-docs --force

# Decompose goal into atomic Task + Playbook contracts
python3 scripts/php_master_cli.py decompose-task --goal "<goal>"

# Execute contract with Orchestrator FSM and self-healing runbook
python3 scripts/php_master_cli.py execute-contract --file <contract.json>

# Audit toolchain matrix
python3 scripts/php_master_cli.py audit-toolchain

# Run DevSecOps SecSDLC gate
python3 scripts/php_master_cli.py run-gate
```
