# Playbook 06: Python Master Autonomous SecSDLC Quality Gate

This playbook details how to operationalize `python-master` as the official Python security, typing, and architectural assurance engine within the `devsecops-master` framework.

---

## 1. Overview & Architectural Role

`python-master` serves as the specialized Python SecSDLC engine within `devsecops-master`. It implements an Orchestrator-Worker architecture featuring 4 specialized developer agents and 1 independent QA/Security verification agent:

```
┌────────────────────────────────────────────────────────┐
│             Lead Orchestrator (Single Source of Truth) │
└───────────────────────────┬────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌───────────────────────────────┐     ┌───────────────────────────────┐
│  Bounded Worker Execution     │     │ Independent Verification Gate │
│  - Core Architect (DDD/Prot.) │     │ (Agent 5: QA & SecSDLC)       │
│  - Performance (Bytecode/Mem) │     │ - Ruff & Mypy Strict          │
│  - Security (Bandit & SCA)    │     │ - Bandit SAST & pip-audit     │
│  - Tooling (Ruff Refactor)    │     │ - Radon CC <= 10 & Vulture    │
└───────────────────────────────┘     └───────────────────────────────┘
```

---

## 2. Running the Python Master Quality Gate

Execute the bundled deterministic quality gate script:

```bash
python3 /path/to/devsecops-master/scripts/python_master_gate.py [target_dir]
```

### Automated Battery Checks:
1. **SAST Analysis:** `bandit -r src/` scans for high/medium severity CWE vulnerabilities.
2. **SCA Dependency Audit:** `pip-audit` cross-references installed dependencies against PyPI advisory databases.
3. **Strict Type Safety:** `mypy src/` enforces PEP 484/544 protocol contracts with zero un-typed definitions.
4. **AST Linting & Formatting:** `ruff check src/` and `ruff format --check src/`.
5. **Cyclomatic Complexity:** `radon cc src/ -s` enforces maximum complexity $\le 10$ across all functions.
6. **Dead Code Elimination:** `vulture src/` identifies orphaned methods and unused variables.

---

## 3. Integrating into CI/CD Pipelines

Add the gate as a blocking step in `.github/workflows/security-gate.yml`:

```yaml
      - name: Python Master SecSDLC Quality Gate
        run: |
          uv run python3 ~/.agents/skills/devsecops-master/scripts/python_master_gate.py . --format markdown
```

The gate returns exit code `0` on clean verification and exit code `1` if any critical blocker is encountered.

---

## 4. Self-Healing Closed Loop

When `python_master_gate.py` detects a failure, invoke the corresponding `python-master` agent to autonomously resolve it:
- **Lint/Formatting violations:** `uv run python -m python_master.cli run-agent tooling_refactorer .`
- **High Cyclomatic Complexity:** `uv run python -m python_master.cli run-agent core_architect .`
- **Vulnerabilities / Secrets:** `uv run python -m python_master.cli run-agent security_hardener .`
- **CPU / Bytecode inefficiencies:** `uv run python -m python_master.cli run-agent performance_optimizer .`
