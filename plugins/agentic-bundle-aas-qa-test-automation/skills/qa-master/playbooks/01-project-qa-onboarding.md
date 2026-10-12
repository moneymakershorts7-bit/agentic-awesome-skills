# Playbook 01: Project QA Onboarding & Stack Detection

This playbook guides the QA agent to inspect an unfamiliar codebase, detect all installed testing frameworks, uncover untested surfaces, and establish an automated testing baseline.

---

## Step 1: Automatic Stack & Framework Detection

Run the QA Orchestrator detection command:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_orchestrator.py --detect-only .
```

The orchestrator examines project descriptors:
- **Node/TS:** `package.json` for test runners (`vitest`, `jest`, `@playwright/test`, `cypress`, `mocha`, `ava`, `supertest`, `pactum`)
- **Python:** `pyproject.toml`, `setup.cfg`, `pytest.ini`, test directories (`tests/`, `test_*.py`)
- **Go:** `go.mod`, `*_test.go`
- **Rust:** `Cargo.toml`, `tests/`

---

## Step 2: Generate Heuristic Test Plan

Run the test plan generator:
```bash
python3 ~/.agents/skills/qa-master/scripts/generate_test_plan.py --repo . --output qa_test_plan.json
```

This inspects the codebase architecture and produces:
1. **SFDIPOT Structure:** Core components, APIs, and business modules.
2. **Missing Test Layers:** Identifies whether unit, integration, or E2E tests are absent.
3. **High-Risk Surfaces:** Identifies complex files with high cyclomatic complexity or frequent recent git edits.
4. **Tailored Exploratory Charters:** Ready-to-execute charters for manual/exploratory testing.

---

## Step 3: Establish Baseline Execution

Execute existing test suites to establish the green baseline:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_orchestrator.py --run-all . --output-dir reports/qa/
```

Verify the baseline verdict:
- If `PASSED`: Baseline established. Record test count and execution duration in working memory.
- If `FAILED`: Do not start writing new features yet. Isolate failing tests and resolve regression before proceeding.
