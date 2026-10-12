# Playbook 03: Automated Test Pyramid Execution & CI Gating

This playbook guides the automated execution of test suites across every level of the test pyramid (Unit, Integration, Contract, E2E), capturing diagnostic artifacts and validating quality thresholds.

---

## Step 1: Pre-Execution Environment Sanitization

Before launching test suites:
1. Verify required environment variables are set (`NODE_ENV=test`, `DATABASE_URL=...`).
2. Ensure destination reports directory is clean and prepared for fresh artifacts.

---

## Step 2: Layered Execution Sequence

Execute tests in ascending order of feedback latency:

```
[Layer 1: Unit & Domain Tests]      (< 30 seconds) -> Immediate fail-fast
            │
            ▼ (Pass)
[Layer 2: Contract & API Tests]     (< 2 minutes)  -> Schema & boundary validation
            │
            ▼ (Pass)
[Layer 3: Integration & Component]  (< 4 minutes)  -> Real ephemeral databases
            │
            ▼ (Pass)
[Layer 4: Critical E2E User Journeys] (< 8 minutes) -> Headless browser automation
```

Run via the QA Orchestrator:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_orchestrator.py --run-all . --output-dir reports/qa/
```

---

## Step 3: Gating Threshold Evaluation

Verify that the run satisfies all gating invariants:
- **Pass Rate:** Must be 100% (zero unexpected failures).
- **Flaky Rate:** Must be 0% in gating suites.
- **Execution Latency:** Fast PR gate must complete in under 5 minutes.
- **Artifacts Attached:** If any test fails, ensure a stack trace, console log, or trace archive is generated.

---

## Step 4: Machine-Readable Reporting

Generate the standardized CI report:
```bash
python3 ~/.agents/skills/qa-master/scripts/qa_reporter.py --input reports/qa/qa_results.json --format markdown --output reports/qa/pr_comment.md
```
Attach `reports/qa/pr_comment.md` directly to GitHub/GitLab Pull Request discussions.
