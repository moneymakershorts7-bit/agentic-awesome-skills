# Playbook 04: Flaky Test Quarantine, Detection, and Triage

Flaky tests (tests that pass and fail intermittently without code changes) undermine developer trust in CI pipelines.

---

## Step 1: Flake Detection & Variance Profiling

When profiling test stability, measure execution variance across iterations:
```bash
python3 ~/.agents/skills/qa-master/scripts/flaky_detector.py --cmd "<test-command>" --runs 10
```

The script runs the target test command $N$ times and computes:
- **Flake Rate:** $\frac{\text{Passed Runs} \times \text{Failed Runs}}{N^2} > 0$
- **Variance / StdDev of Duration:** Detects tests waiting on uncontrolled network delays or timeouts.

---

## Step 2: Immediate Quarantine Policy

Per **El Décimo Hombre** directives:
- If a test exhibits a flake rate $> 0\%$, it MUST NOT block production deployments.
- Quarantine the test immediately:
  - In Playwright: Move to `@quarantine` tag (`test('...', { tag: '@quarantine' })`).
  - In Pytest: Mark with `@pytest.mark.quarantine`.
  - In Jest/Vitest: Move to `tests/quarantine/`.
- Quarantined tests run in an asynchronous diagnostic pipeline, alerting maintainers without blocking CI PR merges.

---

## Step 3: Root Cause Triage Guide

Investigate using the 4 canonical flake root causes:

1. **Uncontrolled Clocks / Time:**
   - *Smell:* Tests relying on `Date.now()`, `datetime.utcnow()`, or comparing timestamps with strict equality.
   - *Fix:* Use fake timers (`jest.useFakeTimers()`, `timecop`, `freezegun`).
2. **Race Conditions / Arbitrary Sleep:**
   - *Smell:* Code contains `time.sleep(2)` or `await page.waitForTimeout(3000)`.
   - *Fix:* Replace sleeps with deterministic predicate polling (`page.waitForSelector()`, `await expect(...).toBeVisible()`).
3. **Shared State Pollution:**
   - *Smell:* Test fails when run in isolation or when tests run in parallel.
   - *Fix:* Ensure tests run within fresh database transactions that roll back on completion, or use distinct user IDs per test run.
4. **Order Dependency:**
   - *Smell:* Test passes in sequence, fails when test suite is randomized.
   - *Fix:* Randomize test execution order locally (`pytest --random-order`, `vitest --sequence.shuffle`) to catch and eliminate leaked state.
