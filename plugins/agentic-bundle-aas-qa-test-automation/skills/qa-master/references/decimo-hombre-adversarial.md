# El Décimo Hombre: Adversarial QA Stress-Testing & Ipcha Mistabra

The Tenth Man operates under the **Ipcha Mistabra** ("the opposite appears to be true") mandate:
When engineering teams agree that "the test suite is green and comprehensive," the Tenth Man assumes the team is suffering from testing illusions and uncovers hidden catastrophic failure modes.

---

## 1. The 5 False Consensus Traps in QA Engineering

```
┌────────────────────────────────────────────────────────────────────────┐
│                        THE 5 FALSE QA ILLUSIONS                        │
├──────────────────────────┬─────────────────────────────────────────────┤
│ 1. Flaky Desensitization │ Rerunning failing CI until it passes green   │
│ 2. Mock Drift Illusion   │ 100% green mocks while real API is broken   │
│ 3. Hollow Coverage       │ 95% line coverage with zero assertions      │
│ 4. Test Duration Wall    │ 45-minute CI suites destroying local tests  │
│ 5. State Pollution       │ Tests passing only in deterministic order   │
└──────────────────────────┴─────────────────────────────────────────────┘
```

### Trap 1: Flaky Test Desensitization
- **The Illusion:** "Test X fails occasionally because of network latency or runner load. Just retry it in CI."
- **The Reality:** Auto-retrying tests hides real intermittent concurrency races and memory leaks. Developers lose trust in CI and begin merging PRs despite test failures ("it's probably just flaky"). Real production outages slip through under the cover of flakes.
- **Tenth Man Directive:** Zero tolerance for unquarantined flakes. Any test exhibiting $> 0\%$ flaky variance over 5 runs MUST be quarantined immediately into a dedicated quarantine suite, blocked from gating PRs until root-caused.

### Trap 2: Mock Drift & False Greens
- **The Illusion:** "We mocked all database repositories and external HTTP services, so our tests run in 2 seconds and are 100% green."
- **The Reality:** The mocked interfaces drift away from production schemas (e.g. database column renamed, third-party API changes error status code from 400 to 422). The mocks return successful canned responses while production crashes on launch.
- **Tenth Man Directive:** Enforce Consumer-Driven Contract Testing (Pact) or Ephemeral Real Containers (Testcontainers) for all external boundaries. Domain logic must be tested with real instances, not mocks.

### Trap 3: Hollow Coverage (Execution without Assertion)
- **The Illusion:** "Our SonarQube / Jest dashboard shows 92% statement coverage. We are safe to deploy."
- **The Reality:** Lines are executed, but few invariants or states are asserted. When code logic is inverted or mutated, 60% of tests still pass.
- **Tenth Man Directive:** Validate assertion quality with Mutation Testing (Mutation Score Index $\ge 75\%$). A high-coverage file with low mutation score indicates assertion theater.

### Trap 4: The Test Duration Wall
- **The Illusion:** "We added 200 comprehensive browser end-to-end tests covering every possible user scenario."
- **The Reality:** The CI pipeline now takes 45 minutes to run. Developers stop testing locally, batch massive changes into single PRs to avoid pipeline waiting, and context switching skyrockets.
- **Tenth Man Directive:** The **5-Minute PR Rule**. Branch PR test gates must complete within 5 minutes using test pyramid pruning, parallel sharding, and shifting heavyweight visual/performance tests to post-merge or nightly cadences.

### Trap 5: Test Interdependence & State Leakage
- **The Illusion:** "The entire suite passes when run sequentially via `npm test`."
- **The Reality:** Test B depends on database rows inserted by Test A. When tests are executed in random order or sharded across parallel worker nodes, tests fail sporadically.
- **Tenth Man Directive:** Mandate randomized test execution order (`--randomize` / `--shuffle`) and clean fixture isolation (fresh database schema or transactions rolled back after each test).

---

## 2. Simulated Pre-Execution After Action Report (Pre-AAR)

### Scenario: The "100% Green" Production Outage
- **1. What was supposed to happen?**
  A critical e-commerce checkout release was deployed after all 450 unit and integration tests passed with 94% coverage in CI.
- **2. What disastrously happened instead?**
  Within 10 minutes of release, 100% of mobile checkout attempts failed with payment processing errors. Total business loss was \$140,000 before rollback.
- **3. Why was there a variance? (5-Whys Root Cause):**
  - *Why 1?* The Stripe payment SDK failed to mount on mobile screens.
  - *Why 2?* A CSP nonce was omitted on the newly styled mobile payment modal.
  - *Why 3?* The automated tests did not run in a mobile viewport with CSP headers enabled.
  - *Why 4?* All mobile tests mocked the Stripe window object instead of running real browser rendering.
  - *Why 5?* The team had prioritized test speed and mock coverage over real observable behavior testing.
- **4. What must be re-engineered now?**
  1. Add a Playwright mobile webkit test running with strict CSP headers enabled.
  2. Implement an exploratory testing charter specifically validating third-party SDK lifecycles.
  3. Prohibit mocking third-party visual SDKs in E2E browser tests.

---

## 3. Non-Negotiable Hardening Directives & Kill Criteria

| Indicator | Kill Trigger Threshold | Required Immediate Action |
| :--- | :--- | :--- |
| **Flaky Test Rate** | $\ge 2\%$ of runs in main branch | Immediate automatic quarantine of flaking spec to separate suite. |
| **Branch Test Latency** | $> 8$ minutes on PR checks | Parallelize workers or prune E2E tests down to core smoke journeys. |
| **Mutation Score Index** | $< 70\%$ on critical domain modules | Block PR until missing assertions are added to kill surviving mutants. |
| **Accessibility Severity**| $\ge 1$ Critical/Serious WCAG violation | Block PR merge immediately. |
| **Performance Degradation**| p95 latency regressed by $> 25\%$ | Fail CI performance quality gate; investigate regression. |
