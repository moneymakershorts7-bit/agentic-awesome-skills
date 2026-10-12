# Playbook 05: Performance & Load Gating with k6

This playbook provides step-by-step guidance for executing load, stress, and latency smoke tests before production deployment.

---

## Step 1: Pre-Execution Environment Setup

1. Verify target endpoint is accessible:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/api/health
   ```
2. Verify k6 or alternative runner is installed (or use standard HTTP benchmarking).

---

## Step 2: Smoke Gate Execution

Run a fast smoke test to establish baseline latency:
```bash
k6 run --vus 5 --duration 30s load-smoke.js
```

### Passing Invariants:
- `http_req_failed`: Rate must be $0.00\%$
- `http_req_duration p(95)`: Must be $< 500\text{ms}$
- `http_req_duration p(99)`: Must be $< 1000\text{ms}$

---

## Step 3: Sustained Load & Stress Gate

For major architectural or database updates:
```bash
k6 run load-stress.js --out json=reports/qa/k6_metrics.json
```

Evaluate system metrics under load:
1. Verify memory does not exhibit monotonic growth (memory leak).
2. Verify CPU utilization does not peg at 100% permanently.
3. Check database connection pool for exhausted connections or deadlocks.

---

## Step 4: Regression Analysis

Compare the current p95 latency against the baseline recorded in previous releases:
- If current p95 latency regresses by $> 20\%$, trigger a **Performance Warning**.
- If current p95 latency regresses by $> 50\%$, **Fail CI Quality Gate** and require performance profiling before merge.
