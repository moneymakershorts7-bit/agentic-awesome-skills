# Test Automation Frameworks & Tooling Matrix

This guide provides concrete, copy-paste production configurations, CLI execution commands, and architectural trade-offs for modern SDET test automation.

---

## 1. Web & UI E2E Automation: Playwright vs Cypress

### Architectural Comparison
- **Playwright:** Out-of-process multi-browser automation via Chrome DevTools Protocol (CDP) / WebSocket. Native support for multi-page, multi-tab, popups, and iframes. Auto-waits for actionability (visible, enabled, stable).
- **Cypress:** In-browser execution inside an iframe within Chromium/Firefox. Fast for single-page component tests, but limited on multi-tab or cross-origin redirects.

### Playwright Production Standard (`playwright.config.ts`)

```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? '100%' : '50%',
  timeout: 30_000,
  expect: {
    timeout: 5_000,
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.01,
      threshold: 0.2,
      animations: 'disabled'
    }
  },
  reporter: [
    ['list'],
    ['junit', { outputFile: 'reports/junit-results.xml' }],
    ['json', { outputFile: 'reports/test-results.json' }],
    ['html', { outputFolder: 'reports/html', open: 'never' }]
  ],
  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:3000',
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    testIdAttribute: 'data-testid',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'mobile-chrome', use: { ...devices['Pixel 7'] } },
  ],
});
```

### Locator Resilience Directives
- **Strict Rule:** NEVER use fragile selectors (`div > .btn-primary:nth-child(2)` or `/html/body/div[2]/button`).
- **Priority Hierarchy:**
  1. Accessibility Role & Name: `page.getByRole('button', { name: /submit order/i })`
  2. Form Label: `page.getByLabel('Work Email')`
  3. Placeholder / Text: `page.getByPlaceholder('name@company.com')`
  4. Test ID (Explicit Contract): `page.getByTestId('order-submit-button')`

---

## 2. API & Contract Testing: Supertest, Playwright, Pact

### In-Memory vs. Network-Bound API Testing
- **Supertest:** Executes against Node HTTP listener in-memory without binding external TCP ports (`supertest(app).get('/api/users')`). Ideal for integration test suites running in CI.
- **Playwright `request`:** Directly issues HTTP calls reusing existing authentication state contexts, cookies, and tokens.
- **Pact (Consumer-Driven Contracts):** Generates JSON pact files during consumer unit tests and verifies them on provider CI builds before deployment (`can-i-deploy`).

### Playwright API & Edge Case Fuzzing Example
```typescript
import { test, expect } from '@playwright/test';

test.describe('API Invariant & Fuzzing Suite', () => {
  test('handles Big List of Naughty Strings gracefully', async ({ request }) => {
    const maliciousPayloads = [
      "'; DROP TABLE users; --",
      "<script>alert('xss')</script>",
      "\u0000",
      "A".repeat(5000),
      "null",
      "undefined",
      "{\"__proto__\": {\"admin\": true}}"
    ];

    for (const payload of maliciousPayloads) {
      const res = await request.post('/api/v1/profile', {
        data: { username: payload, bio: payload }
      });
      // System MUST NEVER crash with 500 or expose stack traces
      expect(res.status()).not.toBe(500);
      expect([200, 400, 422]).toContain(res.status());
    }
  });
});
```

---

## 3. Performance & Load Gating: Grafana k6

### Standard Thresholds & Profiles
- **Smoke Profile:** 5 Virtual Users (VUs) for 30s to verify script and endpoint health.
- **Load / Soak Profile:** Ramp to 100 VUs, hold for 5m, ramp down.
- **Spike Profile:** Surge from 10 to 500 VUs in 10s, hold for 1m, drop.
- **Non-Negotiable Quality Gates:**
  - `http_req_failed: ['rate < 0.001']` (Error rate < 0.1%)
  - `http_req_duration: ['p(95) < 500', 'p(99) < 1200']` (p95 latency < 500ms)

### Production k6 Script (`load-gate.js`)
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 20 },
    { duration: '1m', target: 50 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.001'],
    http_req_duration: ['p(95)<500', 'p(99)<1200'],
  },
};

export default function () {
  const res = http.get(__ENV.TARGET_URL || 'http://localhost:3000/api/health');
  check(res, {
    'status is 200': (r) => r.status === 200,
    'latency is acceptable': (r) => r.timings.duration < 500,
  });
  sleep(1);
}
```

---

## 4. Accessibility Testing: axe-core & WCAG 2.2 AA

```typescript
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('Homepage conforms to WCAG 2.2 AA accessibility standards', async ({ page }) => {
  await page.goto('/');
  await page.waitForLoadState('networkidle');

  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();

  const criticalIssues = results.violations.filter(v => v.impact === 'critical' || v.impact === 'serious');
  expect(criticalIssues).toEqual([]);
});
```

---

## 5. Visual Regression: Tolerances & Hardening
- **Anti-Flake Directives:**
  1. Freeze CSS animations: `*, *::before, *::after { animation: none !important; transition: none !important; }`
  2. Mask dynamic elements: timestamps, random avatars, transaction IDs.
  3. Force subpixel font-smoothing and lock viewport dimensions.
  4. Always generate baselines in containerized headless Chromium to avoid cross-OS font rendering variations.

---

## 6. AI-Driven Hybrid E2E Testing (`tester-army/e2e` Pattern)

Next-generation E2E testing marries high-level natural language agent guidance with deterministic, zero-cost CI replay and standard xUnit locators:

```typescript
import { test, expect } from 'e2e';

test('New user completes workspace onboarding', async ({ app, agent, screen }) => {
  await app.open('/onboarding');

  // Agent drives high-level goal navigation
  await agent.act('select the Growth plan and configure 5 team seats');

  // Independent Judge verifies visual state without actor bias
  await agent.assert('the order summary displays 5 seats with volume discount applied');

  // Grounded xUnit assertion confirms deterministic DOM state
  await expect(screen.getByRole('button', { name: /continue to payment/i })).toBeEnabled();
});
```

### Deterministic Replay & Strict Cache Rules
1. **Committed Replay Cache:** Record user journey steps into `.e2e/cache/` during development.
2. **Deterministic CI Execution:** In CI, steps replay from cache without LLM model invocations at near-native Playwright execution speeds.
3. **Strict Cache Enforcement (`--strict-cache`):** If a UI change invalidates the recorded steps, the CI gate fails immediately with `REPLAY_STALE` rather than silently spending tokens, notifying developers that re-recording is required.

---

## 7. Frontend Chaos Monkey & Resilience Testing (`marmelab/gremlins.js`)

Simulate erratic real-user behavior (rapid clicking, furious typing, random scrolling) inside Playwright to expose memory leaks, race conditions, and uncaught exceptions:

```typescript
import { test, expect } from '@playwright/test';

test('Checkout UI survives 1,000 chaotic user interactions without unhandled errors', async ({ page }) => {
  const uncaughtErrors: string[] = [];
  page.on('pageerror', (err) => uncaughtErrors.push(err.message));

  await page.goto('/checkout');
  await page.waitForLoadState('networkidle');

  // Inject gremlins.js bundle
  await page.addScriptTag({
    url: 'https://unpkg.com/gremlins.js@2.2.0/dist/gremlins.min.js'
  });

  // Unleash a 1,000-action chaos horde
  await page.evaluate(() => {
    return new Promise((resolve) => {
      // @ts-ignore
      const horde = window.gremlins.createHorde({
        species: [
          // @ts-ignore
          window.gremlins.species.clicker({ clickTypes: ['click'] }),
          // @ts-ignore
          window.gremlins.species.formFiller(),
          // @ts-ignore
          window.gremlins.species.scroller()
        ],
        strategies: [
          // @ts-ignore
          window.gremlins.strategies.allTogether({ nb: 1000, delay: 5 })
        ]
      });
      horde.after(() => resolve(true));
      horde.unleash();
    });
  });

  // Verify zero critical client crashes
  expect(uncaughtErrors.filter(e => !e.includes('ResizeObserver'))).toEqual([]);
});
```
