# Modern QA Engineering: Literature, Architecture, and Canon

This reference synthesizes the theoretical foundation of software quality engineering, grounding automated and manual QA practices in proven software engineering literature.

---

## 1. Vladimir Khorikov: Unit Testing Principles, Practices, and Patterns

### The 4 Pillars of a Good Test
A test's value is defined by a multiplicative relationship:
$$\text{Test Value} = [\text{Protection Against Regressions}] \times [\text{Resistance to Refactoring}] \times [\text{Fast Feedback}] \times [\text{Maintainability}]$$
If any single pillar collapses to zero, the test provides zero value and becomes pure technical debt.

1. **Protection Against Regressions:** Measures the test's ability to uncover defects when code changes. Governed by the amount of code executed, complexity of the domain logic, and significance of the business rules.
2. **Resistance to Refactoring (Non-Negotiable):** The degree to which a test remains green when code is refactored without altering observable behavior. Tests that break on implementation refactoring produce *false positives*, leading to test desensitization.
3. **Fast Feedback:** Sub-second to few-second execution latency, enabling continuous execution inside developer feedback loops.
4. **Maintainability:** Clarity of Arrange-Act-Assert structure, minimal setup fixtures, and isolation from fragile external environments.

### Observable Behavior vs. Implementation Details
- **Observable Behavior:** Public operations that achieve a client goal, and externally visible state or side-effects (persisted records, out-of-process messages).
- **Implementation Detail:** Any internal method, private collaborator, intermediate algorithm, or transient state chosen to achieve the goal.
- **Rule:** Never assert against private state or internal method call sequences unless validating an out-of-process command boundary.

### Classical (Detroit) vs. London (Mockist) Testing
- **Classical School:** Unit of isolation is the *cohesive behavioral slice*. Real instances are used for in-process collaborators; only out-of-process dependencies with shared mutable state (databases, message brokers) are doubled. Maximizes *Resistance to Refactoring*.
- **London School:** Unit of isolation is the *class*. Every collaborator is replaced by a mock. Leads to brittle tests tightly coupled to interface contracts and implementation details.
- **Master QA Directive:** Adopt the Classical School for all domain and algorithmic logic. Use test doubles strictly at the system boundary.

---

## 2. Lisa Crispin & Janet Gregory: The Agile Testing Quadrants

Testing must critique the product and support the team across business and technical dimensions:

| Quadrant | Focus & Target | Methodologies & Types | Tools & Automation |
| :--- | :--- | :--- | :--- |
| **Q1: Technology-Facing $\to$ Guiding Team** | Internal code quality & architecture | Unit tests, component tests, API contracts | Automated (xUnit, pytest, Vitest, Bun test) |
| **Q2: Business-Facing $\to$ Guiding Team** | Functional acceptance & user requirements | Acceptance criteria, user stories, BDD workflows | Automated (Playwright, Cypress, Cucumber) |
| **Q3: Business-Facing $\to$ Critiquing Product** | User experience, unforeseen defects, usability | Exploratory testing, usability audits, alpha/beta | Human/Agent Exploratory (SBTM, SFDIPOT) |
| **Q4: Technology-Facing $\to$ Critiquing Product** | Non-functional invariants & system resilience | Load, stress, visual regression, security, chaos | Automated / Scheduled (k6, Stryker, axe-core) |

---

## 3. Elisabeth Hendrickson & James Bach: Exploratory Testing & Oracles

### Heuristic Test Strategy Model: SFDIPOT (San Francisco Depot)
Ensure 360-degree test coverage across 7 product dimensions:
- **Structure (S):** Code, files, dependencies, build targets, database schema.
- **Function (F):** Capabilities the application provides to users and background systems.
- **Data (D):** Input domain, edge-case values, corrupted payloads, format extremes.
- **Interfaces (I):** REST/GraphQL APIs, CLI flags, Web UI, webhooks, event buses.
- **Platform (P):** Operating system variants, browser engines, container runtimes.
- **Operations (O):** Realistic user journeys, peak vs off-peak workloads, admin workflows.
- **Time (T):** Concurrency, asynchronous race conditions, leap years, timeouts, clock skew.

### Consistency Oracles: FEW HICCUPPS
To recognize whether unexpected behavior is a genuine bug, evaluate inconsistency against:
- **F - Familiar Problems:** Recurring bug patterns from past incidents.
- **E - Explainability:** Behavior cannot be logically explained without absurdity.
- **W - World:** Inconsistent with real-world physics, mathematics, or domain laws.
- **H - History:** Inconsistent with how previous stable versions operated.
- **I - Image:** Behavior degrades the organization's reputation or aesthetic quality.
- **C - Comparable Products:** Inconsistent with standard behavior in peer applications.
- **C - Claims:** Inconsistent with documentation, PRDs, or user manual claims.
- **U - User Expectations:** Inconsistent with what target users intuitively anticipate.
- **P - Product:** Inconsistent with other features within the same system.
- **P - Purpose:** Defeats or undermines the feature's fundamental reason for existing.
- **S - Standards:** Violates industry standards, accessibility (WCAG), or security regulations.

### Session-Based Test Management (SBTM) & Charters
- **Charter Syntax:**
  $$\text{Explore } [\text{Target}] \text{ With } [\text{Resources / Constraints}] \text{ To Discover } [\text{Risks / Information}]$$
- **TBS Metric:** Standardized session time accounting:
  $$T_{\text{session}} = T_{\text{Test \& Design (T)}} + T_{\text{Bug Investigation (B)}} + T_{\text{Setup (S)}}$$
  Healthy sessions target $T \ge 70\%$.

---

## 4. Gerard Meszaros: xUnit Test Patterns & Smells

### Test Double Classification
- **Dummy:** Passed to satisfy type signatures; never called or inspected.
- **Stub:** Returns canned values to provide indirect inputs into the SUT.
- **Spy:** Records invocations and arguments for later assertion verification.
- **Mock:** Pre-programmed with strict expectations; self-verifies calls.
- **Fake:** Working implementation with shortcuts (e.g. in-memory SQLite/Dictionary repo).

### Critical Test Smells
- **Assertion Roulette:** Multiple assertions in one test block without failure messages.
- **Mystery Guest:** Relying on magic files or external state outside the test function.
- **Flaky Sleeper:** Hardcoded `sleep(ms)` instead of polling condition awaiters.
- **Conditional Test Logic:** `if/else` or loops inside tests, increasing test maintenance risk.

---

## 5. Microservices & Distributed QA (Sam Newman)
- **Consumer-Driven Contract Testing (Pact):** Consumers define expected request/response contracts; providers verify compliance independently. Eliminates end-to-end integration environments.
- **Testcontainers Paradigm:** Use disposable Docker containers for integration testing (PostgreSQL, Redis, Kafka) instead of fragile in-memory mocks (e.g. H2).
- **Testing in Production:** Canary deployments, feature flags, dark traffic shadowing, and synthetic probes provide verification under real network and data scale.

---

## 6. Advanced Verification: Mutation & Property-Based Testing
- **Mutation Testing (Stryker / Mutmut):** Synthesizes code mutations (e.g., changing `>=` to `>`, inversion, block deletion). Evaluates the **Mutation Score Index (MSI)**:
  $$\text{MSI} = \frac{\text{Mutants Killed}}{\text{Total Mutants} - \text{Equivalent Mutants}} \times 100\%$$
  Reveals tests that execute lines without actually asserting state.
- **Property-Based Testing (Hypothesis / fast-check):** Verifies universal invariants across hundreds of auto-generated edge-case inputs:
  1. *Round-Trip:* `deserialize(serialize(x)) == x`
  2. *Idempotence:* `f(f(x)) == f(x)`
  3. *Metamorphic:* `len(filter(p, list)) <= len(list)`
  4. *Oracle:* `fast_algo(x) == simple_reference_algo(x)`

---

## 7. The Testing Diamond & The 5 Backend Exit Doors (Goldberg Yoni)

### The Testing Diamond vs. The Traditional Pyramid
Rather than overloading the base with isolated unit tests that break upon refactoring, or overloading the top with fragile end-to-end tests:
- **Core Bulk: Integration & Component Testing:** Exercise business operations via public API contracts against real, ephemeral database containers (Testcontainers). Delivers maximum ROI, refactoring resistance, and high regression coverage.
- **Selective Unit Tests:** Reserved strictly for algorithmic logic, pure functions, state machine calculators, and combinatorial edge cases.
- **Focused E2E Smoke Tests:** Small set of critical user journeys (e.g. signup -> checkout -> receipt) verifying browser and network wiring.

### The 5 Backend Exit Doors
Every backend feature or endpoint terminates at one or more of five deterministic "exit doors." A complete test must assert only against these doors without inspecting internal wiring:
1. **Door 1: Immediate Response:** The HTTP/gRPC status code and response payload returned to the caller.
2. **Door 2: State Persistence:** Records updated or created in the database.
3. **Door 3: Third-Party Boundary Calls:** Outgoing HTTP requests to external services (verified via Contract testing or network mocks).
4. **Door 4: Asynchronous Messages:** Events emitted to message brokers (Kafka, RabbitMQ, SQS, Redis pub/sub).
5. **Door 5: Observability & Diagnostics:** Structured logs, OpenTelemetry traces, or metric counters incremented for monitoring.

---

## 8. AI-Augmented Exploratory & Self-Healing Testing (`tester-army/e2e`)

Modern testing harnesses combine natural language goal orientation with deterministic replaying:
- **Autonomous Step Execution:** An AI agent receives a high-level intent (`agent.act('upgrade the workspace to the Pro plan')`) and navigates dynamic DOM elements.
- **Deterministic Action Replay:** Once verified by assertions, the agent's action steps are cached and replayed deterministically without further model invocations until application markup or workflows change.
- **Self-Healing Automation:** When locators break due to design system changes, the autonomous agent re-explores the screen to re-bind the action safely, eliminating flaky script maintenance.
