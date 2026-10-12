# Manual QA & Exploratory Testing: Heuristics, Oracles, and Charters

Manual QA in high-performing engineering teams is not rote "script following"; it is **scientific exploratory investigation**, modeled after Elisabeth Hendrickson's *Explore It!*, James Bach & Michael Bolton's *Rapid Software Testing (RST)*, and Cem Kaner's *Testing Computer Software*.

---

## 1. Product Modeling Heuristic: SFDIPOT

When analyzing a new feature or release, map out tests across the 7 dimensions of SFDIPOT:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SFDIPOT PRODUCT MODEL                           │
├───────────────┬────────────────────────────────────────────────────────┤
│ Structure (S) │ Code, dependencies, config files, DB schemas, bundles │
│ Function (F)  │ What the system does: calculations, workflows, actions │
│ Data (D)      │ Input arguments, edge values, formats, state changes  │
│ Interfaces (I)│ Web UI, CLI flags, REST/GraphQL APIs, background queues │
│ Platform (P)  │ OS, container, browser engines, mobile screen viewports│
│ Operations (O)│ Real human behaviors, peak concurrency, admin tasks    │
│ Time (T)      │ Delays, race conditions, timeouts, timezones, leap sec │
└───────────────┴────────────────────────────────────────────────────────┘
```

---

## 2. Consistency Oracles: FEW HICCUPPS

How do you determine if an observation is an actual defect? Compare it against the 11 consistency oracles:

1. **F - Familiar Problems:** Does this resemble bugs seen in past sprints or known framework quirks?
2. **E - Explainability:** Is the behavior inexplicable without resorting to illogical assumptions?
3. **W - World:** Does it violate physical reality, common sense, or real-world mathematical facts?
4. **H - History:** Does the feature behave differently from previous working versions?
5. **I - Image:** Does the behavior look amateurish, broken, or damaging to the company brand?
6. **C - Comparable Products:** Do major competitors handle this situation more gracefully?
7. **C - Claims:** Does the behavior contradict the PRD, README, help docs, or marketing promises?
8. **U - User Expectations:** Would a reasonable end user be confused, frustrated, or misled?
9. **P - Product:** Is this behavior inconsistent with how sibling features in the same app behave?
10. **P - Purpose:** Does the behavior defeat the core utility for which the feature was created?
11. **S - Standards:** Does it violate industry standards, WCAG accessibility, or security compliance?

---

## 3. Session-Based Test Management (SBTM) & Charter Design

### Canonical Charter Template
$$\mathbf{\text{Explore } [\text{Target / Feature}] \text{ With } [\text{Resources / Constraints}] \text{ To Discover } [\text{Risks / Information}]}$$

### Example Charter:
> **Charter:** Explore the Shopping Cart Checkout with network latency throttling, concurrent browser tabs, and invalid coupon codes to discover state de-synchronization, duplicate charges, or unhandled gateway errors.

### The TBS Metrics Accounting
Every session is timeboxed (typically 60 to 90 minutes). The tester records time spent across:
- **T (Test & Design):** Generating and executing test ideas against the product (target $\ge 70\%$).
- **B (Bug Investigation):** Isolating root causes and writing defect reports (target $\le 20\%$).
- **S (Setup):** Configuring environments, test accounts, and data fixtures (target $\le 10\%$).

---

## 4. Defect Taxonomy & Machine-Parsable Bug Reporting

### Severity (Technical Impact) vs. Priority (Business Urgency)
- **Blocker / P0:** System crash, data loss, security exposure, no workaround. Urgent hotfix required.
- **Critical / P1:** Core business capability impaired for major user segment; complex workaround. Fix in sprint.
- **Major / P2:** Non-critical feature broken or workaround available. Planned next release.
- **Minor / P3:** Edge case, cosmetic UI defect, minor alignment problem.
- **Trivial / P4:** Typo, cosmetic suggestion, non-distracting visual irregularity.

### Canonical Defect Report Format (Markdown)

```markdown
### [BUG-ID] <Concise Imperative Summary>

- **Severity:** Blocker | Critical | Major | Minor | Trivial
- **Priority:** P0 | P1 | P2 | P3
- **Component:** <Module / Route / Service>
- **Environment:** Staging / Production | OS | Browser Version | Git Commit SHA

#### 1. Preconditions & Test Data
- User role / permissions:
- Initial state / data fixtures:

#### 2. Steps to Reproduce (STR)
1. Navigate to ...
2. Input value ...
3. Click button ...

#### 3. Expected vs Actual Result
- **Expected:** System displays success banner and redirects within 500ms.
- **Actual:** UI hangs indefinitely; console logs `500 Internal Server Error: NullPointerException`.

#### 4. Attached Artifacts
- **Screenshot / Video:** `artifacts/bugs/BUG-001/failure.png`
- **Network HAR:** `artifacts/bugs/BUG-001/network.har`
- **Console / Server Logs:** `artifacts/bugs/BUG-001/error.log`
```
