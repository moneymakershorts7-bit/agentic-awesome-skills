# Playbook 02: Session-Based Exploratory Test Execution

Exploratory testing is a structured, investigative process used to discover unexpected edge cases, UX bottlenecks, and architectural failures that automated regression scripts miss.

---

## Step 1: Formulate the Charter

Use Hendrickson's canonical charter formula:
$$\mathbf{\text{Explore } [\text{Target / Feature}] \text{ With } [\text{Resources / Constraints}] \text{ To Discover } [\text{Risks / Information}]}$$

Define the session scope:
- **Duration:** Timeboxed to 60 or 90 minutes.
- **Focus Area:** e.g., Checkout flow, authentication recovery, multi-tenant workspace isolation.
- **Resources:** Network throttling (DevTools Slow 3G), malformed input dictionaries (BLNS), concurrent browser tabs.

---

## Step 2: Session Execution & Time Tracking (TBS Metric)

During the timebox, keep track of activity using the TBS breakdown:
$$T_{\text{session}} = \%T \text{ (Test \& Design)} + \%B \text{ (Bug Investigation)} + \%S \text{ (Environment Setup)}$$
- Aim for $\%T \ge 70\%$.
- If $\%S > 20\%$, pause to automate environment setup fixtures.

---

## Step 3: Oracle Evaluation (FEW HICCUPPS)

When encountering unexpected behavior, evaluate against the 11 consistency oracles:
1. Does it violate **User Expectations** or make the interface feel laggy or unhelpful?
2. Does it contradict written **Claims** in documentation or error messages?
3. Does it break internal **Product** consistency with other similar modals or screens?
4. Is it a recurring **Familiar Problem** from previous releases?

---

## Step 4: Bug Filing & Evidence Capture

For every defect discovered, generate an evidence-grounded report:
1. Exact Steps to Reproduce (STR).
2. Expected vs. Actual behavior.
3. Relevant system log or browser console trace.
4. Assigned Severity (Blocker, Critical, Major, Minor) and Priority (P0-P3).
