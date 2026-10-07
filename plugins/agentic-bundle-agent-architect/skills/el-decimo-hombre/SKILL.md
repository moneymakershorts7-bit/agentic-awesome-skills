---
name: el-decimo-hombre
description: Institutionalized adversarial stress-testing, contrarian deliberation, and pre-execution After Action Review (AAR). Mandates systematic dissent against prevailing consensus to uncover blind spots, black swans, and fatal assumptions.
risk: safe
source: community
date_added: "2026-10-07"
---

# El Décimo Hombre (The Tenth Man)

## When to Use

Use this skill whenever a plan, architectural proposal, strategic decision, or consensus view appears complete and unchallenged. Specifically invoke when:
- The user or team has reached unanimous agreement on an architecture, deployment strategy, or business decision.
- You need an adversarial "Red Team" audit to stress-test critical assumptions before irreversible execution.
- Evaluating low-probability, catastrophic-impact scenarios (Black Swans).
- Running a structured pre-execution After Action Review (Premortem AAR) with explicit kill criteria.

## Core Operational Doctrine

The Tenth Man operates under the **Ipcha Mistabra** ("the opposite appears to be true") mandate:
> **When nine analysts agree, the Tenth Man is duty-bound to assume the nine are wrong and construct the most rigorous, evidence-grounded counter-case possible.**

This is not performative contrarianism or obstruction; it is an active vulnerability discovery engine designed to immunize high-stakes decisions against confirmation bias and groupthink.

---

## Execution Workflow: The 5-Phase Adversarial Loop

```
┌────────────────────────────────────────────────────────┐
│ Phase 1: Consensus & Assumption Extraction             │
│ (Isolate the 9's thesis, hidden axioms, and blind spots)│
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 2: Ipcha Mistabra Inversion (Mandated Dissent)   │
│ (Construct 3 asymmetric failure vectors)               │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 3: Adversarial Council Deliberation              │
│ (Debate between Lead Proponent vs The 10th Man)        │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 4: Simulated After Action Report (Pre-AAR)       │
│ (Expected vs Disaster Reality + 5-Whys Root Cause)     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 5: Kill Criteria & Hardening Directives          │
│ (Non-negotiable abort triggers + structural hedges)    │
└───────────────────────────┴────────────────────────────┘
```

### Phase 1: Consensus & Assumption Extraction
1. Extract the primary thesis and desired outcome.
2. Identify the **Unstated Axioms**: What conditions *must* hold true for this plan to succeed without incident? (e.g., vendor SLA, network reliability, user competence, latency limits, cost bounds).
3. Score the consensus confidence level and identify confirmation bias clusters.

### Phase 2: Empirical Counter-Research (`antagonist-researcher`)
When empirical data, benchmark validation, or historical postmortems are required to challenge the plan:
* **Invoke Subagent:** Delegate deep counter-investigation to `antagonist-researcher`.
* **Investigation Target:** Unearth documented system outages, published CVEs, scalability ceilings, or conflicting benchmark results directly disproving the core assumptions.
* **Evidence Classification:** Tag all findings as `[Certain]`, `[Likely]`, or `[Guessing]` with mandatory citations.

### Phase 3: Ipcha Mistabra Inversion
Construct three distinct, independent attack vectors against the consensus:
1. **Asymmetric Risk / Tail Event:** A low-probability operational shock that invalidates primary dependencies.
2. **Hidden Friction / Scaling Bottleneck:** A second-order breakdown that emerges only under load, concurrency, or prolonged execution.
3. **Adversarial / Malicious Vector:** How an external attacker, competitor, or misconfigured subsystem exploits this specific design.

### Phase 3: Adversarial Council Deliberation
Simulate a structured clash:
- **Proponent Defense:** The strongest rebuttal the original team would give to defend their architecture.
- **Tenth Man Cross-Examination:** Ruthless refutation focusing on empirical data, single points of failure (SPOFs), and unhedged risks.

### Phase 4: Simulated After Action Report (Pre-Execution AAR)
Perform an inverted AAR projecting a catastrophic post-launch scenario:
- **1. What was supposed to happen?** (The original baseline goal).
- **2. What disastrously happened instead?** (The simulated failure state).
- **3. Why was there a variance?** (Root causes via 5 Whys analysis).
- **4. What must be re-engineered now?** (Preventative redesign).

### Phase 5: Kill Criteria & Hardening Directives
Produce the final output containing:
1. **Kill Criteria:** Concrete, observable thresholds (e.g., error rate > 0.5%, P99 latency > 300ms, budget burn > 15%/day) that mandate an immediate halt or rollback.
2. **Structural Hedges:** Architecture or workflow modifications to ensure survivability even if the 10th Man's failure scenarios materialize.

---

## Output Template

When invoking `el-decimo-hombre`, format the output strictly as follows:

```markdown
# 🛡️ El Décimo Hombre: Adversarial Assessment

## 1. The Consensus Under Attack
* **Core Proposal:** [Brief synthesis of the plan]
* **Fragile Assumptions:** [List of 2-4 unvalidated assumptions]

## 2. Inversion & Attack Vectors (Ipcha Mistabra)
* **Vector A (Tail Event / Black Swan):** [Description and blast radius]
* **Vector B (Hidden Bottleneck / Cascade):** [Description and mechanics]
* **Vector C (Adversarial / Exploitation):** [Description and exposure]

## 3. Simulated After Action Report (Disaster Scenario)
* **Simulated Incident:** [How the failure presents in production]
* **Root Cause Breakdown:** [5-Whys isolation of the failure]
* **Detection Lag:** [How long the team took to notice and why]

## 4. Non-Negotiable Kill Criteria
* [Condition 1]: [Trigger metric and immediate abort action]
* [Condition 2]: [Trigger metric and immediate abort action]

## 5. Hardening Directives
* [Action 1]: [Specific architectural or procedural change]
* [Action 2]: [Fallback mechanism or circuit breaker]
```

## Progressive Disclosure

For detailed debate protocols, historical doctrine, and multi-model council patterns, refer to:
- [`references/methodology.md`](file:///home/npirela/.agents/skills/el-decimo-hombre/references/methodology.md)
- [`references/protocols.md`](file:///home/npirela/.agents/skills/el-decimo-hombre/references/protocols.md)
