# 3-Layer Context Assembly & Mathematical Compression Model

This reference details the mathematical formulation and architectural layout for the 3-Layer Context Assembly Engine.

---

## 1. Mathematical Formulation

Let $C_t = [u_0, a_0, u_1, a_1, \dots, u_t, a_t]$ be the full conversation trajectory at turn $t$, where $u_i$ is the user prompt and $a_i$ is the assistant response (including tool invocations $T_i$ and tool results $R_i$).

Let $B_{\text{max}}$ be the maximum token budget allocated for context (e.g., $100,000$ tokens).

### A. Semantic Drift Function
Let $\vec{e}_0 = \text{Embed}(u_0)$ be the initial session anchor vector.
Let $W_k = [u_{t-k}, a_{t-k}, \dots, u_t, a_t]$ be the rolling window of the last $k$ turns (default $k=3$).
The semantic drift metric $D(W_k, \vec{e}_0)$ is computed as:
$$D(W_k, \vec{e}_0) = 1 - \frac{\vec{e}_{W_k} \cdot \vec{e}_0}{\|\vec{e}_{W_k}\| \|\vec{e}_0\|}$$

### B. The Tripartite Compression Trigger Gate
Compression is triggered when:
$$\Phi(C_t) = \mathbb{I}\left( D(W_k, \vec{e}_0) > \theta_{\text{drift}} \right) \times \mathbb{I}\left( \text{Tokens}(C_t) > \alpha \cdot B_{\text{max}} \right) \times \mathbb{I}\left( \text{Boundary}(a_t) = 1 \right)$$
Where:
- $\theta_{\text{drift}} = 0.42$ (calibrated to ignore temporary debugging tangents while catching true task pivots).
- $\alpha = 0.65$ (triggers before entering the degradation zone at $70\%+$ utilization).
- $\text{Boundary}(a_t) \in \{0, 1\}$ indicates completion of a distinct test run, commit, file edit completion, or explicit user topic shift.

---

## 2. The 3-Layer Assembly Specification

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: PINNED INVARIANTS & CONSTRAINTS ($\sim 10\%$ of budget)            │
│ --------------------------------------------------------------------------- │
│ • System Instructions & Core Agent Rules                                    │
│ • User Preferences & Negative Constraints ("NEVER use...", "MUST support..")│
│ • Root Goal ($I_0$) & Architectural Principles                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 2: ANCHORED ITERATIVE SUMMARY & ARTIFACT MAP ($\sim 20\%$ of budget)  │
│ --------------------------------------------------------------------------- │
│ • Structured Markdown Digest of closed milestones                           │
│ • Files Created / Modified / Inspected (with line counts and statuses)       │
│ • Key Architectural Decisions & Rejected Alternatives                       │
│ • Reversible Pointer (Disk path + Line offsets to full JSONL transcripts)    │
├─────────────────────────────────────────────────────────────────────────────┤
│ LAYER 3: HOT ROLLING WINDOW ($\sim 70\%$ of budget)                         │
│ --------------------------------------------------------------------------- │
│ • Last $N$ turns in full raw conversational fidelity                        │
│ • Active code diffs, current error messages, immediate tool call responses  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Telemetry Pruning Rules

Tool outputs are pruned based on category and entropy:

| Tool Output Type | Raw Condition | Pruning Transformation |
|---|---|---|
| **Bash Command Stdout** | $> 30$ lines | Head (5 lines) + Tail (10 lines) + Exit Code + `[truncated X lines -> pointer]` |
| **File Read / View** | $> 40$ lines | Summary of functions/classes inspected + line ranges + file path link |
| **Directory Search / Grep** | $> 25$ matches | Match count + Top 5 file paths + match summary |
| **Compiler / Test Logs** | Passing test suite | `[Test Suite Passed: 48 tests OK (0.84s)]` (strip 500 lines of test names) |
| **Compiler / Test Logs** | Failing test suite | Exact failure assertion + stack frame (5 lines) + strip passing tests |
