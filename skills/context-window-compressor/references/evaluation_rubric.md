# Context Compression Evaluation Rubric & Quality Gates

This reference defines the formal 6-dimension evaluation rubric used to measure context compression quality and verify that zero accuracy degradation occurs during token reduction.

---

## 1. The 6 Functional Quality Dimensions

| Dimension | Target Score | What It Measures | Failure Modes (Points Deducted) |
|---|:---:|---|---|
| **1. Accuracy** | **5.0 / 5.0** | Precise retention of technical facts, error codes, ports, exact variable/function names, and configuration parameters. | Hallucinating a function name, misquoting an error code, or guessing an expired token. |
| **2. Context Awareness** | **5.0 / 5.0** | Accurate representation of the active milestone, branch state, and immediate blockers. | Thinking a completed step is still pending, or repeating an already rejected approach. |
| **3. Artifact Trail** | **5.0 / 5.0** | 100% fidelity on which files were created, modified, read, or deleted, including path resolution. | Forgetting a modified test file, dropping directory prefixes, or losing uncommitted changes. |
| **4. Completeness** | **5.0 / 5.0** | Preservation of all explicit user requirements, multi-part instructions, and edge cases. | Dropping the 3rd requirement in a 3-part prompt, omitting secondary endpoints. |
| **5. Continuity** | **5.0 / 5.0** | Ability to proceed directly with execution without asking the user to repeat previous context or re-reading unchanged files. | Re-fetching already inspected files, re-asking previously clarified questions. |
| **6. Instruction Following** | **5.0 / 5.0** | Strict adherence to negative constraints ("DO NOT touch file X", "No external dependencies", "Must support Node 18"). | Violating a negative constraint stated earlier in the session due to summarization loss. |

---

## 2. Probe-Based Verification Protocol

Rather than relying on lexical overlap metrics (ROUGE, BLEU) which mask critical fact loss, the system executes 4 targeted probe queries after compression:

### Probe 1: Fact Recall Probe
- **Prompt:** `"What was the exact root cause and error message identified in the earlier debugging step?"`
- **Pass Criteria:** Exact error string, file location, and root cause match original trace.

### Probe 2: Artifact Manifest Probe
- **Prompt:** `"List every file that has been created or modified so far, and their current modification status."`
- **Pass Criteria:** Set equality between probe output and true filesystem change manifest.

### Probe 3: Constraint Adherence Probe
- **Prompt:** `"What constraints were established by the user regarding libraries, versions, or banned patterns?"`
- **Pass Criteria:** 100% recall of negative and positive constraints without omissions.

### Probe 4: Task Continuation Probe
- **Prompt:** `"What is the immediate next step to execute, and which functions must be called?"`
- **Pass Criteria:** Logically sound, immediate next step directly continuing from the previous turn's exit state.

---

## 3. Zero-Accuracy-Loss Acceptance Gate

A compression configuration is approved for production **ONLY IF**:
$$\text{Average Score} = 5.00 \ (100\%) \quad \land \quad \text{Constraint Violations} = 0 \quad \land \quad \text{Token Reduction} \ge 65\%$$
