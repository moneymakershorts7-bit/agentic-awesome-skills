# The Grill-Me Interview Rubric: Zero-Assumption Engineering

This rubric governs how an agent conducts an interactive interview with the user.

---

## 1. The Core Invariants

### Invariant 1: Finding Facts is the Agent's Job, Never the User's
- Do not interrogate the user for discoverable environment facts (such as OS details, existing files, or manifest dependencies).
- Inspect repository files and AST configs first to establish ground truth facts in the workspace.
- Focus questions strictly on intent, trade-offs, business logic, constraints, and priorities that cannot be deterministically inferred from the codebase.

### Invariant 2: Always Provide a Pre-Computed Recommended Answer
- Every question MUST feature a recommended option as the very first choice, explicitly marked `(Recommended)`.
- Format questions so that replying "Yes" or selecting Option 1 immediately accepts the best-practice path.
- The user should only have to type when they deliberately wish to override the agent's recommended architectural choice.

### Invariant 3: Walk the Frontier in Rounds (No Information Overload)
- Do not dump 10 questions at once.
- Identify the **Frontier**: questions whose prerequisites are already settled.
- Group 1 to 3 tightly coupled frontier questions into a single round.
- Await the user's answers before expanding the next tier of the decision tree.

---

## 2. Interactive Tool Integration (`ask_question`)

In Antigravity and compatible UI environments, the agent MUST leverage the native `ask_question` tool:

```json
{
  "questions": [
    {
      "question": "Which state management pattern should be used for the new component?",
      "options": [
        "(Recommended) Zustand store with selective hydration",
        "React Context with useReducer",
        "Local useState with prop drilling"
      ],
      "is_multi_select": false
    }
  ]
}
```

### Guidance for Formatting Options:
- Write options as the **user's direct response** (e.g. "(Recommended) Use SQLite FTS5 for local search", NOT "I will use SQLite").
- Never include an "Other" option (the interactive UI automatically provides a write-in field).
- Never number the options manually (the modal UI numbers them automatically).

---

## 3. When to Stop Grilling
The grilling session is complete when:
1. The decision frontier is empty.
2. Target files, signatures, dependencies, error handling, and test acceptance criteria are 100% determined.
3. The certainty score $P(\text{first-try success}) = 1.0$.
4. The user confirms the final plan.
