---
name: agent-criteria-gate
description: Pre-flight criteria evaluation, prompt ambiguity detection, risk triage, and intent routing using System One decision models (Kev, Jev, /v1/systemone) and high-speed local discriminative engines.
allowed-tools:
  - run_command
  - view_file
  - curl
  - fetch
allowed-domains:
  - 127.0.0.1
  - localhost
  - api.typesafe.ai
---

# Agent Criteria Gate

Enforce deterministic, calibrated criteria on user prompts, tool executions, and agent states before triggering expensive generative LLM calls.

## Overview

The `agent-criteria-gate` skill provides a **System One** decision layer that evaluates prompts in $<1\text{ms}$ (local engine) or $15\text{--}40\text{ms}$ (Kev-0.8B) in a single forward pass:
1. **Ambiguity Gate (`is_ambiguous`):** Detects vague or underspecified inputs (`noul`) and stops execution early to ask targeted clarification questions.
2. **Safety & Destructive Gate (`is_destructive`):** Intercepts high-risk commands and data deletion (`noul` + `score`) to require human-in-the-loop (HITL) approval.
3. **Intent Routing (`execution_route`):** Classifies the task category (`choice`) with calibrated confidence scores to route to specialized agents or tools.

## Supported Question Primitives

- **`noul`**: Binary boolean evaluation returning calibrated probability $P(\text{true}) \in [0.0, 1.0]$.
- **`choice`**: Discrete routing across labeled options with full probability distribution and confidence score.
- **`score`**: Weighted continuous score across ordinal rubric levels.

## Usage

### 1. Python Integration
```python
from decision_gate import AgentDecisionGate, DecisionAction
from system_one_client import SystemOneClient

# Initialize client (connects to local Kev or falls back to embedded engine)
client = SystemOneClient(base_url="http://127.0.0.1:8000", fallback_local=True)
gate = AgentDecisionGate(client=client)

action, details = gate.decide("Delete old logs and notify the team")

if action == DecisionAction.ASK_CLARIFICATION:
    print(f"Ambiguous: {details['suggested_response']}")
elif action == DecisionAction.REQUIRE_HITL_APPROVAL:
    print(f"Safety Gate: {details['reason']}")
elif action == DecisionAction.EXECUTE_ROUTE:
    print(f"Dispatching to route: {details['route']} (Confidence: {details['confidence']:.2f})")
```

### 2. Command Line Interface (CLI)
```bash
# Evaluate a prompt
python3 ~/.agents/skills/agent-criteria-gate/cli.py "fix it"

# Benchmark latency on local CPU
python3 ~/.agents/skills/agent-criteria-gate/cli.py --benchmark
```

## References
- Full wire protocol and model deployment options: `references/spec.md`
