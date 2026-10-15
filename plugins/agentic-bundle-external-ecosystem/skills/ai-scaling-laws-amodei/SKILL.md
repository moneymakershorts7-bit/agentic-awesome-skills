---
name: ai-scaling-laws-amodei
description: Dario Amodei's framework on AI scaling laws, capability forecasting,
  compute economics, and human-AI collaboration models.
author: jona
source: community
source_repo: jona/ycombinator-skills
license: MIT
category: startup-strategy
tags:
- scaling-laws
- capability-forecasting
- compute
- enterprise-ai
- safety
allowed-tools:
- view_file
- read_file
- run_command
risk: safe
---
# Scaling and the Road to Human-Level AI

Strategic framework for understanding AI scaling laws and building products that leverage predictable AI capability improvements.

## Core Concepts

### Two Phases of AI Training

**Pretraining**: Models learn to predict the next token by imitating human-written text, understanding underlying correlations in data.

**Reinforcement Learning (RL)**: Models are optimized based on human feedback, reinforcing helpful/honest/harmless behaviors and discouraging harmful ones.

Scaling laws exist for both phases—performance improves predictably with increased compute, data, and parameters.

### Key Metrics

- **Task Horizon**: Length/complexity of tasks AI can complete, measured in equivalent human time
- **Elo Scores**: Rating system measuring model preference comparisons
- **Context Window**: Amount of information processable in a single conversation

### Scaling Law Reliability

Scaling laws have held across 5+ orders of magnitude with physics-level precision. When scaling appears broken, assume training implementation issues first, not fundamental limits.

## Strategic Decision Framework

### Assess Current AI Capabilities

Use the two-axis capability framework:
1. **Y-axis (Flexibility)**: What modalities can the model handle?
2. **X-axis (Task Horizon)**: What equivalent human-time tasks can it complete?

Current trajectory: Task horizons double approximately every 7 months.

### Product Timing Strategy

```
Current capability assessment:
├── Works reliably now → Build and ship immediately
├── Works 70-80% of time → Viable for error-tolerant use cases
├── Works marginally → Build now, ship when next model releases
└── Doesn't work at all → Wait 1-2 model generations
```

**Key insight**: Build products that don't quite work yet with current AI capabilities. Target capabilities slightly beyond current models—future models will make marginal products work.

### Use Case Selection Criteria

Prioritize applications where:
- 70-80% accuracy is acceptable
- Breadth of knowledge matters more than deep focus on one hard problem
- Cross-domain synthesis creates value (biology + psychology + history)
- Human review can catch and correct errors

Deprioritize applications requiring:
- Near-perfect accuracy on first attempt
- Deep specialized reasoning lacking systematic verification checks
- Tasks where errors compound catastrophically

## Extended Knowledge & Deep-Dive Guide

For full operational workflows, step-by-step evaluation matrices, analytical templates, and extended source materials:
- Consult [references/deep-dive.md](references/deep-dive.md)
