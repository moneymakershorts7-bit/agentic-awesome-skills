---
name: agi-framework-chollet
description: "Theoretical framework for understanding intelligence, AGI development\
  \ paths, and the limitations of current AI scaling approaches from Fran\xE7ois Chollet\
  \ (ARC Prize creator)."
author: jona
source: community
source_repo: jona/ycombinator-skills
license: MIT
category: startup-strategy
tags:
- agi
- intelligence
- arc-prize
- machine-learning
- reasoning
allowed-tools:
- view_file
- read_file
- run_command
risk: safe
---
# François Chollet's Framework for AGI

This skill encapsulates François Chollet's theoretical framework for understanding intelligence and the path to AGI, based on his analysis of AI progress and the ARC benchmark.

## Core Concepts

### Two Definitions of Intelligence

**Minsky-style view (task-based):**
- AI performs tasks normally done by humans
- Corporate AGI definition: "model that could perform most economically valuable tasks"
- Focus on capability benchmarks

**McCarthy-style view (adaptation-based):**
- Intelligence is the ability to understand something new on the fly
- Focus on fluid reasoning, not memorized skills
- Measures generalization to novel situations

**Key distinction:** Memorized skills (static, task-specific) vs. fluid general intelligence (dynamic, adaptable).

### The Pre-Training Scaling Era (2020-2024)

**What worked:**
- Self-supervised text modeling at scale
- Predictable benchmark improvements with more compute/data
- Crushing performance on traditional benchmarks

**Why it plateaued for AGI:**
- Benchmarks measured memorized skills, not fluid intelligence
- 50,000x scale-up (2019→2024) yielded only 0%→10% on ARC
- Humans score >95% on ARC with no training
- Confusion between benchmark performance and true understanding

### Test-Time Adaptation Era (2024+)

**Core principle:** Models modify their own behavior dynamically based on specific data encountered during inference.

**Key techniques:**
- Test-time training
- Program synthesis
- Chain-of-thought synthesis
- Self-reprogramming for tasks at hand

**Evidence of progress:**
- OpenAI's O3 (fine-tuned on ARC) achieved human-level ARC performance
- All high-performing ARC approaches use test-time adaptation

### Type 1 vs Type 2 Abstraction

**Type 1 (Perceptual):**
- Pattern recognition from raw sensory data
- Continuous, gradient-based learning
- What deep learning excels at

**Type 2 (Discrete/Programmatic):**
- Symbolic, compositional reasoning
- Discrete program-like structures
- Requires on-the-fly recombination of concepts

**AGI requirement:** Both types working together—deep learning for perception, program search for reasoning.

## Analytical Workflows

### Evaluate AGI Claims

When assessing claims about AGI progress:

1. Identify the benchmark being used
2. Determine if it measures memorized skills or fluid intelligence
3. Check if the model was trained on similar data
4. Ask: "Would performance hold on genuinely novel problems?"
5. Look for test-time adaptation vs. pure pre-training

**Red flags:**
- Claims based solely on traditional benchmarks
- No evaluation on out-of-distribution tasks
- Conflating task performance with general intelligence

### Analyze AI System Architecture

When examining an AI system's potential for general intelligence:

1. Assess pre-training approach
   - What knowledge is baked in?
   - How task-specific is the training?

2. Evaluate test-time capabilities
   - Can the system adapt during inference?
   - Does it use chain-of-thought or program synthesis?
   - Can it modify its behavior for novel problems?

3. Check for both abstraction types
   - Type 1: Perceptual pattern matching
   - Type 2: Discrete symbolic reasoning

4. Determine generalization potential
   - How does it perform on ARC-style tasks?
   - Can it handle problems outside training distribution?

### Assess Intelligence Metrics

When evaluating whether a metric truly measures intelligence:

1. Apply the Chollet criteria:
   - Does it require understanding novel situations?
   - Can it be solved by memorization?
   - Is the solution space too narrow?

2. Check for the "ARC test":
   - Would 50,000x more compute dramatically improve scores?
   - If no, the metric likely measures fluid intelligence
   - If yes, it may just measure knowledge retrieval

3. Consider human baseline:
   - Humans with no training should outperform on true intelligence tests
   - Large gap between human and AI suggests memorization-based approach

## Extended Knowledge & Deep-Dive Guide

For full operational workflows, step-by-step evaluation matrices, analytical templates, and extended source materials:
- Consult [references/deep-dive.md](references/deep-dive.md)
