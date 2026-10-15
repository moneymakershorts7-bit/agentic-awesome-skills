# ai-scientific-discovery-jumper — Complete Reference & Deep Dive

# AI for Scientific Discovery

Principles and workflows for building AI systems that accelerate scientific research, derived from the development of AlphaFold at DeepMind.

## Core Principles

### Research Ideas as Multipliers

Research and architectural innovation multiply the value of data and compute rather than adding linearly.

**Key insight**: AlphaFold2 trained on 1% of available data outperformed AlphaFold1 trained on 100% of data. This demonstrates that ideas can provide 100x leverage over data alone.

**Implication**: When building ML systems for scientific domains, prioritize research iteration over data acquisition. Most compute budget should account for failed research iterations, not final model training.

### Many Mid-Scale Ideas

Breakthroughs come from accumulating many medium-sized innovations, not one revolutionary idea.

**Key insight**: In AlphaFold ablation studies, no single component explained more than 10% of the system's improvement. The breakthrough emerged from combining numerous architectural innovations.

**Implication**: Avoid searching for a single "magic bullet" solution. Instead, systematically develop and integrate multiple complementary improvements.

### Biological Relevance Threshold

Real-world impact requires crossing a threshold where predictions become useful to domain experts who don't care about ML metrics.

**Key insight**: Experimental biologists adopted AlphaFold not because of benchmark scores, but because predictions matched their private experimental data at a useful accuracy level.

**Implication**: Define success by domain expert utility, not benchmark performance. Track adoption signals from target users, not just technical metrics.

## Workflow: Designing Scientific AI Systems

### Step 1: Understand the Domain Problem

1. Identify the core scientific question (e.g., "How does a linear amino acid chain fold into a 3D structure?")
2. Map existing experimental methods and their limitations
3. Determine what accuracy level constitutes "useful" for practitioners
4. Identify available data sources and their characteristics

### Step 2: Evaluate Off-the-Shelf Approaches

1. Test standard ML architectures on the problem
2. Document where generic approaches fail or underperform
3. Identify domain-specific constraints that require custom solutions
4. Establish baseline performance for comparison

**Warning**: Off-the-shelf ML approaches are typically insufficient for scientific breakthroughs. Expect to develop domain-specific innovations.

### Step 3: Invest in Research Iteration

1. Allocate majority of compute budget to experimentation, not final training
2. Design fast iteration cycles to test architectural hypotheses
3. Track ideas systematically—expect most to fail
4. Look for compounding improvements from combining innovations

### Step 4: Validate with Blind Benchmarks

Use held-out test sets where answers are unknown to prevent overfitting:

```
Validation Strategy:
├── Training data: Known structures (e.g., Protein Data Bank)
├── Validation data: Subset of known structures, held out
└── Blind test: Problems with unpublished answers
    └── Example: CASP competition (biennial, ~100 proteins, answers unreleased)
```

**Critical**: True capability can only be measured on problems where answers are unknown to everyone, including system developers.

### Step 5: Cross the Relevance Threshold

1. Identify domain experts willing to test against their private data
2. Track word-of-mouth adoption signals
3. Measure whether users validate predictions independently
4. Monitor for emergent use cases you didn't anticipate

## Workflow: Releasing Scientific AI Tools

### Accessibility Over Capability

A tool's impact depends more on ease of access than raw capability.

**Example**: AlphaFold's database of 200 million pre-computed predictions drove adoption far more than open-source code alone.

### Release Strategy Checklist

```
□ Code release (minimum viable)
  - Open source the model and training code
  - Provide documentation for technical users

□ Pre-computed results (high impact)
  - Generate predictions for common use cases
  - Host accessible database
  - Enable non-technical users to benefit

□ API access (broader reach)
  - Remove computational barriers
  - Enable integration into existing workflows

□ User interface (maximum accessibility)
  - Build tools for domain experts without ML expertise
  - Focus on their workflow, not your architecture
```

### Anticipate Emergent Capabilities

Power users will discover capabilities you didn't design for.

**Example**: Protein interaction prediction emerged from AlphaFold 2 days after release—a capability the team hadn't explicitly built or tested.

**Action**: After release, monitor novel use cases and validate whether they work reliably.

## Decision Framework: Data vs Research Investment

When allocating resources between data acquisition and research:

```
Prioritize DATA when:
├── Problem is well-understood
├── Standard architectures perform reasonably
├── Diminishing returns not yet observed
└── Data collection is feasible and affordable

Prioritize RESEARCH when:
├── Off-the-shelf approaches fundamentally fail
├── Domain constraints require custom solutions
├── Data is expensive or limited
└── Existing approaches hit performance ceiling
```

**Default bias**: Lean toward research investment. The AlphaFold case demonstrates that architectural innovation can provide orders of magnitude more value than data scaling.

## Validation Checklist for Scientific AI

Before claiming a system works for real-world use:

```
□ Blind benchmark validation
  - Test on problems with unknown answers
  - Use established domain competitions if available
  - Avoid overfitting to published test sets

□ Ablation studies
  - Remove each component systematically
  - Measure contribution to overall performance
  - Verify no single idea explains >50% of improvement

□ Domain expert validation
  - Find practitioners with private test data
  - Track whether they adopt the tool
  - Monitor word-of-mouth signals

□ Relevance threshold assessment
  - Define "useful" accuracy for domain experts
  - Measure whether system crosses this threshold
  - Distinguish benchmark improvement from practical utility
```

## Key Concepts Reference

| Concept | Definition | Relevance |
|
