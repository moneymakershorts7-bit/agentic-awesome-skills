# software-paradigms-karpathy — Complete Reference & Deep Dive

# Software Is Changing (Again) - Karpathy Framework

This skill provides Andrej Karpathy's framework for understanding the fundamental shift in how software is written and deployed in the AI era.

## Core Mental Model: Three Software Paradigms

### Software 1.0: Traditional Code
- **What it is**: Human-written instructions (Python, C++, JavaScript, etc.)
- **How it's created**: Developers write explicit logic
- **Where it lives**: GitHub, traditional repositories
- **Example**: Writing Python to classify sentiment with explicit rules

### Software 2.0: Neural Network Weights
- **What it is**: Parameters of trained neural networks
- **How it's created**: Curate datasets → run optimizer → produce weights
- **Where it lives**: Hugging Face (the "GitHub of Software 2.0"), Model Atlas
- **Example**: Training a neural network on labeled sentiment data
- **Key insight**: You don't write this code directly; you tune it through data

### Software 3.0: LLM Prompts
- **What it is**: Natural language instructions that program LLMs
- **How it's created**: Write prompts in English (or other natural languages)
- **Where it lives**: Embedded in applications, prompt libraries
- **Example**: Few-shot prompting an LLM with sentiment examples
- **Key insight**: Programming computers in our native language

## Paradigm Selection Guide

Determine which paradigm to use for a given task:

### Use Software 1.0 (Traditional Code) When:
- Logic is deterministic and well-defined
- Performance/latency is critical
- Behavior must be exactly reproducible
- Compliance requires auditable logic
- The problem has clear algorithmic solutions

### Use Software 2.0 (Neural Networks) When:
- Pattern recognition is required (images, audio, signals)
- Training data is abundant and high-quality
- Fixed-function transformation is needed (image → categories)
- Latency requires optimized, compiled models
- The task is well-scoped and doesn't require reasoning

### Use Software 3.0 (LLM Prompts) When:
- Flexibility and generalization matter
- Tasks require reasoning or common sense
- Rapid iteration is more important than optimization
- The problem involves natural language understanding
- You need to handle edge cases gracefully

## The LLM as Operating System Mental Model

Karpathy frames LLMs as a new kind of operating system, comparable to computing circa 1960s:

```
Traditional OS                    LLM "OS"
─────────────────────────────────────────────────────
CPU                          →    LLM inference engine
RAM                          →    Context window
Disk storage                 →    Training data / weights
Programs                     →    Prompts
System calls                 →    Tool use / function calling
Multi-tasking                →    Agentic loops
```

### Implications of This Model:
- Context window is precious (like early RAM limitations)
- Prompt engineering is systems programming
- Tool use extends capabilities (like syscalls extend programs)
- We're all learning to "program" this new OS together

## Practical Framework: Analyzing a Software Task

When approaching any software task, evaluate across all three paradigms:

### Step 1: Characterize the Task
```
Questions to ask:
- Is the input/output well-defined or open-ended?
- How much does context/reasoning matter?
- What's the latency requirement?
- How often will the logic need to change?
- What data is available for training?
```

### Step 2: Map to Paradigm Strengths

| Characteristic | Best Paradigm |
|
