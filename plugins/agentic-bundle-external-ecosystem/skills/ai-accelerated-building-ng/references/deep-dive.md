# ai-accelerated-building-ng — Complete Reference & Deep Dive

# Andrew Ng: Building Faster with AI

Guidance for applying Andrew Ng's principles on startup execution speed and AI-accelerated development, based on AI Fund's experience building approximately one startup per month.

## Core Thesis

**Execution speed is the strongest predictor of startup success.** AI coding tools enable 10x faster prototyping, shifting bottlenecks from implementation to product management and user feedback.

## AI Stack Layers

Understand where opportunities exist in the AI technology stack:

```
Layer 5: Applications        ← Biggest opportunities (must generate revenue for all layers below)
Layer 4: Orchestration       ← New layer enabling easier app building (agentic coordination)
Layer 3: Foundation Models   ← High PR/hype but dependent on app layer revenue
Layer 2: Cloud Infrastructure
Layer 1: Semiconductors
```

**Key insight:** Media focuses on technology layers, but by definition, the application layer must generate the most value to sustain the entire stack.

## Agentic AI Workflows

### Why Agentic Approaches Matter

Traditional LLM usage forces linear generation (first word to last, no backspace). Humans don't write well this way—neither does AI.

**Agentic workflow pattern:**
1. Generate outline/plan
2. Conduct research (web fetches, document retrieval)
3. Write first draft
4. Self-critique the draft
5. Revise based on critique
6. Iterate until quality threshold met

This iterative loop is slower but produces dramatically better results.

### When to Use Agentic Workflows

Apply agentic approaches for:
- Complex compliance document analysis
- Medical diagnosis reasoning
- Legal document interpretation
- Any task requiring research + synthesis + revision

### Implementing Agentic Workflows

```
┌─────────────────────────────────────────────┐
│           Agentic Workflow Loop             │
├─────────────────────────────────────────────┤
│                                             │
│    ┌──────────┐                             │
│    │  PLAN    │ ← Define task, create       │
│    └────┬─────┘   outline or approach       │
│         │                                   │
│         ▼                                   │
│    ┌──────────┐                             │
│    │ RESEARCH │ ← Fetch context, retrieve   │
│    └────┬─────┘   documents, web search     │
│         │                                   │
│         ▼                                   │
│    ┌──────────┐                             │
│    │  DRAFT   │ ← Generate initial output   │
│    └────┬─────┘                             │
│         │                                   │
│         ▼                                   │
│    ┌──────────┐                             │
│    │ CRITIQUE │ ← Self-evaluate against     │
│    └────┬─────┘   requirements              │
│         │                                   │
│         ▼                                   │
│    ┌──────────┐     No                      │
│    │ GOOD     │────────┐                    │
│    │ ENOUGH?  │        │                    │
│    └────┬─────┘        │                    │
│         │ Yes          │                    │
│         ▼              │                    │
│    ┌──────────┐   ┌────┴─────┐              │
│    │  OUTPUT  │   │  REVISE  │──────┐       │
│    └──────────┘   └──────────┘      │       │
│                        ▲            │       │
│                        └────────────┘       │
│                                             │
└─────────────────────────────────────────────┘
```

## Startup Execution Speed Principles

### Speed as Success Predictor

High-velocity execution correlates with startup success. AI Fund observes this across their portfolio of monthly startup launches.

### AI-Enabled Acceleration

Current AI coding tools enable approximately **10x faster prototyping**:
- Rapid MVP development
- Faster iteration cycles
- Reduced time from idea to testable product

### Shifted Bottlenecks

When implementation accelerates 10x, new bottlenecks emerge:
1. **Product management decisions** - What to build becomes more important than how fast you can build
2. **User feedback collection** - Getting real user input becomes the limiting factor
3. **Idea validation** - Testing concrete ideas matters more than coding speed

### Best Practices for Speed

1. **Start with concrete ideas** - Vague concepts slow execution; specific features accelerate it
2. **Use AI coding assistants** - Leverage tools for rapid prototyping
3. **Iterate in 2-3 month cycles** - Best practices change frequently; stay current
4. **Focus on customer conversations** - Speed includes talking to users, not just writing code
5. **Design features and pricing early** - AI Fund teams do this alongside coding

## Evaluating AI Startup Opportunities

### Application Layer Focus

When evaluating where to build:

| Layer | Opportunity Size | Competition | Barrier |
|
