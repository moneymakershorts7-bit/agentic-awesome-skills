# claude-code-guidance-cherny — Complete Reference & Deep Dive

# Claude Code Best Practices

Guidance for using Claude Code effectively and understanding its design philosophy, based on insights from Boris Cherny, the creator of Claude Code.

## Core Philosophy

### Build for T+6 Months

Design and configure for the model six months from now, not today's limitations:

- Avoid over-engineering workarounds for current model weaknesses
- Expect model improvements to obsolete most scaffolding code
- Treat compensatory instructions in CLAUDE.md as temporary

### Blatant Demand Principle

Only optimize behaviors users already perform:

- Observe what you do manually and repeatedly
- Make existing workflows easier, don't invent new ones
- If you're not already doing something manually, Claude Code won't magically make you do it

### Scaffolding is Tech Debt

All code and configuration compensating for model limitations is temporary:

- Expect to delete or rewrite within 6 months
- Don't over-invest in workarounds
- Model improvements typically provide 10-20% gains that obsolete previous scaffolding

## CLAUDE.md Configuration

### Keep It Minimal

```markdown
# Project: [Name]

## Context
[One paragraph describing what this project does]

## Key Patterns
- [Pattern 1]: [Brief explanation]
- [Pattern 2]: [Brief explanation]

## Preventable Mistakes
- [Mistake to avoid]
- [Another mistake to avoid]

## Commands
- Build: `[command]`
- Test: `[command]`
- Deploy: `[command]`
```

### When to Delete and Start Fresh

Delete CLAUDE.md and restart when:

- File exceeds ~500 lines
- Instructions contradict each other
- Many instructions address obsolete model limitations
- You notice Claude ignoring parts of the file

### What to Add Immediately

Add to CLAUDE.md when you notice:

- Repeated mistakes in PR reviews
- Project-specific conventions Claude keeps missing
- Build or test commands that require explanation

### What to Avoid

Do not add:

- General coding best practices (Claude already knows these)
- Verbose explanations of obvious patterns
- Instructions for problems that newer models handle automatically

## Plan Mode

### What It Is

Plan mode is a single prompt instruction that prevents Claude from writing code immediately:

```
Please think through this problem step by step without writing code yet.
```

### When to Use Plan Mode

Use for approximately 80% of sessions, especially:

- Complex tasks with multiple components
- Tasks requiring architectural decisions
- Debugging sessions where root cause is unclear
- Unfamiliar codebases or domains

### When to Skip Plan Mode

Skip for:

- Trivial changes (typo fixes, simple renames)
- Well-defined tasks with clear implementation
- Follow-up work where plan already exists

### Implementing Automatic Plan Mode

Add to CLAUDE.md for complex projects:

```markdown
## Default Behavior
For any task involving more than a single file change, start by outlining the approach before writing code.
```

## Sub-Agent Workflows

### Calibrating Agent Count

Match parallelism to task difficulty:

| Task Type | Agents | Example |
|
