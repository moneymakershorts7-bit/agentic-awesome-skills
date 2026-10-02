# Chapter and Artifact Templates

Detailed specifications for generating chapters, glossary, patterns, and cheatsheets.

## Chapter File Structure

Each chapter in `chapters/` must follow this structure:

```markdown
# Chapter <N> — <Title>

<One-line core premise of the chapter>

## Key Concepts & Mental Models
- **<Concept Name>**: <definition and operational mechanics>

## Actionable Principles
1. **<Rule Name>**: <practical instruction and applicability conditions>

## Step-by-Step Techniques
### <Technique Name>
1. <Step 1>
2. <Step 2>

## Anti-Patterns & Pitfalls
- **<What to avoid>**: <why it fails and remediation>

## Worked Example
*(Reconstruct one concrete example the author works through)*

## Reference Tables
*(Reproduce comparison matrices, parameter tables, or decision guides)*
```

## Glossary and Index Guidelines

- `glossary.md`: Alphabetical list of all named frameworks, terms, and definitions with chapter citations.
- `patterns.md`: Catalog of actionable techniques, categorized by use case.
- `cheatsheet.md`: High-density reference tables and decision trees.
