---
name: markup-master
description: Enterprise-grade autonomous engineering platform and agent orchestrator specialized in Markup, Notation, Data Interchange and Structural Schemas. Powered by an Orchestrator-Worker Architecture with 4 domain workers and 1 independent adversarial verifier.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
license: Apache-2.0
---

# `markup-master`: Autonomous Markup, Notation & Schema Platform

`markup-master` is an enterprise-grade autonomous engineering platform and agent orchestrator specialized in **Markup, Notation, Data Interchange and Structural Schemas** (HTML5, JSON, XML, CommonMark, YAML, TOML, CSV, and SVG) located at `/home/npirela/markup-master`.

The platform rejects both the *Monolithic God-Agent* and *Chatty Role-Playing Committee* anti-patterns through a strict **Orchestrator-Worker Architecture** with **Maker/Checker Orthogonality**.

---

## 1. Non-Negotiable Invariants

> [!IMPORTANT]
> Whenever designing, modifying, refactoring, authoring, or validating markup, data schemas, or technical documentation, the agent **MUST ALWAYS** invoke and adhere to `markup-master`.

1. **Semantic Hierarchy**: Eradicate div and span soup. Enforce semantic milestones (`<main>`, `<nav>`, `<article>`, `<section>`, `<header>`, `<footer>`).
2. **WCAG 2.2 AA Accessibility Invariant**: Zero axe-core critical or serious violations. Headings must follow a logical hierarchy with a single `<h1>` without level skips. All interactive controls require computable accessible names.
3. **Cumulative Layout Shift (CLS) Eradication**: All `<img>`, `<video>`, and `<iframe>` elements must declare explicit `width` and `height` attributes or CSS aspect ratios.
4. **Strict Schema Encapsulation**: Every JSON Schema Draft 2020-12 object definition must declare `additionalProperties: false` or `unevaluatedProperties: false` to eliminate property injection.
5. **64-bit Integer & IEEE 754 Precision**: Numbers exceeding safe integer bounds ($|n| > 2^{53}-1$) must be serialized as strings in JSON.
6. **YAML Determinism & Tag Safety**: Strict double-quoting of boolean-like strings (`"yes"`, `"no"`, `"on"`, `"off"`). Total prohibition of unsafe custom tags (`!ruby/object`, `!!python/object`).
7. **CSV Formula Injection Sanitization (CWE-1236)**: Any cell beginning with `=`, `+`, `-`, `@`, `|`, or `%` must be prepended with a single quote (`'`) to disable spreadsheet formula execution.
8. **XXE & Billion Laughs Defense**: Total prohibition of external entity resolution (`SYSTEM` and `PUBLIC`) and DTD parameter entities. Enforce entity expansion recursion caps.
9. **SVG Sanitization**: Strip `<script>`, `on*` event handlers, `javascript:` URIs, and `<foreignObject>` from SVG documents. Enforce responsive `viewBox`.
10. **Progressive Disclosure**: Technical documentation and `SKILL.md` root files must remain strictly under 300 lines, delegating deep reference matrices to `references/`.
11. **Adversarial Gate with Unconditional Veto Power**: Agent 5 (`verifier-qa-auditor`) holds unconditional veto power over all PRs.
12. **AST Roundtrip Idempotency**: $Parser(Serializer(AST)) \equiv AST$.

---

## 2. Specialized Agent Directory

| Agent ID | Role | Core Domain & Invariants | Key Specifications |
| :--- | :--- | :--- | :--- |
| **`html-a11y-architect`** | Semantic HTML & Web A11y Architect | HTML5, WAI-ARIA, WCAG 2.2 AA. Single `<h1>`, valid nesting, zero axe-core violations, explicit image dimensions. | W3C HTML 5.3, WCAG 2.2 |
| **`schema-data-engineer`** | Schema, Data Interchange & Tabular Specialist | JSON, JSON Schema Draft 2020-12, YAML 1.2, TOML 1.0, CSV. `additionalProperties: false`, Norway problem fix, formula escaping. | RFC 8259, JSON Schema, RFC 4180 |
| **`xml-svg-specialist`** | XML, SVG & Hierarchical Document Specialist | W3C XML 1.0, XSD 1.1, SVG 2.0. XXE defense, Billion Laughs mitigation, SVG script and event handler sanitization, `viewBox`. | XML 1.0, XSD 1.1, W3C SVG 2.0 |
| **`markdown-ast-engineer`** | Markdown, AST & Technical Docs Engineer | CommonMark v0.31.2, GFM tables, Frontmatter, AST. Progressive disclosure (<300 lines), aligned pipe tables, verified anchors. | CommonMark, GFM Spec |
| **`verifier-qa-auditor`** | Independent Adversarial Verification Agent | Independent gatekeeper with **unconditional veto power**. Conformance, axe-core A11y, security bomb and XXE checks, AST roundtrip idempotency. | W3C Nu Validator, axe-core |

---

## 3. Operational CLI Protocols

Use `markup-master` (available globally in PATH) or the Python helper `python3 ~/.agents/skills/markup-master/scripts/markup_master_cli.py`:

### A. Autonomous Orchestration (Worker + Verifier Loop)
Decomposes target files into bounded slices, delegates to specialized notation workers, verifies via Agent 5, and applies self-healing:
```bash
markup-master orchestrate index.html schema.json --write
```

### B. Independent Adversarial Verification Gate
Executes 4 verification gates (Conformance, Accessibility, Security, AST Roundtrip Idempotency):
```bash
markup-master verify index.html config.yaml
```

### C. Exact Standards Corpus Search (BM25 Engine)
Search offline W3C, IETF, and CommonMark specifications with line-accurate citations:
```bash
markup-master search-corpus --query "XXE external entity injection"
```

### D. Documentation Freshness Cadence Audit
Inspect cryptographic hashes and verify the 30-day freshness schedule:
```bash
markup-master check-docs-cadence
```

### E. 38+ FOSS Toolchain Matrix Inspection
Catalog and inspect FOSS markup tools and fallback AST engines:
```bash
markup-master toolchain
```

---

## 4. Deep Reference Library

- `references/agent_contracts.md`: Detailed Task + Playbook JSON contracts, schema specifications, and FSM transition rules.
- `references/toolchain_matrix.md`: Exhaustive guide to 38+ FOSS markup tools across 6 operational categories with install recipes.
- `references/troubleshooting_playbook.md`: Diagnostic runbooks for WCAG color contrast, XXE attacks, JSON Schema leaks, and CSV formula escapes.
