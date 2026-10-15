---
name: skill-router
description: "Hierarchical intent router and capability discovery engine for agent skills and MCP tools. Use when unsure which skill or tool to invoke, or to dynamically resolve capabilities with zero prompt token bloat."
allowed-tools:
  - run_command
category: agent-orchestration
risk: safe
source: self
date_added: "2026-10-15"
author: Deepmind Antigravity Pair
---

# Skill & Tool Router (Hierarchical Index Tree)

Fast, deterministic 3-layer capability router for 3,524 installed skills and MCP tools based on AnyTool (arXiv:2402.04253), ToolRerank (arXiv:2403.06551), and MCP-Zero.

---

## When to Use

Use this skill when:
- You need to discover or select the best skill or tool for a user request across 3,500+ capabilities without overloading prompt context.
- The user's task is vague, complex, or spans multiple domains (e.g. "Build high-throughput video streaming in Rust on AWS with HIPAA compliance").
- You want to retrieve relevant `SKILL.md` paths or MCP tools dynamically.

---

## How to Use

### 1. CLI Invocation (Fastest)
Run the installed executable CLI:
```bash
skill-router "<task or user query>"
```

For JSON output suited for programmatic agent parsing:
```bash
skill-router "<task or user query>" --json --top-k 5
```

For domain scoring details and multi-domain union explanation:
```bash
skill-router "<task or user query>" --explain
```

### 2. Python Engine API
```python
import sys
sys.path.insert(0, "/home/npirela/.agents/skills/skill-router/scripts")
from skill_router_engine import ProductionHierarchicalEngine

engine = ProductionHierarchicalEngine()
result = engine.route("speed up slow postgres queries and tune connection pool", top_k=5)

# Primary domain and recommendations
print("Domain:", result["primary_domain"])
for rec in result["recommendations"]:
    print(f"[{rec['type']}] {rec['id']} (Score: {rec['score']}) -> {rec['domain']}/{rec['subcat']}")
```

---

## Architecture

The engine uses a 3-tier progressive disclosure model:
1. **Layer 0 (Root Index):** 10 canonical domains (~754 tokens) embedded in base prompt context.
2. **Layer 1 (Subcategory Branch):** Dynamic exploration of functional branches on demand.
3. **Layer 2 (Leaf Activation):** Direct loading of the exact `SKILL.md` or MCP tool schema.

Features:
- **Inverted Posting Index:** Sub-millisecond sparse lookup (< 4ms latency).
- **MMR Diversity Re-ranking:** Submodular penalty ($\lambda=0.65$, max 2 items per family) preventing verb swarming.
- **Two-Tier Namespace Aggregation:** Deterministic MCP server clustering.
- **Multi-Domain Union:** Activates secondary domain candidates when top score differential $< 25\%$.
- **Synonym Expansion:** Normalizes colloquial developer phrasing to formal taxonomy terms.