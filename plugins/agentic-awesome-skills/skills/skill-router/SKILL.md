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

## Architecture & Routing Engines

The skill router supports two complementary routing paradigms:

### 1. Hierarchical Production Engine (3-Layer Taxonomy)
Uses a 3-tier progressive disclosure model based on AnyTool and ToolRerank:
- **Layer 0 (Root Index):** 10 canonical domains (~754 tokens) embedded in base prompt context.
- **Layer 1 (Subcategory Branch):** Dynamic exploration of functional branches on demand.
- **Layer 2 (Leaf Activation):** Direct loading of the exact `SKILL.md` or MCP tool schema.
- **MMR Diversity Re-ranking:** Submodular penalty ($\lambda=0.65$, max 2 items per family) preventing verb swarming.

### 2. Adaptive MirrorMoE Engine (`adaptive_mirrormoe_skill_router.py`)
Inspired by *MirrorMoE* (arXiv:2610.22353, Li et al., ETH Zurich / HKU / MPI-IS / WU Vienna):
- **Stage 1 (Lexical Retrieval Beam):** SQLite FTS5 BM25 candidate filtering evaluating top $N=30$ candidate skills in $<1$ ms.
- **Stage 2 (Dual-Head Attention & Mirroring):** Multi-representation scaled dot-product attention across Domain, Functionality, and Context orthogonal heads. Computes standard softmax ($\xi_i$) and sign-negated mirrored routing ($\zeta_i \propto 1/\xi_i$).
- **Stage 3 (Dynamic Effective Capacity & Token Pruning):** Evaluates exponential Shannon entropy:
  $$K_{\mathsf{eff}} = \exp\left(-\sum_{i \in \mathcal{A}} \bar{\xi}_i \ln \bar{\xi}_i\right)$$
  Enforces dynamic pruning threshold $T_{\text{prune}} = \gamma / K_{\mathsf{eff}}$. Simple tasks automatically collapse to 1 expert (saving 80% prompt tokens and eliminating distractor noise), while multi-domain compositions preserve 3–5 experts.
- **CLI Usage:**
  ```bash
  python3 scripts/adaptive_mirrormoe_skill_router.py "<task query>" --top-k 5
  ```