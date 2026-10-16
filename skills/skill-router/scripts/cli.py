#!/usr/bin/env python3
import sys
import os
import argparse
import json

# Ensure scripts dir is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from skill_router_engine import ProductionHierarchicalEngine

def main():
    parser = argparse.ArgumentParser(
        description="Hierarchical Skill & Tool Router: Instant sub-millisecond capability discovery for AI agents."
    )
    parser.add_argument("query", nargs="*", help="Natural language query describing task or intent")
    parser.add_argument("--top-k", type=int, default=5, help="Number of recommendations to return (default: 5)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON for agent automation")
    parser.add_argument("--explain", action="store_true", help="Include domain scoring and multi-domain union details")
    parser.add_argument("--enforce", action="store_true", help="Exit 0 if skills resolved, exit 1 if no skills found (gate enforcement)")
    parser.add_argument("--prompt", action="store_true", help="Emit markdown alert context block for agent reasoning")
    args = parser.parse_args()

    query_str = " ".join(args.query).strip()
    if not query_str:
        parser.print_help()
        sys.exit(0)

    engine = ProductionHierarchicalEngine()
    res = engine.route(query_str, top_k=args.top_k)

    if args.enforce:
        if not res.get("recommendations"):
            print("FALLBACK_AUTHORIZED: No canonical skill registered. Primitive implementation permitted.")
            sys.exit(1)
        else:
            top_skill = res["recommendations"][0]["id"]
            print(f"CANONICAL_SKILL_RESOLVED: {top_skill}")
            sys.exit(0)

    if args.json:
        print(json.dumps(res, indent=2))
        return

    if args.prompt:
        recs = res.get("recommendations", [])
        if not recs:
            print(f"<!-- SKILL_ROUTER: No canonical skills matched for '{query_str}'. Fallback permitted. -->")
        else:
            print(f"<!-- SKILL_ROUTER RESOLUTION :: Phase 0 Gate PASS (Primary Domain: {res['primary_domain']}) -->")
            print("> [!IMPORTANT]")
            print(f"> **MANDATORY DOMAIN SKILLS RESOLVED FOR:** `{query_str}`")
            for i, r in enumerate(recs, 1):
                skill_id = r["id"]
                score = r["score"]
                skill_path = os.path.expanduser(f"~/.agents/skills/{skill_id}/SKILL.md")
                print(f"> {i}. **{skill_id}** (Score: {score:.1f}) -> [`{skill_id}`](file://{skill_path})")
            print("> **Directive:** Adopt the pipeline, scripts, and conventions in the resolved skills. DO NOT write ad-hoc low-level primitive scripts (e.g. PIL, raw subprocess).")
        return

    print(f"\n🎯 [Skill Router] Query: \"{query_str}\"")
    print(f"📁 Primary Domain: {res['primary_domain']}")
    if res.get("multi_domain_union_active"):
        print(f"🌐 Multi-Domain Union Active: {', '.join(res['active_domains'])}")

    print(f"\n⚡ Recommended Capabilities (Top {len(res['recommendations'])}):")
    for i, r in enumerate(res["recommendations"], 1):
        type_badge = "🛠️ TOOL " if r["type"] == "mcp_tool" else "📦 SKILL"
        print(f"  {i}. {type_badge} [{r['id']}] (Score: {r['score']})")
        print(f"     Subcategory: {r['domain']}/{r['subcat']}")
        if r["description"]:
            print(f"     Description: {r['description'][:100]}...")

    if args.explain:
        print("\n🔍 Domain Ranking Details:")
        for dom, sc in res["ranked_domains"]:
            print(f"  - {dom}: {sc:.2f} pts")

if __name__ == "__main__":
    main()
