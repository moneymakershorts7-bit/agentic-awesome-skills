#!/usr/bin/env python3
"""
free_for_dev_indexer.py: Indexer and Catalog Generator for Free Developer Tools
Parses ripienaar/free-for-dev and associated developer tool repositories into
structured JSON and browsable Markdown catalogs, with automatic project tagging
and stack recommendation scoring.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from _project_paths import find_repo_root
    REPO_ROOT = find_repo_root(__file__)
except Exception:
    REPO_ROOT = Path(__file__).resolve().parents[2]

UPSTREAM_README_URL = "https://raw.githubusercontent.com/ripienaar/free-for-dev/master/README.md"
INDEX_JSON_PATH = REPO_ROOT / "data" / "free_for_dev_index.json"
CATALOG_MD_PATH = REPO_ROOT / "docs" / "free_for_dev" / "CATALOG.md"

# Project tag mappings for stack recommendations
TAG_KEYWORDS: Dict[str, List[str]] = {
    "ai_agents": ["ai", "llm", "gpt", "gemini", "claude", "agent", "prompt", "nlp", "speech", "whisper", "vision", "vector", "embedding", "rag", "langchain", "llamaindex", "composio"],
    "serverless_edge": ["serverless", "edge", "worker", "cloudflare", "lambda", "functions", "deno", "wasm", "low-latency", "cdn", "fastly", "netlify", "vercel"],
    "database_storage": ["database", "postgres", "sql", "sqlite", "mysql", "mongodb", "redis", "storage", "s3", "blob", "bucket", "vector", "qdrant", "pinecone", "weaviate", "supabase", "neon", "turso", "upstash"],
    "devops_ci": ["ci", "cd", "docker", "container", "kubernetes", "build", "pipeline", "github actions", "deploy", "git", "artifact", "registry", "test", "automation"],
    "observability": ["monitoring", "logs", "telemetry", "tracing", "metrics", "alert", "apm", "uptime", "status page", "sentry", "grafana", "prometheus", "axiom", "datadog", "better stack"],
    "auth_security": ["auth", "authentication", "authorization", "oauth", "jwt", "saml", "sso", "security", "pki", "ssl", "tls", "secrets", "vault", "firewall", "waf", "clerk", "doppler"],
    "fullstack_web": ["frontend", "backend", "react", "nextjs", "vue", "svelte", "api", "rest", "graphql", "websocket", "webhook", "cms", "forms", "email", "payment", "stripe"],
}


def slugify(text: str) -> str:
    """Convert a name to a clean, lowercase URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    return text.strip("-")


def fetch_upstream_readme(url: str = UPSTREAM_README_URL) -> str:
    """Fetch raw markdown from GitHub repository."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "FreeForDev-Indexer/1.0 (Autonomous Coding Agent)"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_free_for_dev_markdown(content: str) -> List[Dict[str, Any]]:
    """Parse Markdown content of free-for-dev into structured tool records."""
    entries: List[Dict[str, Any]] = []
    current_cat = "General"
    current_subcat = ""
    lines = content.splitlines()
    in_toc = False

    item_regex = re.compile(r"^\s*\*\s*\[([^\]]+)\]\((https?://[^\)]+)\)(?:\s*[-–—:]\s*(.*))?$")
    subitem_regex = re.compile(r"^\s{2,}\*\s*([^-–—:]+)(?:[-–—:]\s*(.*))?$")

    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith("## table of contents"):
            in_toc = True
            continue
        if in_toc and line.startswith("## "):
            in_toc = False

        if in_toc:
            continue

        if line.startswith("## "):
            current_cat = line[3:].strip()
            current_subcat = ""
            continue
        elif line.startswith("### "):
            current_subcat = line[4:].strip()
            continue

        m = item_regex.match(line)
        if m:
            name = m.group(1).strip()
            url = m.group(2).strip()
            desc = m.group(3).strip() if m.group(3) else ""

            # Extract tags & properties
            tags = extract_tags(name, current_cat, current_subcat, desc)
            no_cc = bool(re.search(r"no credit card|no cc|free tier without card", desc, re.IGNORECASE))
            has_api = bool(re.search(r"\bapi\b|rest|graphql|sdk", desc + " " + name, re.IGNORECASE))
            has_free_tier = True

            entry = {
                "id": slugify(name),
                "name": name,
                "url": url,
                "category": current_cat,
                "subcategory": current_subcat,
                "description": desc,
                "tags": tags,
                "no_credit_card": no_cc,
                "has_api": has_api,
                "recommended_for": infer_project_recommendations(tags),
                "last_verified": datetime.date.today().isoformat(),
            }
            entries.append(entry)
        elif stripped.startswith("*") and entries and not entries[-1]["description"]:
            sub_m = subitem_regex.match(line)
            if sub_m:
                sub_desc = stripped.lstrip("*").strip()
                if entries[-1]["description"]:
                    entries[-1]["description"] += " | " + sub_desc
                else:
                    entries[-1]["description"] = sub_desc
                # Re-compute tags after updating description
                entries[-1]["tags"] = extract_tags(
                    entries[-1]["name"],
                    entries[-1]["category"],
                    entries[-1]["subcategory"],
                    entries[-1]["description"]
                )
                entries[-1]["recommended_for"] = infer_project_recommendations(entries[-1]["tags"])

    return entries


def extract_tags(name: str, category: str, subcategory: str, description: str) -> List[str]:
    """Derive search and tech stack tags from tool metadata and description."""
    text = f"{name} {category} {subcategory} {description}".lower()
    tags: Set[str] = set()

    for stack_name, keywords in TAG_KEYWORDS.items():
        for kw in keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", text):
                tags.add(stack_name)
                tags.add(kw)

    # Specific common platform tags
    specifics = [
        "postgresql", "postgres", "mysql", "sqlite", "redis", "mongodb", "graphql", "rest",
        "cloudflare", "aws", "gcp", "azure", "docker", "kubernetes", "vercel", "netlify",
        "supabase", "sentry", "openai", "gemini", "groq", "clerk", "turso", "neon"
    ]
    for sp in specifics:
        if re.search(r"\b" + re.escape(sp) + r"\b", text):
            tags.add(sp)

    return sorted(list(tags))


def infer_project_recommendations(tags: List[str]) -> List[str]:
    """Map tags to concrete architecture recommendations."""
    recommendations = []
    tag_set = set(tags)
    if "ai_agents" in tag_set or "llm" in tag_set or "vector" in tag_set:
        recommendations.append("AI Coding Agents & Autonomous Pipelines")
    if "serverless_edge" in tag_set or "cloudflare" in tag_set:
        recommendations.append("Edge Serverless & High-Performance Microservices")
    if "database_storage" in tag_set or "postgres" in tag_set or "sqlite" in tag_set:
        recommendations.append("Cloud Databases & Vector Store Persistence")
    if "observability" in tag_set or "monitoring" in tag_set or "logs" in tag_set:
        recommendations.append("Production Observability, APM & Uptime Alerts")
    if "devops_ci" in tag_set or "docker" in tag_set or "github actions" in tag_set:
        recommendations.append("CI/CD Automation, Testing & Build Workflows")
    if "auth_security" in tag_set or "security" in tag_set:
        recommendations.append("Zero Trust Authentication, WAF & Secrets Management")
    if not recommendations:
        recommendations.append("General Developer Productivity & Web Tools")
    return recommendations


def generate_catalog_markdown(entries: List[Dict[str, Any]]) -> str:
    """Generate a clean, structured Markdown catalog grouped by category."""
    lines: List[str] = []
    lines.append("# Free-for-Dev Master Index & Catalog")
    lines.append("")
    lines.append(f"> **Total Indexed Tools:** {len(entries)}  ")
    lines.append(f"> **Last Synchronized:** {datetime.date.today().isoformat()}  ")
    lines.append(f"> **Source Reference:** [ripienaar/free-for-dev](https://github.com/ripienaar/free-for-dev)")
    lines.append("")
    lines.append("An autonomous, curated, and indexed knowledge base of SaaS, PaaS, IaaS, APIs, AI, and developer tools offering free tiers. Maintained automatically by the autonomous Jules Coding Assistant and Agent Maintainer.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Group by category
    cats: Dict[str, List[Dict[str, Any]]] = {}
    for entry in entries:
        cat = entry["category"]
        cats.setdefault(cat, []).append(entry)

    # Table of Contents
    lines.append("## Categories Navigation")
    lines.append("")
    for cat in sorted(cats.keys()):
        anchor = slugify(cat)
        lines.append(f"- [{cat}](#{anchor}) ({len(cats[cat])} tools)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Category Sections
    for cat in sorted(cats.keys()):
        anchor = slugify(cat)
        lines.append(f"## {cat}")
        lines.append("")
        cat_tools = cats[cat]
        for tool in sorted(cat_tools, key=lambda x: x["name"].lower()):
            name = tool["name"]
            url = tool["url"]
            desc = tool["description"]
            subcat = f" *({tool['subcategory']})*" if tool.get("subcategory") else ""
            badges = []
            if tool.get("no_credit_card"):
                badges.append("`No Credit Card`")
            if tool.get("has_api"):
                badges.append("`API`")
            badge_str = (" " + " ".join(badges)) if badges else ""
            
            lines.append(f"### [{name}]({url}){subcat}{badge_str}")
            if desc:
                lines.append(f"{desc}")
            if tool.get("recommended_for"):
                recs = ", ".join(tool["recommended_for"])
                lines.append(f"- **Recommended For:** {recs}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def build_index(force_fetch: bool = False) -> List[Dict[str, Any]]:
    """Build or update the index, saving JSON and Markdown files."""
    INDEX_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_MD_PATH.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Fetching latest free-for-dev dataset from upstream...")
    raw_md = fetch_upstream_readme()
    print(f"[*] Parsing tools and calculating stack tags...")
    entries = parse_free_for_dev_markdown(raw_md)
    print(f"[+] Successfully parsed {len(entries)} developer tools across categories.")

    # Save JSON index
    with open(INDEX_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved structured index to: {INDEX_JSON_PATH}")

    # Generate and save Markdown catalog
    catalog_md = generate_catalog_markdown(entries)
    with open(CATALOG_MD_PATH, "w", encoding="utf-8") as f:
        f.write(catalog_md)
    print(f"[+] Saved browsable catalog to: {CATALOG_MD_PATH}")

    return entries


def load_index() -> List[Dict[str, Any]]:
    """Load existing index from disk or build if missing."""
    if INDEX_JSON_PATH.is_file():
        try:
            with open(INDEX_JSON_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return build_index()


def search_tools(query: str, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Search tools by name, description, tags, or category."""
    q = query.lower().strip()
    results = []
    for e in entries:
        haystack = f"{e['name']} {e['category']} {e['subcategory']} {e['description']} {' '.join(e['tags'])}".lower()
        if q in haystack:
            results.append(e)
    return results


def recommend_for_stack(stack: str, entries: List[Dict[str, Any]], limit: int = 15) -> List[Dict[str, Any]]:
    """Recommend top tools matching a project stack."""
    st = stack.lower().strip()
    matches = []
    for e in entries:
        score = 0
        tag_set = set(e["tags"])
        if st in tag_set:
            score += 3
        if st in e["name"].lower():
            score += 4
        if st in e["category"].lower():
            score += 2
        if st in e["description"].lower():
            score += 1
        if e.get("no_credit_card"):
            score += 1
        if score > 0:
            matches.append((score, e))

    matches.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in matches[:limit]]


def main() -> int:
    parser = argparse.ArgumentParser(description="Free-For-Dev Catalog & Search Indexer")
    parser.add_argument("--update", action="store_true", help="Fetch latest upstream data and regenerate index")
    parser.add_argument("--search", "-s", type=str, help="Search tools by keyword")
    parser.add_argument("--category", "-c", type=str, help="List tools in category")
    parser.add_argument("--recommend", "-r", type=str, help="Get recommendations for a project stack keyword (e.g. postgres, cloudflare, llm, auth)")
    parser.add_argument("--stats", action="store_true", help="Display index statistics")
    parser.add_argument("--json", action="store_true", help="Output results in raw JSON format")

    args = parser.parse_args()

    if args.update or not INDEX_JSON_PATH.is_file():
        entries = build_index(force_fetch=True)
    else:
        entries = load_index()

    if args.stats:
        cats: Dict[str, int] = {}
        for e in entries:
            cats[e["category"]] = cats.get(e["category"], 0) + 1
        print(f"Total Tools Indexed: {len(entries)}")
        print(f"Total Categories: {len(cats)}")
        print("\nBreakdown by Category:")
        for cat, count in sorted(cats.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {cat}: {count} tools")
        return 0

    if args.search:
        results = search_tools(args.search, entries)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\nFound {len(results)} tools matching '{args.search}':\n")
            for r in results[:25]:
                cc = " [No Credit Card]" if r.get("no_credit_card") else ""
                print(f"• {r['name']} ({r['category']}){cc}")
                print(f"  URL: {r['url']}")
                print(f"  Free Tier: {r['description'][:140]}...")
                print()
        return 0

    if args.recommend:
        results = recommend_for_stack(args.recommend, entries)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\nTop Free Tools Recommended for Stack: '{args.recommend}':\n")
            for r in results:
                cc = " [No Credit Card]" if r.get("no_credit_card") else ""
                print(f"• {r['name']} ({r['category']}){cc}")
                print(f"  URL: {r['url']}")
                print(f"  Free Tier: {r['description']}")
                print(f"  Relevance: {', '.join(r.get('recommended_for', []))}")
                print()
        return 0

    if args.category:
        results = [e for e in entries if args.category.lower() in e["category"].lower()]
        print(f"\nTools in Category '{args.category}' ({len(results)} found):\n")
        for r in results:
            print(f"• {r['name']} - {r['url']}")
            print(f"  {r['description']}")
            print()
        return 0

    print(f"Free-for-Dev Index ready ({len(entries)} tools). Use --search, --recommend, --category, or --stats.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
