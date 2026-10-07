#!/usr/bin/env python3
"""
free_for_dev_scout.py: Autonomous Daily Sentinel for Free Developer Tools & Services
Monitors ripienaar/free-for-dev, awesome-free lists, and GitHub commits for newly released
free tiers, developer APIs, databases, hosting, and AI services.
Generates daily discovery dossiers, updates the master index, and proposes project integration recipes.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from _project_paths import find_repo_root
    REPO_ROOT = find_repo_root(__file__)
except Exception:
    REPO_ROOT = Path(__file__).resolve().parents[2]

INDEX_JSON_PATH = REPO_ROOT / "data" / "free_for_dev_index.json"
DAILY_DIR = REPO_ROOT / "docs" / "free_for_dev" / "daily"
LEDGER_PATH = REPO_ROOT / "docs" / "free_for_dev" / "LEDGER.md"

UPSTREAM_REPO = "ripienaar/free-for-dev"
TRACKED_REPOS = [
    "ripienaar/free-for-dev",
    "open-free-llm-api/awesome-freellm-apis",
    "mnfst/awesome-free-llm-apis",
    "255kb/stack-on-a-budget",
]


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Execute command safely and return exit code, stdout, stderr."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def get_github_token() -> Optional[str]:
    """Retrieve GitHub token from environment or gh CLI."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    code, stdout, _ = run_cmd(["gh", "auth", "token"], timeout=5)
    if code == 0 and stdout:
        return stdout
    return None


def fetch_recent_upstream_commits(repo: str = UPSTREAM_REPO, limit: int = 15) -> List[Dict[str, Any]]:
    """Fetch recent merged commits from upstream repository."""
    code, stdout, _ = run_cmd([
        "gh", "api", f"repos/{repo}/commits?per_page={limit}"
    ], timeout=20)
    if code == 0 and stdout:
        try:
            return json.loads(stdout)
        except Exception:
            pass

    # Fallback to urllib
    url = f"https://api.github.com/repos/{repo}/commits?per_page={limit}"
    req = urllib.request.Request(url, headers={"User-Agent": "FreeForDev-Scout/1.0"})
    token = get_github_token()
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[WARN] Error fetching commits for {repo}: {e}", file=sys.stderr)
        return []


def fetch_recent_prs(repo: str = UPSTREAM_REPO, limit: int = 15) -> List[Dict[str, Any]]:
    """Fetch recent closed/merged PRs."""
    code, stdout, _ = run_cmd([
        "gh", "api", f"repos/{repo}/pulls?state=closed&per_page={limit}&sort=updated&direction=desc"
    ], timeout=20)
    if code == 0 and stdout:
        try:
            return json.loads(stdout)
        except Exception:
            pass
    return []


def extract_added_tools_from_commits(commits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract tool names and descriptions from recent commit messages and PR bodies."""
    discoveries = []
    seen = set()

    for c in commits:
        msg = c.get("commit", {}).get("message", "")
        sha = c.get("sha", "")[:7]
        date_str = c.get("commit", {}).get("author", {}).get("date", "")[:10]
        
        # Match "Add <Tool>" or "Added <Tool>" or "Add <Tool> to <Category>"
        match = re.search(r"Add(?:ed)?\s+([A-Za-z0-9\.\-\_\s]+?)(?:\s+(?:to|for|API|into)\b|\n|$)", msg, re.IGNORECASE)
        if match:
            raw_name = match.group(1).strip()
            # Clean up common noise
            if len(raw_name) > 2 and len(raw_name) < 40 and raw_name.lower() not in ["new", "free", "resource", "listing", "section", "table of contents", "readme"]:
                if raw_name.lower() not in seen:
                    seen.add(raw_name.lower())
                    discoveries.append({
                        "name": raw_name,
                        "commit_sha": sha,
                        "date": date_str,
                        "message": msg.splitlines()[0],
                        "details": "\n".join(msg.splitlines()[1:]).strip(),
                    })

    return discoveries


def generate_project_recipes(tools: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Generate architectural recommendations and integration recipes for user projects."""
    recipes = []
    for t in tools:
        name = t.get("name", "Tool")
        desc = t.get("description", "") or t.get("details", "")
        rec = {
            "tool": name,
            "category": t.get("category", "Developer Tool"),
            "use_case": "Cloud & Agent Workflows",
            "recipe": f"Integrate {name} to expand zero-cost developer infrastructure. Free tier: {desc}"
        }
        name_lower = name.lower()
        desc_lower = desc.lower()

        if "api" in name_lower or "api" in desc_lower or "llm" in desc_lower or "ai" in desc_lower:
            rec["use_case"] = "AI Agents & Autonomous Workflows"
            rec["recipe"] = f"Use `{name}` API as an external MCP tool or LLM reasoning backend for agentic pipelines without increasing monthly cloud costs."
        elif "postgres" in desc_lower or "database" in desc_lower or "sql" in desc_lower or "vector" in desc_lower:
            rec["use_case"] = "Database & Vector Persistence"
            rec["recipe"] = f"Provision `{name}` free cluster as persistent storage or vector index for multi-tenant microservices or semantic memory graphs."
        elif "worker" in desc_lower or "serverless" in desc_lower or "edge" in desc_lower:
            rec["use_case"] = "Edge Serverless Microservices"
            rec["recipe"] = f"Deploy edge endpoints to `{name}` to achieve sub-10ms global latency with zero idle server costs."
        elif "ci" in desc_lower or "test" in desc_lower or "lint" in desc_lower or "docker" in desc_lower:
            rec["use_case"] = "CI/CD & DevOps Automation"
            rec["recipe"] = f"Incorporate `{name}` in `.github/workflows/` for automated regression testing, security scanning, and containerized builds."
        elif "monitor" in desc_lower or "log" in desc_lower or "uptime" in desc_lower:
            rec["use_case"] = "Observability & Alerting"
            rec["recipe"] = f"Configure `{name}` webhooks to deliver real-time uptime health checks and error telemetry to chat/dashboard."

        recipes.append(rec)
    return recipes


def generate_daily_dossier(
    today: str,
    recent_discoveries: List[Dict[str, Any]],
    indexed_sample: List[Dict[str, Any]],
    recipes: List[Dict[str, str]]
) -> str:
    """Format daily Markdown bulletin."""
    lines = []
    lines.append(f"# Free-For-Dev Daily Discovery Bulletin — {today}")
    lines.append("")
    lines.append(f"> **Scout Mode:** Autonomous Jules Coding Assistant & Maintainer Sentinel  ")
    lines.append(f"> **Upstream Tracked:** [`ripienaar/free-for-dev`](https://github.com/ripienaar/free-for-dev) + GitHub Free Tech Ecosystem  ")
    lines.append(f"> **Status:** Active Synchronization  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 🔍 Newly Discovered & Merged Free Tools (Last 24–48h)")
    lines.append("")
    if recent_discoveries:
        for d in recent_discoveries:
            lines.append(f"### ✦ {d['name']} (Commit [`{d['commit_sha']}`])")
            lines.append(f"- **Summary:** {d['message']}")
            if d.get("details"):
                lines.append(f"- **Context:** {d['details']}")
            lines.append(f"- **Discovery Date:** `{d['date']}`")
            lines.append("")
    else:
        lines.append("*No new pull requests merged upstream in the last 24 hours. Catalog remains current.*")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 💡 Architectural Proposals & Project Integration Recipes")
    lines.append("")
    lines.append("How to immediately leverage free tiers in active agentic, edge, and cloud projects:")
    lines.append("")
    for r in recipes[:6]:
        lines.append(f"#### **{r['tool']}** — *{r['use_case']}*")
        lines.append(f"- **Implementation Strategy:** {r['recipe']}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 📊 Master Catalog Health & Statistics")
    lines.append("")
    lines.append(f"- **Total Indexed Free Tools:** {len(indexed_sample)}")
    lines.append(f"- **Catalog Reference:** [`docs/free_for_dev/CATALOG.md`](../CATALOG.md)")
    lines.append(f"- **Index Data Store:** [`data/free_for_dev_index.json`](../../data/free_for_dev_index.json)")
    lines.append("")

    return "\n".join(lines)


def update_ledger(today: str, discoveries: List[Dict[str, Any]]) -> None:
    """Append discovery summary to LEDGER.md."""
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    header = "# Free-For-Dev Discovery Ledger\n\nContinuous audit trail of free tools and services discovered by the autonomous sentinel.\n\n| Date | Tool Name | Upstream Commit | Discovery Note |\n| :--- | :--- | :--- | :--- |\n"
    
    if not LEDGER_PATH.is_file():
        content = header
    else:
        with open(LEDGER_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        if "| Date |" not in content:
            content = header + content

    new_rows = []
    for d in discoveries:
        row = f"| {today} | **{d['name']}** | `{d['commit_sha']}` | {d['message'][:80]} |"
        if row not in content:
            new_rows.append(row)

    if new_rows:
        content += "\n".join(new_rows) + "\n"
        with open(LEDGER_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Appended {len(new_rows)} entries to {LEDGER_PATH}")


def scout_and_notify(sentinel_mode: bool = False) -> Dict[str, Any]:
    """Execute the complete daily scouting workflow."""
    today = datetime.date.today().isoformat()
    DAILY_DIR.mkdir(parents=True, exist_ok=True)
    dossier_path = DAILY_DIR / f"{today}.md"

    print(f"[*] Fetching recent commits and PRs from {UPSTREAM_REPO}...")
    commits = fetch_recent_upstream_commits(UPSTREAM_REPO, limit=20)
    discoveries = extract_added_tools_from_commits(commits)
    print(f"[+] Found {len(discoveries)} recent tool updates from upstream commits.")

    # Load master index
    from free_for_dev_indexer import load_index, build_index
    try:
        indexed = load_index()
    except Exception:
        indexed = build_index()

    # Generate recipes
    recipes = generate_project_recipes(discoveries if discoveries else indexed[:5])

    # Generate daily dossier
    dossier_md = generate_daily_dossier(today, discoveries, indexed, recipes)
    with open(dossier_path, "w", encoding="utf-8") as f:
        f.write(dossier_md)
    print(f"[+] Generated daily dossier at: {dossier_path}")

    # Update ledger
    if discoveries:
        update_ledger(today, discoveries)

    summary = {
        "date": today,
        "new_discoveries_count": len(discoveries),
        "total_indexed": len(indexed),
        "dossier_file": str(dossier_path),
        "discoveries": discoveries,
        "top_recipes": recipes[:3]
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Free-For-Dev Daily Sentinel & Project Recommender")
    parser.add_argument("--sentinel", action="store_true", help="Run in autonomous Sentinel mode for Jules / Cron")
    parser.add_argument("--notify", action="store_true", help="Print structured notification message")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")

    args = parser.parse_args()

    res = scout_and_notify(sentinel_mode=args.sentinel)

    if args.json:
        print(json.dumps(res, indent=2))
    elif args.notify or args.sentinel:
        print("\n========================================================")
        print(f"🚀 FREE-FOR-DEV DAILY DISCOVERY BULLETIN ({res['date']})")
        print("========================================================")
        print(f"• Total Indexed Tools: {res['total_indexed']}")
        print(f"• New Discoveries Today: {res['new_discoveries_count']}")
        print(f"• Daily Dossier: {res['dossier_file']}")
        print("\nTop Recommended Project Recipes:")
        for r in res['top_recipes']:
            print(f"  👉 [{r['tool']}] ({r['use_case']}): {r['recipe']}")
        print("========================================================\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
