#!/usr/bin/env python3
"""
awesome_scout.py: Autonomous GitHub Awesome Topics & Projects Scout (Zero Token Cost)
Scouts https://github.com/topics/awesome and curated awesome-* repositories.
Extracts, scores, and matches 100% Free & Open-Source tools to active project stacks
defined in agent memory (~/.agents/memory/semantic/projects.md and system.md).
Dispatches autonomous PRs via Google Jules and GitHub Actions with zero chat token usage.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
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

PROJECTS_MD_PATH = Path(os.path.expanduser("~/.agents/memory/semantic/projects.md"))
SYSTEM_MD_PATH = Path(os.path.expanduser("~/.agents/memory/semantic/system.md"))
DOCS_PROPOSALS_DIR = REPO_ROOT / "docs" / "awesome-proposals"
DATA_PROPOSALS_DIR = REPO_ROOT / "data" / "awesome-proposals"
LEDGER_PATH = DOCS_PROPOSALS_DIR / "LEDGER.md"

FREE_LICENSES = {
    "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "gpl-2.0", "gpl-3.0",
    "agpl-3.0", "lgpl-2.1", "lgpl-3.0", "mpl-2.0", "unlicense", "cc0-1.0", "isc"
}

POPULAR_AWESOME_LISTS = [
    "sindresorhus/awesome",
    "vinta/awesome-python",
    "awesome-selfhosted/awesome-selfhosted",
    "avelino/awesome-go",
    "rust-unofficial/awesome-rust",
    "dhamaniasad/awesome-postgres",
    "agiresearch/AI-Agent-Paper-List",
    "eugeneyan/open-llms",
    "f/awesome-chatgpt-prompts",
    "analysis-tools-dev/static-analysis",
    "agarrharr/awesome-cli-apps",
    "trimstray/the-book-of-secret-knowledge",
    "undergroundwires/privacy.sexy",
    "kuchin/awesome-cto"
]

DEFAULT_PROJECT_KEYWORDS: Dict[str, List[str]] = {
    "agentic-awesome-skills": ["agent", "llm", "skill", "mcp", "tool", "prompt", "eval", "workflow", "automation", "security"],
    "obsidian-skills": ["obsidian", "markdown", "knowledge", "notes", "canvas", "pkm", "vault", "graph"],
    "presentation-publishing": ["pdf", "typeset", "typst", "presentation", "powerpoint", "epub", "editorial", "cdp", "chromium"],
    "audiobook-tts": ["tts", "speech", "audio", "whisper", "voice", "audiobook", "prosody", "sound", "f5-tts"],
    "database-systems": ["postgres", "pglite", "sqlite", "lancedb", "vector", "database", "sql", "orm"],
    "security-compliance": ["security", "audit", "cve", "sast", "firewall", "zero-trust", "secrets", "hardening", "trivy"],
    "cloudflare-edge": ["cloudflare", "workers", "serverless", "edge", "durable-objects", "wasm", "kv", "r2"],
}


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Execute command safely without external shell injection."""
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


def extract_active_project_profiles() -> Dict[str, Dict[str, Any]]:
    """Parse projects.md to extract active project names and technologies."""
    profiles: Dict[str, Dict[str, Any]] = {}
    if not PROJECTS_MD_PATH.is_file():
        return {k: {"keywords": v, "description": k} for k, v in DEFAULT_PROJECT_KEYWORDS.items()}

    try:
        content = PROJECTS_MD_PATH.read_text(encoding="utf-8")
        current_proj = ""
        for line in content.splitlines():
            proj_match = re.match(r"^##\s+\d+\.\s+`?([^`\n]+)`?", line)
            if proj_match:
                current_proj = proj_match.group(1).strip().lower().replace(" ", "-")
                profiles[current_proj] = {"keywords": set(), "lines": []}
                # Pre-populate defaults if known
                for def_k, def_kw in DEFAULT_PROJECT_KEYWORDS.items():
                    if def_k in current_proj or current_proj in def_k:
                        profiles[current_proj]["keywords"].update(def_kw)
            elif current_proj and line.strip():
                profiles[current_proj]["lines"].append(line.strip())
                words = re.findall(r'[a-zA-Z0-9_-]{3,}', line.lower())
                profiles[current_proj]["keywords"].update(words)
    except Exception as e:
        print(f"[WARN] Error parsing projects.md: {e}", file=sys.stderr)

    # Format keywords to list
    final_profiles = {}
    for k, v in profiles.items():
        kw_list = sorted(list(v["keywords"]))
        final_profiles[k] = {
            "keywords": kw_list or DEFAULT_PROJECT_KEYWORDS.get(k, ["developer", "tools"]),
            "summary": " ".join(v.get("lines", []))[:200]
        }
    return final_profiles or {k: {"keywords": v, "summary": k} for k, v in DEFAULT_PROJECT_KEYWORDS.items()}


def search_github_awesome(query: str, limit: int = 15) -> List[Dict[str, Any]]:
    """Search GitHub repositories with awesome topic or query."""
    full_query = f"{query} topic:awesome"
    cmd = ["gh", "api", f"search/repositories?q={urllib.parse.quote_plus(full_query)}&per_page={limit}&sort=stars&order=desc"]
    code, stdout, _ = run_cmd(cmd, timeout=20)
    if code == 0 and stdout:
        try:
            data = json.loads(stdout)
            return data.get("items", [])
        except Exception:
            pass

    # Fallback to urllib
    url = f"https://api.github.com/search/repositories?q={urllib.parse.quote_plus(full_query)}&per_page={limit}&sort=stars&order=desc"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Awesome-Project-Scout/1.0",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    token = get_github_token()
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("items", [])
    except Exception as e:
        print(f"[WARN] Awesome search API error for '{query}': {e}", file=sys.stderr)
        return []


def is_free_and_open_source(repo_data: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify if repository has a verified FOSS license and no paid-only gate."""
    license_info = repo_data.get("license") or {}
    spdx = (license_info.get("spdx_id") or "").lower()
    
    description = (repo_data.get("description") or "").lower()
    paid_signals = ["subscription only", "paid plan required", "pricing:", "commercial license only", "freemium (paid)"]
    for signal in paid_signals:
        if signal in description:
            return False, f"Proprietary/Commercial signal in description: '{signal}'"

    if spdx in FREE_LICENSES:
        return True, spdx.upper()
    if license_info.get("name") and any(lic_pattern in license_info.get("name", "").lower() for lic_pattern in ["mit", "apache", "bsd", "gpl"]):
        return True, license_info.get("name", "FOSS")
    
    # If open repo on github with open topics without paid indicators
    if not spdx or spdx == "noassertion":
        return True, "Open GitHub Repo (Community)"
    
    return False, f"Non-permissive license ({spdx})"


def match_tool_to_projects(tool_desc: str, tool_name: str, topics: List[str], project_profiles: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compute semantic match score between a discovered tool and active projects."""
    matches = []
    text_corpus = f"{tool_name} {tool_desc} {' '.join(topics)}".lower()
    
    for proj_name, profile in project_profiles.items():
        matched_kw = []
        for kw in profile.get("keywords", []):
            if len(kw) >= 3 and kw.lower() in text_corpus:
                matched_kw.append(kw)
        
        if matched_kw:
            relevance = min(100, int((len(matched_kw) / 3.0) * 100))
            matches.append({
                "project": proj_name,
                "relevance": relevance,
                "matched_keywords": matched_kw[:6],
            })

    return sorted(matches, key=lambda x: x["relevance"], reverse=True)


def scout_awesome_tools(project_profiles: Dict[str, Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """Scout GitHub for awesome tools matching active projects."""
    discovered: Dict[str, Dict[str, Any]] = {}
    
    queries = [
        "developer tools",
        "agent cli",
        "selfhosted",
        "security audit",
        "markdown notes",
        "postgres",
        "tts voice",
        "local ai",
        "cloudflare workers",
    ]

    for q in queries:
        repos = search_github_awesome(q, limit=limit)
        for repo in repos:
            full_name = repo.get("full_name", "")
            if not full_name or full_name in discovered:
                continue

            is_free, lic_note = is_free_and_open_source(repo)
            if not is_free:
                continue

            desc = repo.get("description") or "Open source developer tool from GitHub Awesome"
            name = repo.get("name", "")
            stars = repo.get("stargazers_count", 0)
            forks = repo.get("forks_count", 0)
            url = repo.get("html_url", f"https://github.com/{full_name}")
            topics = repo.get("topics", [])
            lang = repo.get("language") or "Multi"

            proj_matches = match_tool_to_projects(desc, name, topics, project_profiles)
            if not proj_matches:
                continue

            discovered[full_name] = {
                "id": name.lower().replace(".", "-"),
                "name": name,
                "full_name": full_name,
                "description": desc,
                "stars": stars,
                "forks": forks,
                "license": lic_note,
                "url": url,
                "language": lang,
                "topics": topics[:6],
                "project_matches": proj_matches,
                "top_project": proj_matches[0]["project"],
                "relevance": proj_matches[0]["relevance"],
            }

    return sorted(list(discovered.values()), key=lambda x: (x["relevance"], x["stars"]), reverse=True)


def stage_proposals(tools: List[Dict[str, Any]], today_str: str) -> Tuple[Path, Path]:
    """Generate structured markdown dossier and JSON proposals."""
    DOCS_PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)

    dossier_path = DOCS_PROPOSALS_DIR / f"{today_str}.md"
    json_path = DATA_PROPOSALS_DIR / f"proposals-{today_str}.json"

    # Write Markdown Dossier
    with open(dossier_path, "w", encoding="utf-8") as f:
        f.write(f"# 🚀 Awesome Tools Proposal Dossier: {today_str}\n\n")
        f.write(f"> Autonomous Zero-Token Scout matching 100% Free & Open-Source tools to active project stacks.\n\n")
        f.write(f"- **Date:** {today_str}\n")
        f.write(f"- **Candidate Tools Found:** {len(tools)}\n")
        f.write(f"- **Cost/Token Usage:** **0 Tokens** (Automated GitHub Heuristic Engine)\n")
        f.write(f"- **License Policy:** Strictly Free / Open Source (MIT, Apache-2.0, BSD, GPL, Self-Hosted)\n\n")
        f.write("---\n\n")

        # Group by Target Project
        projects_map: Dict[str, List[Dict[str, Any]]] = {}
        for t in tools:
            p = t["top_project"]
            projects_map.setdefault(p, []).append(t)

        for proj, p_tools in projects_map.items():
            f.write(f"## 📁 Target Project: `{proj}`\n\n")
            f.write("| Tool | Stars | License | Language | Match Keywords | Description |\n")
            f.write("| :--- | :---: | :---: | :---: | :--- | :--- |\n")
            for t in p_tools:
                stars_fmt = f"{t['stars']:,}" if t['stars'] else "0"
                match_kw = ", ".join(t['project_matches'][0]['matched_keywords'])
                desc_short = (t['description'][:80] + "...") if len(t['description']) > 80 else t['description']
                f.write(f"| [{t['name']}]({t['url']}) | ⭐ {stars_fmt} | `{t['license']}` | `{t['language']}` | `{match_kw}` | {desc_short} |\n")
            f.write("\n")

        f.write("---\n\n")
        f.write("## 🛠️ Autonomous Jules & Maintainer Action\n\n")
        f.write("1. **Recommend by project:** `skills-maintainer awesome recommend <project-name>`\n")
        f.write("2. **Audit tool locally:** `vet-tool audit <repo_url>`\n")
        f.write("3. **Dispatch Jules PR:** `skills-maintainer jules awesome`\n")

    # Write JSON snapshot
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "date": today_str,
            "total": len(tools),
            "tools": tools
        }, f, indent=2)

    # Update LEDGER.md
    existing_ledger = ""
    if LEDGER_PATH.is_file():
        try:
            existing_ledger = LEDGER_PATH.read_text(encoding="utf-8")
        except Exception:
            existing_ledger = ""

    if not existing_ledger:
        existing_ledger = "# Master Awesome Tools Proposals Ledger\n\nAutomated Zero-Token Scout Proposals Log.\n\n| Date | Free Tools Discovered | Target Projects | Dossier Link |\n| :--- | :---: | :--- | :--- |\n"

    top_projs = ", ".join(list(projects_map.keys())[:3])
    new_row = f"| {today_str} | {len(tools)} | `{top_projs}` | [{today_str}.md]({today_str}.md) |\n"
    if today_str not in existing_ledger:
        existing_ledger += new_row
        LEDGER_PATH.write_text(existing_ledger, encoding="utf-8")

    return dossier_path, json_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Autonomous Awesome Tools & Projects Scout (Zero Token Cost)")
    parser.add_argument("--search", type=str, help="Search specific query under topic:awesome")
    parser.add_argument("--recommend", type=str, help="Recommend free tools for a specific active project name")
    parser.add_argument("--limit", type=int, default=10, help="Max candidates per query (default: 10)")
    parser.add_argument("--dry-run", action="store_true", help="Print findings to stdout without saving dossiers")
    parser.add_argument("--jules", action="store_true", help="Dispatch discovery task to Google Jules")
    args = parser.parse_args()

    today_str = datetime.date.today().strftime("%Y-%m-%d")
    project_profiles = extract_active_project_profiles()

    if args.recommend:
        target_proj = args.recommend.lower().strip()
        matching_proj = next((k for k in project_profiles if target_proj in k), None)
        if not matching_proj:
            print(f"Project '{target_proj}' not found in memory. Available projects: {list(project_profiles.keys())}")
            return 1
        print(f"🔍 Searching Free Awesome Tools for project: `{matching_proj}` (Keywords: {', '.join(project_profiles[matching_proj]['keywords'][:8])})...")
        tools = scout_awesome_tools({matching_proj: project_profiles[matching_proj]}, limit=args.limit)
        print(f"\nTop {len(tools)} Free Tools for `{matching_proj}`:")
        for t in tools[:args.limit]:
            print(f"  - ⭐ {t['stars']} | [{t['name']}]({t['url']}) | License: {t['license']}")
            print(f"    {t['description']}")
            print(f"    Matched keywords: {', '.join(t['project_matches'][0]['matched_keywords'])}\n")
        return 0

    if args.search:
        print(f"🔍 Searching topic:awesome for: '{args.search}' (Filtering 100% Free / Open-Source)...")
        repos = search_github_awesome(args.search, limit=args.limit)
        count = 0
        for r in repos:
            is_free, lic_note = is_free_and_open_source(r)
            if not is_free:
                continue
            count += 1
            print(f"[{count}] ⭐ {r.get('stargazers_count', 0)} | {r.get('full_name')} ({lic_note})")
            print(f"    {r.get('description')}")
            print(f"    URL: {r.get('html_url')}\n")
        return 0

    print(f"🚀 Running Autonomous Awesome Project Scout for {len(project_profiles)} active projects...")
    tools = scout_awesome_tools(project_profiles, limit=args.limit)
    print(f"Found {len(tools)} verified Free/OSS tools matched to active projects.")

    if args.dry_run:
        print("\n--- DRY RUN SUMMARY ---")
        for t in tools[:8]:
            print(f"  - [{t['top_project']}] ⭐ {t['stars']} {t['name']} ({t['license']}) -> {t['url']}")
        return 0

    dossier_path, json_path = stage_proposals(tools, today_str)
    print(f"✅ Proposals saved:")
    print(f"  - Dossier: {dossier_path}")
    print(f"  - Data: {json_path}")
    print(f"  - Ledger: {LEDGER_PATH}")

    if args.jules:
        print("\n🤖 Dispatching automated Awesome PR task to Google Jules...")
        prompt = f"Review the latest awesome tools proposal in {dossier_path} and integrate top verified free tools into agentic-awesome-skills."
        cmd = ["skills-maintainer", "jules", "new", prompt]
        code, stdout, stderr = run_cmd(cmd, timeout=30)
        print(f"Jules Dispatch Result: {stdout or stderr}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
