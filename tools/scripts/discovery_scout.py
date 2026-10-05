#!/usr/bin/env python3
"""
discovery_scout.py: Autonomous GitHub Scout for Agent Skills & MCP Servers
Searches GitHub for new Agent Skills and Model Context Protocol (MCP) servers,
evaluates quality and security, de-duplicates against existing catalog,
and stages candidate entries for monthly maintenance review.
"""

from __future__ import annotations

import argparse
import concurrent.futures
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


MALICIOUS_PATTERNS = [
    re.compile(r'/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+', re.IGNORECASE),
    re.compile(r'nc\s+(-e|-c|--exec)\s+', re.IGNORECASE),
    re.compile(r'base64\s+(-d|--decode)\s*\|\s*(sh|bash)', re.IGNORECASE),
    re.compile(r'curl\s+[^|\n]+\|\s*(sh|bash)', re.IGNORECASE),
    re.compile(r'wget\s+[^|\n]+\|\s*(sh|bash)', re.IGNORECASE),
    re.compile(r'eval\s*\(\s*base64', re.IGNORECASE),
    re.compile(r'token_exfiltrat', re.IGNORECASE),
    re.compile(r'discord\.com/api/webhooks', re.IGNORECASE),
    re.compile(r'telegram\.org/bot', re.IGNORECASE),
    re.compile(r'import\s+pty;\s*pty\.spawn', re.IGNORECASE),
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


def search_github_repos(query: str, limit: int = 15) -> List[Dict[str, Any]]:
    """Search GitHub repositories using gh CLI or urllib."""
    cmd = ["gh", "api", f"search/repositories?q={urllib.parse.quote_plus(query)}&per_page={limit}&sort=updated&order=desc"]
    code, stdout, stderr = run_cmd(cmd, timeout=20)
    if code == 0 and stdout:
        try:
            data = json.loads(stdout)
            return data.get("items", [])
        except Exception:
            pass

    # Fallback to urllib
    url = f"https://api.github.com/search/repositories?q={urllib.parse.quote_plus(query)}&per_page={limit}&sort=updated&order=desc"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AAS-Discovery-Scout/1.0",
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
        print(f"[WARN] Search API error for '{query}': {e}", file=sys.stderr)
        return []


def load_known_skills_catalog(repo_root: Path) -> Set[str]:
    """Load IDs, names, and sources of existing skills in the repository."""
    known: Set[str] = set()
    index_file = repo_root / "skills_index.json"
    if index_file.is_file():
        try:
            with open(index_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            if "id" in item:
                                known.add(str(item["id"]).strip().lower())
                            if "name" in item:
                                known.add(str(item["name"]).strip().lower())
        except Exception as e:
            print(f"[WARN] Could not parse skills_index.json: {e}", file=sys.stderr)

    skills_dir = repo_root / "skills"
    if skills_dir.is_dir():
        for item in skills_dir.iterdir():
            if item.is_dir():
                known.add(item.name.strip().lower())

    return known


def load_known_mcp_catalog(repo_root: Path) -> Set[str]:
    """Load known MCP server identifiers."""
    known: Set[str] = {
        "memory", "github", "agent-browser", "cloudflare", "cloudflare-docs",
        "kaggle", "skillspector", "gws", "fetch", "filesystem", "puppeteer",
        "brave-search", "sqlite", "postgres", "slack", "notion", "zendesk",
        "git", "sequential-thinking", "everything", "sentry", "docker"
    }
    mcp_config = Path("/home/npirela/.gemini/config/mcp_config.json")
    if mcp_config.is_file():
        try:
            with open(mcp_config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                servers = cfg.get("mcpServers", {})
                for k in servers:
                    known.add(k.strip().lower())
        except Exception:
            pass
    return known


def assess_security_risk(content: str, description: str = "") -> Tuple[str, List[str]]:
    """Scan text content for security red flags."""
    combined = f"{description}\n{content}"
    findings: List[str] = []
    for pat in MALICIOUS_PATTERNS:
        match = pat.search(combined)
        if match:
            findings.append(f"Matched pattern: {match.group(0)[:40]}")

    if findings:
        return "HIGH", findings
    if "sudo" in combined.lower() or "chmod +s" in combined.lower():
        return "MEDIUM", ["Contains elevated privilege requests (sudo/chmod)"]
    if "api_key" in combined.lower() or "token" in combined.lower():
        return "LOW", ["References API credentials or tokens"]
    return "SAFE", []


def score_candidate(stars: int, forks: int, has_license: bool, risk: str) -> int:
    """Compute a quality score from 1 to 5."""
    score = 1
    if has_license:
        score += 1
    if stars >= 5:
        score += 1
    if stars >= 25:
        score += 1
    if stars >= 100:
        score += 1
    if risk == "HIGH":
        score = max(1, score - 3)
    elif risk == "MEDIUM":
        score = max(1, score - 1)
    return min(5, max(1, score))


def sanitize_id(name: str) -> str:
    """Convert name to clean identifier."""
    clean = re.sub(r'[^a-zA-Z0-9_-]', '-', name).strip('-').lower()
    clean = re.sub(r'-+', '-', clean)
    return clean or "unknown-candidate"


def scout_skills(known_skills: Set[str], limit: int = 15) -> List[Dict[str, Any]]:
    """Search GitHub for new Agent Skills."""
    queries = [
        "topic:agent-skills",
        "topic:claude-skills",
        "topic:agentic-skills",
        "topic:antigravity-skills",
        "agent skill in:name,description",
    ]

    discovered: Dict[str, Dict[str, Any]] = {}

    for query in queries:
        repos = search_github_repos(query, limit=limit)
        for repo in repos:
            full_name = repo.get("full_name", "")
            repo_name = repo.get("name", "")
            candidate_id = sanitize_id(repo_name)

            if not full_name or candidate_id in known_skills or full_name.lower() in known_skills:
                continue

            if full_name in discovered:
                continue

            description = repo.get("description") or "Agent skill for autonomous workflows."
            stars = repo.get("stargazers_count", 0)
            forks = repo.get("forks_count", 0)
            license_info = repo.get("license") or {}
            license_spdx = license_info.get("spdx_id") or "UNLICENSED"
            updated_at = repo.get("updated_at", "")
            html_url = repo.get("html_url", f"https://github.com/{full_name}")
            topics = repo.get("topics", [])

            risk_level, findings = assess_security_risk("", description)
            score = score_candidate(stars, forks, license_spdx != "UNLICENSED", risk_level)

            discovered[full_name] = {
                "type": "skill",
                "id": candidate_id,
                "full_name": full_name,
                "name": repo_name,
                "description": description,
                "stars": stars,
                "forks": forks,
                "license": license_spdx,
                "url": html_url,
                "topics": topics,
                "updated_at": updated_at,
                "risk": risk_level,
                "findings": findings,
                "score": score,
            }

    return list(discovered.values())


def scout_mcps(known_mcps: Set[str], limit: int = 15) -> List[Dict[str, Any]]:
    """Search GitHub for new Model Context Protocol (MCP) servers."""
    queries = [
        "topic:mcp-server",
        "topic:modelcontextprotocol",
        "mcp-server in:name",
        "\"@modelcontextprotocol\" in:description",
    ]

    discovered: Dict[str, Dict[str, Any]] = {}

    for query in queries:
        repos = search_github_repos(query, limit=limit)
        for repo in repos:
            full_name = repo.get("full_name", "")
            repo_name = repo.get("name", "")
            clean_id = sanitize_id(repo_name.replace("mcp-server-", "").replace("-mcp", ""))

            if not full_name or clean_id in known_mcps or full_name.lower() in known_mcps:
                continue

            if full_name in discovered:
                continue

            description = repo.get("description") or "Model Context Protocol (MCP) Server"
            stars = repo.get("stargazers_count", 0)
            forks = repo.get("forks_count", 0)
            license_info = repo.get("license") or {}
            license_spdx = license_info.get("spdx_id") or "UNLICENSED"
            updated_at = repo.get("updated_at", "")
            html_url = repo.get("html_url", f"https://github.com/{full_name}")
            topics = repo.get("topics", [])
            language = repo.get("language") or "TypeScript"

            transport = "stdio"
            if "sse" in description.lower() or "sse" in topics:
                transport = "sse"

            install_cmd = ""
            if language.lower() in ["typescript", "javascript"]:
                install_cmd = f"npx -y {repo_name}"
            elif language.lower() in ["python"]:
                install_cmd = f"uvx {repo_name}"
            elif language.lower() in ["go"]:
                install_cmd = f"go install github.com/{full_name}@latest"
            elif language.lower() in ["rust"]:
                install_cmd = f"cargo install {repo_name}"
            else:
                install_cmd = f"git clone {html_url}"

            risk_level, findings = assess_security_risk("", description)
            score = score_candidate(stars, forks, license_spdx != "UNLICENSED", risk_level)

            discovered[full_name] = {
                "type": "mcp",
                "id": clean_id,
                "full_name": full_name,
                "name": repo_name,
                "description": description,
                "stars": stars,
                "forks": forks,
                "license": license_spdx,
                "url": html_url,
                "topics": topics,
                "language": language,
                "transport": transport,
                "install_cmd": install_cmd,
                "updated_at": updated_at,
                "risk": risk_level,
                "findings": findings,
                "score": score,
            }

    return list(discovered.values())


def stage_candidates(
    skills: List[Dict[str, Any]],
    mcps: List[Dict[str, Any]],
    today_str: str,
    repo_root: Path
) -> Tuple[Path, Path]:
    """Generate staged files and discovery documents in repository."""
    staging_dir = repo_root / "staging" / "discovery" / today_str
    docs_discovery_dir = repo_root / "docs" / "discovery"
    data_discovery_dir = repo_root / "data" / "discovery"

    staging_dir.mkdir(parents=True, exist_ok=True)
    docs_discovery_dir.mkdir(parents=True, exist_ok=True)
    data_discovery_dir.mkdir(parents=True, exist_ok=True)

    # 1. Stage Skills
    for skill in skills:
        skill_id = skill["id"]
        skill_dir = staging_dir / "skills" / skill_id
        skill_dir.mkdir(parents=True, exist_ok=True)
        skill_md_path = skill_dir / "SKILL.md"

        desc_escaped = skill["description"].replace('"', '\\"')
        content = f"""---
name: {skill_id}
description: "{desc_escaped}"
license: {skill["license"]}
risk: {skill["risk"].lower()}
source: community
date_added: '{today_str}'
allowed-tools:
  - Read
  - Grep
  - Bash
metadata:
  repository: "{skill["url"]}"
  stars: {skill["stars"]}
  score: {skill["score"]}/5
---

# {skill["name"]}

Candidate agent skill discovered on GitHub from [{skill["full_name"]}]({skill["url"]}).

## Overview
{skill["description"]}

## Instructions & Usage
Refer to upstream repository documentation: [{skill["url"]}]({skill["url"]})

## Limitations
- Staged candidate awaiting monthly repository maintenance triage and verification.
"""
        with open(skill_md_path, "w", encoding="utf-8") as f:
            f.write(content)

    # 2. Stage MCP Servers
    for mcp in mcps:
        mcp_id = mcp["id"]
        mcp_dir = staging_dir / "mcps"
        mcp_dir.mkdir(parents=True, exist_ok=True)
        mcp_json_path = mcp_dir / f"{mcp_id}.json"

        mcp_entry = {
            "id": mcp_id,
            "name": mcp["name"],
            "repository": mcp["url"],
            "description": mcp["description"],
            "language": mcp.get("language", "TypeScript"),
            "transport": mcp.get("transport", "stdio"),
            "install_cmd": mcp.get("install_cmd", ""),
            "stars": mcp["stars"],
            "license": mcp["license"],
            "risk": mcp["risk"],
            "score": mcp["score"],
            "discovered_at": today_str,
            "mcpConfigSnippet": {
                mcp_id: {
                    "command": mcp.get("install_cmd", "").split()[0] if mcp.get("install_cmd") else "npx",
                    "args": mcp.get("install_cmd", "").split()[1:] if mcp.get("install_cmd") else ["-y", mcp["name"]],
                }
            }
        }
        with open(mcp_json_path, "w", encoding="utf-8") as f:
            json.dump(mcp_entry, f, indent=2)

    # 3. Write Daily Discovery Report (Markdown)
    daily_doc_path = docs_discovery_dir / f"{today_str}.md"
    with open(daily_doc_path, "w", encoding="utf-8") as f:
        f.write(f"# Daily Agent Skills & MCP Discovery Scout: {today_str}\n\n")
        f.write(f"> Automated GitHub scouting report generated by Google Jules / Discovery Scout.\n\n")
        f.write(f"- **Date:** {today_str}\n")
        f.write(f"- **New Skills Discovered:** {len(skills)}\n")
        f.write(f"- **New MCP Servers Discovered:** {len(mcps)}\n")
        f.write(f"- **Staging Path:** `staging/discovery/{today_str}/`\n\n")
        f.write("---\n\n")

        f.write("## 🌟 Discovered Agent Skills\n\n")
        if skills:
            f.write("| Score | Name | Stars | License | Risk | Repository | Description |\n")
            f.write("| :---: | :--- | :---: | :---: | :---: | :--- | :--- |\n")
            for s in sorted(skills, key=lambda x: x["score"], reverse=True):
                stars_fmt = f"{s['stars']:,}" if s['stars'] else "0"
                desc_short = (s['description'][:90] + "...") if len(s['description']) > 90 else s['description']
                f.write(f"| {s['score']}/5 | `{s['id']}` | {stars_fmt} | {s['license']} | `{s['risk']}` | [{s['full_name']}]({s['url']}) | {desc_short} |\n")
        else:
            f.write("_No new uncataloged skills discovered today._\n")

        f.write("\n---\n\n")
        f.write("## 🔌 Discovered MCP Servers\n\n")
        if mcps:
            f.write("| Score | Name | Stars | Transport | Language | Repository | Description |\n")
            f.write("| :---: | :--- | :---: | :---: | :---: | :--- | :--- |\n")
            for m in sorted(mcps, key=lambda x: x["score"], reverse=True):
                stars_fmt = f"{m['stars']:,}" if m['stars'] else "0"
                desc_short = (m['description'][:90] + "...") if len(m['description']) > 90 else m['description']
                f.write(f"| {m['score']}/5 | `{m['id']}` | {stars_fmt} | `{m['transport']}` | {m['language']} | [{m['full_name']}]({m['url']}) | {desc_short} |\n")
        else:
            f.write("_No new uncataloged MCP servers discovered today._\n")

        f.write("\n---\n\n")
        f.write("## 📋 Monthly Triage Guidance\n\n")
        f.write("During the monthly repository maintenance sweep (`skills-maintainer all` or `skills-maintainer review-discovery`):\n")
        f.write("1. **Review candidate worthiness:** Filter by Score >= 3 and Risk `SAFE`/`LOW`.\n")
        f.write("2. **Security scan:** Run `skills-maintainer review-discovery --audit`.\n")
        f.write("3. **Promote:** Run `skills-maintainer review-discovery --accept <id>` to move into active `skills/` or `plugins/`.\n")
        f.write("4. **Discard:** Run `skills-maintainer review-discovery --reject <id>` for low-quality or duplicate candidates.\n")

    # 4. Save JSON Snapshot in data/discovery/
    daily_json_path = data_discovery_dir / f"daily-{today_str}.json"
    snapshot = {
        "date": today_str,
        "total_skills": len(skills),
        "total_mcps": len(mcps),
        "skills": skills,
        "mcps": mcps,
    }
    with open(daily_json_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)

    # 5. Append/Update Master Discovery LEDGER.md
    ledger_path = docs_discovery_dir / "LEDGER.md"
    existing_ledger = ""
    if ledger_path.is_file():
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                existing_ledger = f.read()
        except Exception:
            existing_ledger = ""

    if not existing_ledger:
        existing_ledger = "# Master Discovery Ledger: Agent Skills & MCP Servers\n\nCumulative log of all automated GitHub discoveries staged for monthly maintenance review.\n\n| Date | New Skills | New MCPs | Staging Directory | Report Link |\n| :--- | :---: | :---: | :--- | :--- |\n"

    new_row = f"| {today_str} | {len(skills)} | {len(mcps)} | `staging/discovery/{today_str}/` | [{today_str}.md]({today_str}.md) |\n"
    if today_str not in existing_ledger:
        existing_ledger += new_row
        with open(ledger_path, "w", encoding="utf-8") as f:
            f.write(existing_ledger)

    return daily_doc_path, daily_json_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Autonomous GitHub Scout for Agent Skills & MCP Servers")
    parser.add_argument("--limit", type=int, default=10, help="Max candidates per search query (default: 10)")
    parser.add_argument("--dry-run", action="store_true", help="Print findings without writing files")
    args = parser.parse_args()

    today_str = datetime.date.today().strftime("%Y-%m-%d")
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting Autonomous GitHub Discovery Scout...")
    print(f"Repository Root: {REPO_ROOT}")
    print(f"Date: {today_str} | Query limit: {args.limit}")

    known_skills = load_known_skills_catalog(REPO_ROOT)
    known_mcps = load_known_mcp_catalog(REPO_ROOT)
    print(f"Known Catalog: {len(known_skills)} skills, {len(known_mcps)} MCP identifiers loaded.")

    print("\n[1/2] Scouting GitHub for new Agent Skills...")
    skills = scout_skills(known_skills, limit=args.limit)
    print(f"Found {len(skills)} uncataloged candidate skill repositories.")

    print("\n[2/2] Scouting GitHub for new Model Context Protocol (MCP) Servers...")
    mcps = scout_mcps(known_mcps, limit=args.limit)
    print(f"Found {len(mcps)} uncataloged candidate MCP server repositories.")

    if args.dry_run:
        print("\n--- DRY RUN SUMMARY ---")
        print(f"Skills ({len(skills)}):")
        for s in skills[:5]:
            print(f"  - [{s['score']}/5] {s['id']} ({s['full_name']}) - {s['stars']} stars - Risk: {s['risk']}")
        print(f"\nMCP Servers ({len(mcps)}):")
        for m in mcps[:5]:
            print(f"  - [{m['score']}/5] {m['id']} ({m['full_name']}) - {m['stars']} stars - Risk: {m['risk']}")
        return 0

    if skills or mcps:
        doc_path, json_path = stage_candidates(skills, mcps, today_str, REPO_ROOT)
        print(f"\n✅ Discovery successfully staged!")
        print(f"  - Daily Report: {doc_path}")
        print(f"  - Data Snapshot: {json_path}")
        print(f"  - Staging Root: {REPO_ROOT / 'staging' / 'discovery' / today_str}")
    else:
        print("\nℹ️ No new uncataloged skills or MCP servers found today.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
