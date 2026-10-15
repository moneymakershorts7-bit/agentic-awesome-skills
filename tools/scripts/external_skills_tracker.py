#!/usr/bin/env python3
"""
external_skills_tracker.py: Multi-Repository Provenance Tracker & Upstream Synchronizer
Automatically tracks, monitors, and synchronizes skills installed from 280+ third-party
GitHub repositories into ~/.agents/skills and agentic-awesome-skills.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SKILLS_DIR = os.path.expanduser("~/.agents/skills")
REPO_ROOT = Path(__file__).resolve().parents[2]
PROVENANCE_FILE = os.path.expanduser("~/.agents/memory/working/external_skills_provenance.json")
STATE_FILE = os.path.expanduser("~/.agents/memory/working/external_skills_state.json")
LOG_DIR = os.path.expanduser("~/.agents/memory/working")

def extract_provenance(skills_dir: str = SKILLS_DIR) -> Dict[str, List[str]]:
    """Scan all installed skills and map external GitHub repositories to their skill IDs."""
    repo_map = defaultdict(list)
    if not os.path.exists(skills_dir):
        return {}

    for s in sorted(os.listdir(skills_dir)):
        p = os.path.join(skills_dir, s, "SKILL.md")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(1500)
                    m = re.search(r'source:\s*["\']?(?:https?://github\.com/)?([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)', content)
                    if m:
                        repo = m.group(1).rstrip('/"\'')
                        if "/" in repo and not repo.startswith("sickn33/") and not repo.startswith("moneymakershorts7-bit/"):
                            repo_map[repo].append(s)
            except Exception:
                pass

    os.makedirs(os.path.dirname(PROVENANCE_FILE), exist_ok=True)
    with open(PROVENANCE_FILE, "w", encoding="utf-8") as f:
        json.dump(repo_map, f, indent=2)

    return repo_map

def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_checked": None, "repos": {}}

def save_state(state: Dict[str, Any]):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def check_repo_upstream(repo: str) -> Optional[Dict[str, str]]:
    """Query GitHub API via gh cli or urllib for the latest HEAD commit."""
    cmd = ["gh", "api", f"repos/{repo}/commits/HEAD", "--jq", "{sha: .sha, date: .commit.committer.date, message: .commit.message}"]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12)
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout.strip())
    except Exception:
        pass
    return None

def check_all_upstreams(limit: int = 50, verbose: bool = False) -> Dict[str, Any]:
    """Check upstream status across all tracked repositories."""
    provenance = extract_provenance()
    state = load_state()
    repos_state = state.setdefault("repos", {})

    print(f"📦 [External Skills Tracker] Tracking {len(provenance)} third-party repositories...")
    
    # Sort repos by skill count descending
    sorted_repos = sorted(provenance.items(), key=lambda x: len(x[1]), reverse=True)
    if limit > 0:
        sorted_repos = sorted_repos[:limit]

    updates_available = []
    up_to_date = []
    unreachable = []

    for i, (repo, skills) in enumerate(sorted_repos, 1):
        latest = check_repo_upstream(repo)
        if not latest:
            unreachable.append(repo)
            if verbose:
                print(f"  [{i:02d}/{len(sorted_repos)}] ⚠️ {repo:<42} | Unreachable or private")
            continue

        prev_sha = repos_state.get(repo, {}).get("sha")
        curr_sha = latest["sha"]
        date_str = latest.get("date", "")[:10]
        msg = (latest.get("message", "").splitlines() or [""])[0][:50]

        is_update = (prev_sha is not None and prev_sha != curr_sha)
        
        repos_state[repo] = {
            "sha": curr_sha,
            "date": latest.get("date"),
            "skills_count": len(skills),
            "skills": skills[:5],
            "last_message": msg,
            "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        if is_update:
            updates_available.append((repo, len(skills), date_str, msg))
            print(f"  [{i:02d}/{len(sorted_repos)}] 🚀 {repo:<42} | UPDATE DETECTED ({date_str}) -> {len(skills)} skills")
        else:
            up_to_date.append(repo)
            if verbose or len(skills) >= 15:
                print(f"  [{i:02d}/{len(sorted_repos)}] ✅ {repo:<42} | Synced ({date_str}) | {len(skills)} skills")

    state["last_checked"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_state(state)

    print("\n" + "=" * 65)
    print("UPSTREAM SCAN SUMMARY:")
    print(f"  - Repositories Evaluated: {len(sorted_repos)}")
    print(f"  - Updates Available:      {len(updates_available)}")
    print(f"  - Up to Date:             {len(up_to_date)}")
    print(f"  - Unreachable/Private:    {len(unreachable)}")
    print("=" * 65)

    if updates_available:
        print("\n🚀 REPOSITORIES WITH NEW COMMITS:")
        for r, cnt, d, m in updates_available:
            print(f"  - {r} ({cnt} skills, {d}): {m}")

    return {
        "total_tracked": len(provenance),
        "checked": len(sorted_repos),
        "updates_count": len(updates_available),
        "updates": updates_available
    }

def main():
    parser = argparse.ArgumentParser(description="External Skills Upstream Provenance Tracker")
    parser.add_argument("--scan", action="store_true", help="Extract and display provenance mapping")
    parser.add_argument("--check", action="store_true", help="Check upstream commits for tracked repositories")
    parser.add_argument("--limit", type=int, default=30, help="Max repositories to query (default: 30)")
    parser.add_argument("--all", action="store_true", help="Check all repositories without limit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose per-repo output")
    args = parser.parse_args()

    if args.scan:
        prov = extract_provenance()
        print(f"Discovered {len(prov)} third-party repositories governing {sum(len(v) for v in prov.values())} skills.")
        for r, sks in sorted(prov.items(), key=lambda x: len(x[1]), reverse=True)[:20]:
            print(f"  - {r}: {len(sks)} skills")
        return

    # Default to check
    limit = 0 if args.all else args.limit
    check_all_upstreams(limit=limit, verbose=args.verbose)

if __name__ == "__main__":
    main()
