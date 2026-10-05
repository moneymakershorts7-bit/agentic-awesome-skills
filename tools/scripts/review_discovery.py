#!/usr/bin/env python3
"""
review_discovery.py: Monthly Repository Maintenance Review & Decision Engine
Inspects staged discovery candidates from Google Jules and daily scouts,
executes security audits, and enables the maintainer/agent to accept,
reject, or triage discovered Agent Skills and MCP servers.
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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from _project_paths import find_repo_root
    REPO_ROOT = find_repo_root(__file__)
except Exception:
    REPO_ROOT = Path(__file__).resolve().parents[2]


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 45) -> Tuple[int, str, str]:
    """Execute command safely and return exit code, stdout, stderr."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=str(cwd or REPO_ROOT),
            check=False,
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def collect_staged_candidates(repo_root: Path) -> Dict[str, Any]:
    """Gather all staged discovery items across staging/discovery/*/."""
    staging_base = repo_root / "staging" / "discovery"
    candidates: Dict[str, Any] = {
        "skills": {},
        "mcps": {},
        "dates": []
    }

    if not staging_base.is_dir():
        return candidates

    for date_dir in sorted(staging_base.iterdir()):
        if not date_dir.is_dir():
            continue
        date_str = date_dir.name
        candidates["dates"].append(date_str)

        # Collect skills
        skills_dir = date_dir / "skills"
        if skills_dir.is_dir():
            for skill_dir in skills_dir.iterdir():
                if skill_dir.is_dir():
                    skill_id = skill_dir.name
                    skill_md = skill_dir / "SKILL.md"
                    content = ""
                    if skill_md.is_file():
                        try:
                            with open(skill_md, "r", encoding="utf-8") as f:
                                content = f.read()
                        except Exception:
                            pass
                    candidates["skills"][skill_id] = {
                        "id": skill_id,
                        "date": date_str,
                        "path": skill_dir,
                        "skill_md": skill_md,
                        "content": content,
                    }

        # Collect MCPs
        mcps_dir = date_dir / "mcps"
        if mcps_dir.is_dir():
            for mcp_file in mcps_dir.glob("*.json"):
                mcp_id = mcp_file.stem
                try:
                    with open(mcp_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        candidates["mcps"][mcp_id] = {
                            "id": mcp_id,
                            "date": date_str,
                            "path": mcp_file,
                            "data": data,
                        }
                except Exception:
                    pass

    return candidates


def audit_staged_candidates(candidates: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    """Execute malware scanner and security checks on staged candidates."""
    print("[AUDIT] Running security scans across all staged candidates...")
    results = {"clean_skills": [], "flagged_skills": [], "clean_mcps": [], "flagged_mcps": []}

    # Run malware scanner if available
    malware_script = repo_root / "tools" / "scripts" / "malware_scanner.py"
    staging_path = repo_root / "staging" / "discovery"
    if malware_script.is_file() and staging_path.is_dir():
        code, stdout, _ = run_cmd(["python3", str(malware_script), "--strict", str(staging_path)])
        if code == 0:
            print("  ✅ Malware & Supply-Chain scan: PASSED (Zero malicious payloads).")
        else:
            print("  ⚠️ Malware scan raised warnings:")
            print(f"     {stdout[:200]}")

    for skill_id, item in candidates["skills"].items():
        content = item.get("content", "")
        if "eval(" in content or "rm -rf /" in content or "base64" in content:
            results["flagged_skills"].append((skill_id, "Suspicious pattern detected in SKILL.md"))
        else:
            results["clean_skills"].append(skill_id)

    for mcp_id, item in candidates["mcps"].items():
        data = item.get("data", {})
        risk = data.get("risk", "SAFE")
        if risk in ["HIGH", "CRITICAL"]:
            results["flagged_mcps"].append((mcp_id, f"Risk rating: {risk}"))
        else:
            results["clean_mcps"].append(mcp_id)

    return results


def accept_skill(skill_id: str, candidates: Dict[str, Any], repo_root: Path) -> bool:
    """Promote candidate skill from staging to active skills/ catalog."""
    if skill_id not in candidates["skills"]:
        print(f"[ERROR] Skill '{skill_id}' not found in staged discovery.", file=sys.stderr)
        return False

    item = candidates["skills"][skill_id]
    src_dir = item["path"]
    dst_dir = repo_root / "skills" / skill_id

    if dst_dir.exists():
        print(f"[WARN] Skill '{skill_id}' already exists in active catalog. Overwriting...", file=sys.stderr)
        shutil.rmtree(dst_dir)

    shutil.copytree(src_dir, dst_dir)
    print(f"  ✅ Promoted skill '{skill_id}' -> skills/{skill_id}/")

    # Update ledger
    record_decision_in_ledger(skill_id, "skill", "ACCEPTED", repo_root)
    return True


def accept_mcp(mcp_id: str, candidates: Dict[str, Any], repo_root: Path) -> bool:
    """Add candidate MCP server into repository catalog."""
    if mcp_id not in candidates["mcps"]:
        print(f"[ERROR] MCP server '{mcp_id}' not found in staged discovery.", file=sys.stderr)
        return False

    item = candidates["mcps"][mcp_id]
    data = item.get("data", {})

    # Register in data/discovered_mcps.json
    mcps_catalog_file = repo_root / "data" / "discovered_mcps.json"
    catalog: Dict[str, Any] = {}
    if mcps_catalog_file.is_file():
        try:
            with open(mcps_catalog_file, "r", encoding="utf-8") as f:
                catalog = json.load(f)
        except Exception:
            catalog = {}

    catalog[mcp_id] = data
    with open(mcps_catalog_file, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    print(f"  ✅ Registered MCP server '{mcp_id}' -> data/discovered_mcps.json")
    record_decision_in_ledger(mcp_id, "mcp", "ACCEPTED", repo_root)
    return True


def reject_candidate(item_id: str, item_type: str, reason: str, candidates: Dict[str, Any], repo_root: Path) -> bool:
    """Reject candidate, remove from staging, and log decision."""
    target_path = None
    if item_type == "skill" and item_id in candidates["skills"]:
        target_path = candidates["skills"][item_id]["path"]
    elif item_type == "mcp" and item_id in candidates["mcps"]:
        target_path = candidates["mcps"][item_id]["path"]

    if target_path and target_path.exists():
        if target_path.is_dir():
            shutil.rmtree(target_path)
        else:
            target_path.unlink()

    print(f"  ❌ Rejected candidate '{item_id}' ({item_type}). Reason: {reason}")
    record_decision_in_ledger(item_id, item_type, f"REJECTED: {reason}", repo_root)
    return True


def record_decision_in_ledger(item_id: str, item_type: str, decision: str, repo_root: Path) -> None:
    """Append monthly triage decision to docs/discovery/DECISIONS.md."""
    decisions_file = repo_root / "docs" / "discovery" / "DECISIONS.md"
    decisions_file.parent.mkdir(parents=True, exist_ok=True)
    today_str = datetime.date.today().strftime("%Y-%m-%d")

    entry = f"- `[{today_str}]` **{item_id}** (`{item_type}`): {decision}\n"

    existing = ""
    if decisions_file.is_file():
        try:
            with open(decisions_file, "r", encoding="utf-8") as f:
                existing = f.read()
        except Exception:
            existing = ""

    if not existing:
        existing = "# Monthly Maintenance Discovery Decisions Log\n\nOfficial record of accepted, rejected, and deferred candidate skills and MCP servers.\n\n"

    with open(decisions_file, "w", encoding="utf-8") as f:
        f.write(existing + entry)


def print_dossier(candidates: Dict[str, Any], repo_root: Path) -> None:
    """Generate and display the Monthly Discovery Dossier."""
    today_str = datetime.date.today().strftime("%Y-%m-%d")
    total_skills = len(candidates["skills"])
    total_mcps = len(candidates["mcps"])

    print("\n" + "=" * 78)
    print(f"  MONTHLY DISCOVERY DOSSIER & TRIAGE: {today_str}")
    print(f"  Pending Review: {total_skills} Candidate Skills | {total_mcps} Candidate MCPs")
    print("=" * 78 + "\n")

    print("🌟 STAGED CANDIDATE SKILLS:")
    print("-" * 78)
    if candidates["skills"]:
        for sid, s in candidates["skills"].items():
            print(f"  • `{sid}` (Discovered: {s['date']}) -> Staging: {s['path']}")
    else:
        print("  (No candidate skills awaiting triage)")

    print("\n🔌 STAGED CANDIDATE MCP SERVERS:")
    print("-" * 78)
    if candidates["mcps"]:
        for mid, m in candidates["mcps"].items():
            m_data = m.get("data", {})
            stars = m_data.get("stars", 0)
            print(f"  • `{mid}` (Stars: {stars}, Lang: {m_data.get('language')}) -> Repository: {m_data.get('repository')}")
    else:
        print("  (No candidate MCP servers awaiting triage)")

    print("\n" + "=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(description="Monthly Repository Maintenance Review & Decision Engine")
    parser.add_argument("--list", action="store_true", help="List all staged discovery candidates")
    parser.add_argument("--dossier", action="store_true", help="Display full monthly discovery dossier")
    parser.add_argument("--audit", action="store_true", help="Run security scans on all staged candidates")
    parser.add_argument("--accept", type=str, help="Accept and promote a skill or MCP by ID (or 'all-safe')")
    parser.add_argument("--reject", type=str, help="Reject a candidate by ID")
    parser.add_argument("--reason", type=str, default="Low quality or duplicate", help="Reason for rejection")
    parser.add_argument("--type", choices=["skill", "mcp"], default="skill", help="Type of candidate for accept/reject")
    args = parser.parse_args()

    candidates = collect_staged_candidates(REPO_ROOT)

    if args.dossier or args.list:
        print_dossier(candidates, REPO_ROOT)
        return 0

    if args.audit:
        audit_staged_candidates(candidates, REPO_ROOT)
        return 0

    if args.accept:
        if args.accept == "all-safe":
            audit_res = audit_staged_candidates(candidates, REPO_ROOT)
            print(f"\n[ACCEPT ALL SAFE] Promoting {len(audit_res['clean_skills'])} skills and {len(audit_res['clean_mcps'])} MCPs...")
            for sid in audit_res["clean_skills"]:
                accept_skill(sid, candidates, REPO_ROOT)
            for mid in audit_res["clean_mcps"]:
                accept_mcp(mid, candidates, REPO_ROOT)

            # Re-index catalog
            print("\n[RE-INDEX] Running npm run update:skills...")
            run_cmd(["npm", "run", "update:skills"])
            print("✅ All safe candidates promoted and catalog updated!")
            return 0
        else:
            if args.type == "skill":
                success = accept_skill(args.accept, candidates, REPO_ROOT)
            else:
                success = accept_mcp(args.accept, candidates, REPO_ROOT)

            if success:
                run_cmd(["npm", "run", "update:skills"])
            return 0 if success else 1

    if args.reject:
        success = reject_candidate(args.reject, args.type, args.reason, candidates, REPO_ROOT)
        return 0 if success else 1

    # Default action if no flag specified: show dossier
    print_dossier(candidates, REPO_ROOT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
