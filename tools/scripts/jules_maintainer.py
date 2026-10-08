#!/usr/bin/env python3
"""
jules_maintainer.py: Google Jules Autonomous Coding Agent Orchestrator
CLI and programmatic controller for Google Jules REST API (v1alpha) & CLI:
- Dispatch asynchronous cloud maintenance tasks
- Resolve GitHub issues into automated Pull Requests
- Monitor active cloud sessions, plans, and execution traces
- Proactively sweep repository health, security, and documentation
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from _project_paths import find_repo_root
    REPO_ROOT = find_repo_root(__file__)
except Exception:
    REPO_ROOT = Path(__file__).resolve().parents[2]

JULES_API_BASE = "https://jules.googleapis.com/v1alpha"
GITHUB_REPO_DEFAULT = "moneymakershorts7-bit/agentic-awesome-skills"


def get_api_key() -> Optional[str]:
    """Retrieve Jules API key from environment or ~/.config/jules/env."""
    key = os.environ.get("JULES_API_KEY")
    if key:
        return key.strip()
    config_file = Path.home() / ".config" / "jules" / "env"
    if config_file.exists():
        try:
            for line in config_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("JULES_API_KEY="):
                    return line.partition("=")[2].strip().strip('"').strip("'")
        except Exception:
            pass
    return None


def jules_api_request(
    endpoint: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute authenticated REST request to Google Jules API."""
    key = api_key or get_api_key()
    if not key:
        raise ValueError(
            "JULES_API_KEY is not set. Generate an API key at https://jules.google.com -> Settings "
            "and export JULES_API_KEY or save in ~/.config/jules/env."
        )

    url = f"{JULES_API_BASE}/{endpoint.lstrip('/')}"
    headers = {
        "x-goog-api-key": key,
        "Content-Type": "application/json",
        "User-Agent": "Jules-Maintainer/1.0 (Agentic Awesome Skills)",
    }

    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Jules API HTTP {e.code} Error ({e.reason}): {err_body}") from None
    except Exception as e:
        raise RuntimeError(f"Jules API network error: {e}") from None


def list_sources(api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all connected GitHub repositories in Jules."""
    res = jules_api_request("sources", method="GET", api_key=api_key)
    return res.get("sources", [])


def list_sessions(api_key: Optional[str] = None, page_size: int = 20) -> List[Dict[str, Any]]:
    """List recent Jules coding sessions."""
    res = jules_api_request(f"sessions?pageSize={page_size}", method="GET", api_key=api_key)
    return res.get("sessions", [])


def get_session(session_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve details and PR output of a session."""
    clean_id = session_id.replace("sessions/", "")
    return jules_api_request(f"sessions/{clean_id}", method="GET", api_key=api_key)


def get_session_activities(session_id: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve reasoning steps, logs, and activity timeline for a session."""
    clean_id = session_id.replace("sessions/", "")
    res = jules_api_request(f"sessions/{clean_id}/activities?pageSize=50", method="GET", api_key=api_key)
    return res.get("activities", [])


def create_session(
    prompt: str,
    title: str = "Autonomous Maintenance",
    repo: str = GITHUB_REPO_DEFAULT,
    starting_branch: str = "main",
    auto_pr: bool = True,
    require_approval: bool = False,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Dispatch an asynchronous coding task to Jules Cloud VM."""
    payload = {
        "prompt": prompt,
        "title": title,
        "sourceContext": {
            "source": f"sources/github/{repo}",
            "githubRepoContext": {
                "startingBranch": starting_branch,
            },
        },
        "automationMode": "AUTO_CREATE_PR" if auto_pr else "DEFAULT",
        "requirePlanApproval": require_approval,
    }
    return jules_api_request("sessions", method="POST", payload=payload, api_key=api_key)


def resolve_github_issue(
    issue_number: int,
    repo: str = GITHUB_REPO_DEFAULT,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch GitHub issue details via `gh` CLI and dispatch solution task to Jules."""
    print(f"🔍 Fetching GitHub Issue #{issue_number} from {repo}...")
    try:
        res = subprocess.run(
            ["gh", "issue", "view", str(issue_number), "--repo", repo, "--json", "title,body,labels"],
            check=True,
            capture_output=True,
            text=True,
        )
        issue_data = json.loads(res.stdout)
    except Exception as e:
        raise RuntimeError(f"Failed to fetch issue #{issue_number} via GitHub CLI: {e}") from None

    title = issue_data.get("title", f"Issue #{issue_number}")
    body = issue_data.get("body", "No description provided.")
    labels = [label.get("name", "") for label in issue_data.get("labels", [])]

    prompt = (
        f"Act as the Autonomous Lead Developer for {repo}. Resolve GitHub Issue #{issue_number}:\n\n"
        f"### Title: {title}\n"
        f"### Labels: {', '.join(labels)}\n\n"
        f"### Issue Description:\n{body}\n\n"
        f"### Instructions:\n"
        f"1. Follow AGENTS.md guidelines.\n"
        f"2. Implement the required fixes or features cleanly with zero regressions.\n"
        f"3. Run `npm run validate` and tests to verify.\n"
        f"4. Follow Conventional Commits format.\n"
        f"5. Automatically open a Pull Request addressing Issue #{issue_number}."
    )

    session_title = f"Fix Issue #{issue_number}: {title[:40]}"
    print(f"🚀 Dispatching solution task to Google Jules Cloud...")
    session = create_session(
        prompt=prompt,
        title=session_title,
        repo=repo,
        auto_pr=True,
        api_key=api_key,
    )
    return session


def main():
    parser = argparse.ArgumentParser(description="Google Jules Autonomous Coding Agent Orchestrator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    list_parser = subparsers.add_parser("list", help="List sessions or connected sources")
    list_parser.add_argument("--sources", action="store_true", help="List connected repositories instead of sessions")

    # dispatch
    dispatch_parser = subparsers.add_parser("dispatch", help="Dispatch an autonomous coding prompt to Jules")
    dispatch_parser.add_argument("prompt", help="Instructions for Jules")
    dispatch_parser.add_argument("--title", default="Autonomous Task", help="Short title for session")
    dispatch_parser.add_argument("--repo", default=GITHUB_REPO_DEFAULT, help="Target GitHub repo (owner/repo)")
    dispatch_parser.add_argument("--branch", default="main", help="Starting branch")

    # resolve-issue
    issue_parser = subparsers.add_parser("resolve-issue", help="Dispatch GitHub issue resolution to Jules")
    issue_parser.add_argument("issue_number", type=int, help="GitHub issue number")
    issue_parser.add_argument("--repo", default=GITHUB_REPO_DEFAULT, help="Target GitHub repo (owner/repo)")

    # status
    status_parser = subparsers.add_parser("status", help="Get session status & PR outputs")
    status_parser.add_argument("session_id", help="Jules session ID")

    # activities
    act_parser = subparsers.add_parser("activities", help="View reasoning and execution activities")
    act_parser.add_argument("session_id", help="Jules session ID")

    args = parser.parse_args()

    try:
        if args.command == "list":
            if args.sources:
                sources = list_sources()
                print(f"Connected Repositories ({len(sources)}):")
                for s in sources:
                    print(f"  • {s.get('id', s.get('name'))}")
            else:
                sessions = list_sessions()
                print(f"Recent Jules Sessions ({len(sessions)}):")
                for s in sessions:
                    sid = s.get("id", s.get("name", "")).replace("sessions/", "")
                    title = s.get("title", "Untitled")
                    state = s.get("state", "UNKNOWN")
                    print(f"  • [{state}] {sid} — {title}")

        elif args.command == "dispatch":
            print(f"Dispatching task to Google Jules for {args.repo}...")
            session = create_session(args.prompt, title=args.title, repo=args.repo, starting_branch=args.branch)
            sid = session.get("id", session.get("name", ""))
            print(f"✅ Session successfully created: {sid}")
            print(f"   Jules Cloud VM is now executing in background with automatic PR creation.")

        elif args.command == "resolve-issue":
            session = resolve_github_issue(args.issue_number, repo=args.repo)
            sid = session.get("id", session.get("name", ""))
            print(f"✅ Issue #{args.issue_number} handed off to Jules session: {sid}")

        elif args.command == "status":
            sess = get_session(args.session_id)
            print(json.dumps(sess, indent=2))

        elif args.command == "activities":
            acts = get_session_activities(args.session_id)
            print(f"Activities for session {args.session_id} ({len(acts)}):")
            for a in acts:
                desc = a.get("description", a.get("message", ""))
                print(f"  [{a.get('type', 'EVENT')}] {desc}")

    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
