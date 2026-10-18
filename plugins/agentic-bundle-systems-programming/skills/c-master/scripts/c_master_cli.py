#!/usr/bin/env python3
"""
c_master_cli.py: Agent CLI Helper for Project c-master
Allows agents to execute orchestration, corpus queries, toolchain probing,
documentation cadence auditing, and SecSDLC gates.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def resolve_c_master_binary() -> Path:
    candidates = [
        Path("/home/npirela/c-master/bin/c-master"),
        Path("/home/npirela/c-master/build/bin/c-master"),
        Path("./bin/c-master"),
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    raise FileNotFoundError("c-master binary not found. Build c-master first using cmake.")


def main():
    parser = argparse.ArgumentParser(description="c-master Agent Helper CLI")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # search-corpus
    search_p = subparsers.add_parser("search-corpus", help="Search canonical C literature")
    search_p.add_argument("--query", required=True, help="Search query keyword")

    # check-docs-cadence
    subparsers.add_parser("check-docs-cadence", help="Audit 30-day documentation freshness cadence")

    # update-docs
    update_p = subparsers.add_parser("update-docs", help="Refresh .docs_manifest.json")
    update_p.add_argument("--force", action="store_true", help="Force update review horizon")

    # toolchain
    subparsers.add_parser("toolchain", help="Catalog and probe 38+ FOSS C toolchain")

    # orchestrate
    orch_p = subparsers.add_parser("orchestrate", help="Run multi-agent orchestration")
    orch_p.add_argument("--goal", default="Build high-throughput network engine", help="High-level engineering goal")

    # verify / gate
    subparsers.add_parser("verify", help="Run independent adversarial verifier gate")
    subparsers.add_parser("gate", help="Run DevSecOps SecSDLC gate")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    repo_dir = Path("/home/npirela/c-master").resolve()

    if args.command == "gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/c_master_gate.py")
        if not gate_script.exists():
            print(f"Error: Gate script {gate_script} not found.", file=sys.stderr)
            sys.exit(1)
        res = subprocess.run([sys.executable, str(gate_script), str(repo_dir)])
        sys.exit(res.returncode)

    try:
        binary = resolve_c_master_binary()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    cmd = [str(binary), args.command]
    if args.command == "search-corpus":
        cmd.extend(["--query", args.query])
    elif args.command == "update-docs" and args.force:
        cmd.append("--force")
    elif args.command == "orchestrate":
        cmd.extend(["--goal", args.goal])

    res = subprocess.run(cmd, cwd=repo_dir)
    sys.exit(res.returncode)


if __name__ == "__main__":
    main()
