#!/usr/bin/env python3
"""
swift_master_cli.py: Agent CLI Helper for Project swift-master
Allows agents to execute orchestration, corpus queries, toolchain probing,
documentation cadence auditing, and SecSDLC gates.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def resolve_swift_master_binary() -> Path:
    candidates = [
        Path("/home/npirela/swift-master/.build/release/swift-master"),
        Path("/home/npirela/swift-master/.build/debug/swift-master"),
        Path("./.build/release/swift-master"),
        Path("./.build/debug/swift-master"),
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    raise FileNotFoundError("swift-master binary not found. Build swift-master first using 'swift build'.")


def main():
    parser = argparse.ArgumentParser(description="swift-master Agent Helper CLI")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # search-corpus
    search_p = subparsers.add_parser("search-corpus", help="Search canonical Swift literature")
    search_p.add_argument("--query", required=True, help="Search query keyword")

    # check-docs-cadence
    subparsers.add_parser("check-docs-cadence", help="Audit 30-day documentation freshness cadence")

    # update-docs
    update_p = subparsers.add_parser("update-docs", help="Refresh .docs_manifest.json")
    update_p.add_argument("--force", action="store_true", help="Force update review horizon")

    # toolchain
    subparsers.add_parser("toolchain-matrix", help="Catalog and probe 38+ FOSS Swift toolchain")

    # orchestrate
    orch_p = subparsers.add_parser("orchestrate", help="Run multi-agent orchestration")
    orch_p.add_argument("--task", required=True, help="Path to TaskPlaybookContract JSON file")

    # self-test
    subparsers.add_parser("self-test", help="Run internal platform health check")

    # gate
    gate_p = subparsers.add_parser("gate", help="Run DevSecOps SecSDLC gate")
    gate_p.add_argument("--strict", action="store_true", help="Enforce zero-tolerance failure threshold")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    repo_dir = Path("/home/npirela/swift-master").resolve()

    if args.command == "gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/swift_master_gate.py")
        if not gate_script.exists():
            print(f"Error: Gate script {gate_script} not found.", file=sys.stderr)
            sys.exit(1)
        cmd = [sys.executable, str(gate_script), "--target", str(repo_dir)]
        if args.strict:
            cmd.append("--strict")
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

    try:
        binary = resolve_swift_master_binary()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    cmd = [str(binary), args.command]
    if args.command == "search-corpus":
        cmd.extend(["--query", args.query])
    elif args.command == "orchestrate":
        cmd.extend(["--task", args.task])
    elif args.command == "update-docs" and args.force:
        cmd.append("--force")

    res = subprocess.run(cmd, cwd=repo_dir)
    sys.exit(res.returncode)


if __name__ == "__main__":
    main()
