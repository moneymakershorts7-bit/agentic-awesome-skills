#!/usr/bin/env python3
"""
ruby_master_cli.py: Agent CLI Helper for Project ruby-master
Allows agents to execute orchestration, corpus queries, toolchain probing,
documentation cadence auditing, and SecSDLC gates.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def resolve_ruby_master_binary() -> Path:
    candidates = [
        Path("/home/npirela/ruby-master/bin/ruby-master"),
        Path("/home/npirela/.local/bin/ruby-master"),
        Path("./bin/ruby-master"),
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    raise FileNotFoundError("ruby-master binary not found at /home/npirela/ruby-master/bin/ruby-master")


def main():
    parser = argparse.ArgumentParser(description="ruby-master Agent Helper CLI")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # search-corpus
    search_p = subparsers.add_parser("search-corpus", help="Search canonical Ruby literature")
    search_p.add_argument("--query", required=True, help="Search query keyword")
    search_p.add_argument("--limit", type=int, default=5, help="Result limit")

    # check-docs-cadence
    subparsers.add_parser("check-docs-cadence", help="Audit 30-day documentation freshness cadence")

    # update-docs
    update_p = subparsers.add_parser("update-docs", help="Refresh .docs_manifest.json")
    update_p.add_argument("--force", action="store_true", help="Force update review horizon")

    # toolchain-matrix
    tool_p = subparsers.add_parser("toolchain-matrix", help="Catalog and probe 38+ FOSS Ruby toolchain")
    tool_p.add_argument("--category", help="Filter by toolchain category")

    # decompose-goal
    decomp_p = subparsers.add_parser("decompose-goal", help="Decompose goal into TaskPlaybook contracts")
    decomp_p.add_argument("--goal", required=True, help="Goal description")

    # execute-contract
    exec_p = subparsers.add_parser("execute-contract", help="Dispatch contract through FSM to worker & verifier-qa")
    exec_p.add_argument("--file", required=True, help="Path to contract JSON file")

    # self-test
    subparsers.add_parser("self-test", help="Run internal test suite")

    # gate
    subparsers.add_parser("gate", help="Run DevSecOps SecSDLC gate")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    bin_path = resolve_ruby_master_binary()

    if args.command == "search-corpus":
        cmd = [str(bin_path), "search-corpus", "--query", args.query, "--limit", str(args.limit)]
        sys.exit(subprocess.run(cmd).returncode)

    if args.command == "check-docs-cadence":
        cmd = [str(bin_path), "check-docs-cadence"]
        sys.exit(subprocess.run(cmd).returncode)

    if args.command == "update-docs":
        cmd = [str(bin_path), "update-docs"]
        if args.force:
            cmd.append("--force")
        sys.exit(subprocess.run(cmd).returncode)

    if args.command == "toolchain-matrix":
        cmd = [str(bin_path), "toolchain-matrix"]
        if args.category:
            cmd.extend(["--category", args.category])
        sys.exit(subprocess.run(cmd).returncode)

    if args.command == "decompose-goal":
        cmd = [str(bin_path), "decompose-goal", "--goal", args.goal]
        sys.exit(subprocess.run(cmd).returncode)

    if args.command == "execute-contract":
        cmd = [str(bin_path), "execute-contract", "--file", args.file]
        sys.exit(subprocess.run(cmd).returncode)

    if args.command == "self-test":
        cmd = ["rspec"]
        sys.exit(subprocess.run(cmd, cwd="/home/npirela/ruby-master").returncode)

    if args.command == "gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/ruby_master_gate.py")
        cmd = [sys.executable, str(gate_script), "/home/npirela/ruby-master"]
        sys.exit(subprocess.run(cmd).returncode)


if __name__ == "__main__":
    main()
