#!/usr/bin/env python3
"""
cpp_master_cli.py - Python CLI helper for cpp-master autonomous C++ platform.
Dispatches subcommands to the pure C++ cpp-master binary located in build/bin/cpp-master.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def find_cpp_master_binary(workspace: Path) -> Path:
    """Locate cpp-master binary."""
    # 1. Check workspace build/bin/cpp-master
    candidate = workspace / "build" / "bin" / "cpp-master"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return candidate

    # 2. Check canonical home workspace
    canonical = Path("/home/npirela/cpp-master/build/bin/cpp-master")
    if canonical.exists() and os.access(canonical, os.X_OK):
        return canonical

    raise FileNotFoundError("cpp-master binary not found. Run 'cmake --build build' in /home/npirela/cpp-master.")


def run_cpp_master(args: list[str], workspace: Path) -> int:
    """Execute cpp-master command with arguments."""
    try:
        binary = find_cpp_master_binary(workspace)
        cmd = [str(binary)] + args
        print(f"[cpp-master-cli] Executing: {' '.join(cmd)} in {workspace}", file=sys.stderr)
        res = subprocess.run(cmd, cwd=workspace, check=False)
        return res.returncode
    except Exception as e:
        print(f"[cpp-master-cli] Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Helper CLI for cpp-master Autonomous Platform")
    parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        default=Path("/home/npirela/cpp-master"),
        help="Workspace root of cpp-master",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Search Corpus
    p_search = subparsers.add_parser("search-corpus", help="Query BM25 C++ canonical literature")
    p_search.add_argument("query", help="Search query string")
    p_search.add_argument("--limit", "-n", type=int, default=5, help="Number of results")

    # Check Docs Cadence
    subparsers.add_parser("check-docs-cadence", help="Verify 30-day documentation freshness manifest")

    # Update Docs
    p_update = subparsers.add_parser("update-docs", help="Update doc hashes in .docs_manifest.json")
    p_update.add_argument("--force", action="store_true", help="Force update timestamp and hashes")

    # Toolchain
    subparsers.add_parser("toolchain", help="Audit and list 40+ canonical C++ FOSS tools")

    # Orchestrate
    p_orch = subparsers.add_parser("orchestrate", help="Run Lead Orchestrator across domain slices")
    p_orch.add_argument("goal", help="Engineering goal to decompose and execute")

    # Verify
    subparsers.add_parser("verify", help="Run independent adversarial QA verifier battery")

    # SecSDLC Quality Gate
    subparsers.add_parser("gate", help="Run DevSecOps SecSDLC quality gate")

    args = parser.parse_args()
    ws = args.workspace

    if args.subcommand == "search-corpus":
        return run_cpp_master(["search-corpus", "--query", args.query, "--limit", str(args.limit)], ws)
    elif args.subcommand == "check-docs-cadence":
        return run_cpp_master(["check-docs-cadence"], ws)
    elif args.subcommand == "update-docs":
        cmd_args = ["update-docs"]
        if args.force:
            cmd_args.append("--force")
        return run_cpp_master(cmd_args, ws)
    elif args.subcommand == "toolchain":
        return run_cpp_master(["toolchain"], ws)
    elif args.subcommand == "orchestrate":
        return run_cpp_master(["orchestrate", "--goal", args.goal], ws)
    elif args.subcommand == "verify":
        return run_cpp_master(["verify"], ws)
    elif args.subcommand == "gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/cpp_master_gate.py")
        if gate_script.exists():
            res = subprocess.run([sys.executable, str(gate_script), str(ws)], check=False)
            return res.returncode
        return run_cpp_master(["check-docs-cadence"], ws)

    return 1


if __name__ == "__main__":
    sys.exit(main())
