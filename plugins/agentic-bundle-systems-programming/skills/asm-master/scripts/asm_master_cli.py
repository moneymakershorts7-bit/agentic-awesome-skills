#!/usr/bin/env python3
"""
asm-master Agent CLI Helper Script
Provides agents with direct programmatic access to:
- Task + Playbook Contract execution & FSM transitions
- Canonical literature search (BM25/TF-IDF)
- 38+ FOSS Assembly Toolchain Matrix auditing
- 30-Day Documentation Freshness Cadence checking
- DevSecOps SecSDLC Quality Gate execution
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path("/home/npirela/asm-master")


def run_command(cmd: list[str]) -> int:
    return subprocess.run(cmd, cwd=str(REPO_ROOT), shell=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="asm-master Agent CLI Orchestrator")
    subparsers = parser.add_subparsers(dest="subcommand", help="Operational Subcommands")

    # 1. run-contract
    p_contract = subparsers.add_parser("run-contract", help="Execute Task + Playbook Contract")
    p_contract.add_argument("contract_file", help="Path to JSON contract file")
    p_contract.add_argument("--max-retries", type=int, default=3, help="Max self-healing loops")

    # 2. search-corpus
    p_search = subparsers.add_parser("search-corpus", help="Query canonical literature via BM25")
    p_search.add_argument("--query", "-q", required=True, help="Search query")
    p_search.add_argument("--top-k", type=int, default=5, help="Top matches count")

    # 3. toolchain-matrix
    p_tools = subparsers.add_parser("toolchain-matrix", help="Inspect 38+ FOSS Assembly tools")
    p_tools.add_argument("--json", action="store_true", help="Output JSON format")

    # 4. check-cadence
    p_cadence = subparsers.add_parser("check-cadence", help="Audit 30-day documentation freshness")

    # 5. run-gate
    p_gate = subparsers.add_parser("run-gate", help="Execute DevSecOps SecSDLC Gate")
    p_gate.add_argument("target_dir", nargs="?", default=str(REPO_ROOT), help="Project target directory")
    p_gate.add_argument("--json", action="store_true", help="Output JSON format")

    # 6. test
    p_test = subparsers.add_parser("test", help="Execute full verification battery")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "run-contract":
        cmd = ["python3", str(REPO_ROOT / "tools" / "contract_runner.py"), args.contract_file, "--max-retries", str(args.max_retries)]
        return run_command(cmd)

    elif args.subcommand == "search-corpus":
        cmd = ["python3", str(REPO_ROOT / "tools" / "corpus_search.py"), "--query", args.query, "--top-k", str(args.top_k)]
        return run_command(cmd)

    elif args.subcommand == "toolchain-matrix":
        cmd = ["python3", str(REPO_ROOT / "tools" / "toolchain_matrix.py")]
        if args.json:
            cmd.append("--json")
        return run_command(cmd)

    elif args.subcommand == "check-cadence":
        cmd = ["python3", str(REPO_ROOT / "tools" / "cadence_manager.py"), "--check"]
        return run_command(cmd)

    elif args.subcommand == "run-gate":
        cmd = ["python3", "/home/npirela/.agents/skills/devsecops-master/scripts/asm_master_gate.py", args.target_dir]
        if args.json:
            cmd.append("--json")
        return run_command(cmd)

    elif args.subcommand == "test":
        return run_command(["make", "test"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
