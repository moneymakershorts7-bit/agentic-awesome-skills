#!/usr/bin/env python3
"""
Bash Master CLI Helper
Autonomous agent companion tool providing unified CLI access to bash-master capabilities:
- BM25 vectorless corpus search across canonical literature
- FOSS toolchain matrix visualization and JSON export
- Independent verification battery (ShellCheck style, shfmt, checkbashisms, Bats)
- 30-Day documentation freshness cadence verification
- Full DevSecOps SecSDLC quality gate
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def find_bash_master_root() -> Path:
    """Locate the bash-master workspace root."""
    candidate = Path("/home/npirela/bash-master")
    if candidate.exists() and (candidate / "bin" / "bash-master").exists():
        return candidate
    cwd = Path.cwd().resolve()
    for parent in [cwd] + list(cwd.parents):
        if (parent / "bin" / "bash-master").exists():
            return parent
    return candidate


def cmd_search(args: argparse.Namespace) -> int:
    root = find_bash_master_root()
    bin_path = root / "bin" / "bash-master"
    if not bin_path.exists():
        print(f"Error: {bin_path} not found", file=sys.stderr)
        return 1
    res = subprocess.run([str(bin_path), "search-corpus", args.query, str(args.top_k)], cwd=root)
    return res.returncode


def cmd_matrix(args: argparse.Namespace) -> int:
    root = find_bash_master_root()
    bin_path = root / "bin" / "bash-master"
    if not bin_path.exists():
        print(f"Error: {bin_path} not found", file=sys.stderr)
        return 1
    subcmd = "export-toolchain" if args.json else "toolchain-matrix"
    res = subprocess.run([str(bin_path), subcmd], cwd=root)
    return res.returncode


def cmd_verify(args: argparse.Namespace) -> int:
    root = find_bash_master_root()
    bin_path = root / "bin" / "bash-master"
    if not bin_path.exists():
        print(f"Error: {bin_path} not found", file=sys.stderr)
        return 1
    target = Path(args.target_file).resolve()
    if not target.exists():
        print(f"Error: target file {target} does not exist", file=sys.stderr)
        return 1
    res = subprocess.run([str(bin_path), "verify", str(target)], cwd=root)
    return res.returncode


def cmd_cadence(args: argparse.Namespace) -> int:
    root = find_bash_master_root()
    bin_path = root / "bin" / "bash-master"
    if not bin_path.exists():
        print(f"Error: {bin_path} not found", file=sys.stderr)
        return 1
    res = subprocess.run([str(bin_path), "check-docs-cadence"], cwd=root)
    return res.returncode


def cmd_gate(args: argparse.Namespace) -> int:
    gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/bash_master_gate.py")
    if not gate_script.exists():
        print(f"Error: DevSecOps gate {gate_script} not found", file=sys.stderr)
        return 1
    target_dir = args.target_dir or str(find_bash_master_root())
    cmd = [sys.executable, str(gate_script), target_dir]
    if args.json:
        cmd.append("--json")
    res = subprocess.run(cmd)
    return res.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Bash Master Agent Companion CLI")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # search
    p_search = subparsers.add_parser("search", help="BM25 search canonical literature")
    p_search.add_argument("query", help="Exact terms or concepts to query")
    p_search.add_argument("--top-k", type=int, default=5, help="Number of results")
    p_search.set_defaults(func=cmd_search)

    # matrix
    p_matrix = subparsers.add_parser("matrix", help="Display 38+ FOSS toolchain matrix")
    p_matrix.add_argument("--json", action="store_true", help="Output JSON format")
    p_matrix.set_defaults(func=cmd_matrix)

    # verify
    p_verify = subparsers.add_parser("verify", help="Run independent verification battery")
    p_verify.add_argument("target_file", help="Shell script to audit")
    p_verify.set_defaults(func=cmd_verify)

    # cadence
    p_cadence = subparsers.add_parser("cadence", help="Verify 30-day documentation freshness")
    p_cadence.set_defaults(func=cmd_cadence)

    # gate
    p_gate = subparsers.add_parser("gate", help="Execute DevSecOps SecSDLC quality gate")
    p_gate.add_argument("target_dir", nargs="?", default=None, help="Target repository directory")
    p_gate.add_argument("--json", action="store_true", help="Output JSON format")
    p_gate.set_defaults(func=cmd_gate)

    parsed = parser.parse_args()
    sys.exit(parsed.func(parsed))


if __name__ == "__main__":
    main()
