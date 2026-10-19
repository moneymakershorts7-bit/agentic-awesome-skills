#!/usr/bin/env python3
"""
API Master CLI Helper Script for Agent Workflows.
Enables agents to orchestrate, search literature, validate contracts, and execute gates.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def resolve_api_master_bin() -> str | None:
    """Locate api-master executable binary."""
    venv_bin = Path("/home/npirela/api-master/.venv/bin/api-master")
    if venv_bin.exists() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)
    return shutil.which("api-master")


def main():
    parser = argparse.ArgumentParser(description="API Master Agent CLI Helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    subparsers.add_parser("status", help="Show platform status and agent fleet health")

    # toolchain
    subparsers.add_parser("toolchain", help="Inspect 38+ FOSS toolchain matrix")

    # search-corpus
    search_p = subparsers.add_parser("search-corpus", help="Search canonical literature")
    search_p.add_argument("--query", "-q", required=True, help="Search query")
    search_p.add_argument("--top-k", "-k", type=int, default=5, help="Number of results")

    # validate-contract
    val_p = subparsers.add_parser("validate-contract", help="Validate TaskPlaybookContract JSON")
    val_p.add_argument("--file", "-f", required=True, help="Contract file path")

    # dispatch
    disp_p = subparsers.add_parser("dispatch", help="Execute work slice through FSM")
    disp_p.add_argument("--file", "-f", required=True, help="Contract file path")

    # check-docs-cadence
    subparsers.add_parser("check-docs-cadence", help="Verify 30-day documentation freshness")

    # gate
    gate_p = subparsers.add_parser("gate", help="Run DevSecOps API Master Gate")
    gate_p.add_argument("target", nargs="?", default="/home/npirela/api-master", help="Target dir")

    args = parser.parse_args()
    api_master_bin = resolve_api_master_bin()

    if args.command in ("status", "toolchain", "check-docs-cadence"):
        if not api_master_bin:
            print("Error: api-master binary not found.", file=sys.stderr)
            sys.exit(1)
        proc = subprocess.run([api_master_bin, args.command])
        sys.exit(proc.returncode)

    elif args.command == "search-corpus":
        if not api_master_bin:
            print("Error: api-master binary not found.", file=sys.stderr)
            sys.exit(1)
        proc = subprocess.run([api_master_bin, "search-corpus", "--query", args.query, "--top-k", str(args.top_k)])
        sys.exit(proc.returncode)

    elif args.command in ("validate-contract", "dispatch"):
        if not api_master_bin:
            print("Error: api-master binary not found.", file=sys.stderr)
            sys.exit(1)
        proc = subprocess.run([api_master_bin, args.command, "--file", args.file])
        sys.exit(proc.returncode)

    elif args.command == "gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/api_master_gate.py")
        if not gate_script.exists():
            print(f"Error: Gate script {gate_script} not found.", file=sys.stderr)
            sys.exit(1)
        proc = subprocess.run([sys.executable, str(gate_script), args.target])
        sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
