#!/usr/bin/env python3
"""
php_master_cli.py: Agent helper script for php-master operations.
Enables agents to orchestrate, verify slices, search the corpus, and inspect toolchains.
All methods adhere to Cyclomatic Complexity <= 10.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def resolve_binary() -> str:
    local_bin = Path("/home/npirela/php-master/bin/php-master")
    if local_bin.exists() and os.access(local_bin, os.X_OK):
        return str(local_bin)
    which_bin = shutil.which("php-master")
    if which_bin:
        return which_bin
    return "php-master"


def run_command(args: list[str]) -> int:
    binary = resolve_binary()
    cmd = [binary] + args
    res = subprocess.run(cmd, shell=False)
    return res.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="php-master CLI agent helper")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    search_p = subparsers.add_parser("search-corpus", help="Search canonical PHP corpus")
    search_p.add_argument("--query", "-q", required=True, help="Search terms")

    subparsers.add_parser("check-docs-cadence", help="Verify 30-day documentation cadence")
    subparsers.add_parser("update-docs", help="Force refresh documentation hashes")

    decomp_p = subparsers.add_parser("decompose-task", help="Decompose goal into contracts")
    decomp_p.add_argument("--goal", required=True, help="Goal description")

    exec_p = subparsers.add_parser("execute-contract", help="Execute contract through FSM")
    exec_p.add_argument("--file", "-f", required=True, help="Path to contract JSON file")

    subparsers.add_parser("audit-toolchain", help="Audit 38+ FOSS PHP toolchain")

    verify_p = subparsers.add_parser("verify-slice", help="Verify sample slice execution")
    verify_p.add_argument("--slice", required=True, help="Slice ID")

    inv_p = subparsers.add_parser("agent-invariants", help="Display agent invariants")
    inv_p.add_argument("--agent", help="Filter by agent type")

    parsed, unknown = parser.parse_known_args()

    if parsed.subcommand == "search-corpus":
        return run_command(["search-corpus", "--query", parsed.query])
    elif parsed.subcommand == "check-docs-cadence":
        return run_command(["check-docs-cadence"])
    elif parsed.subcommand == "update-docs":
        return run_command(["update-docs"])
    elif parsed.subcommand == "decompose-task":
        return run_command(["decompose-task", "--goal", parsed.goal])
    elif parsed.subcommand == "execute-contract":
        return run_command(["execute-contract", "--file", parsed.file])
    elif parsed.subcommand == "audit-toolchain":
        return run_command(["audit-toolchain"])
    elif parsed.subcommand == "verify-slice":
        return run_command(["verify-slice", "--slice", parsed.slice])
    elif parsed.subcommand == "agent-invariants":
        args = ["agent-invariants"]
        if parsed.agent:
            args.extend(["--agent", parsed.agent])
        return run_command(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
