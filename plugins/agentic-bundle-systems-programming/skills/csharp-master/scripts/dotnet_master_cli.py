#!/usr/bin/env python3
"""
dotnet_master_cli.py: Agent helper script for csharp-master operations.
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
    local_bin = Path("/home/npirela/csharp-master/bin/csharp-master")
    if local_bin.exists() and os.access(local_bin, os.X_OK):
        return str(local_bin)
    which_bin = shutil.which("csharp-master")
    if which_bin:
        return which_bin
    return "csharp-master"


def run_command(args: list[str]) -> int:
    binary = resolve_binary()
    cmd = [binary] + args
    res = subprocess.run(cmd)
    return res.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="csharp-master CLI agent helper")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    search_p = subparsers.add_parser("search-corpus", help="Search canonical .NET corpus")
    search_p.add_argument("--query", "-q", required=True, help="Search terms")

    subparsers.add_parser("check-docs-cadence", help="Verify 30-day documentation cadence")
    subparsers.add_parser("update-docs", help="Force refresh documentation hashes")
    subparsers.add_parser("audit-toolchain", help="Audit 38+ FOSS .NET toolchain")
    subparsers.add_parser("verify-slice", help="Verify sample slice execution")

    parsed, unknown = parser.parse_known_args()

    if parsed.subcommand == "search-corpus":
        return run_command(["search-corpus", "--query", parsed.query])
    elif parsed.subcommand == "check-docs-cadence":
        return run_command(["check-docs-cadence"])
    elif parsed.subcommand == "update-docs":
        return run_command(["update-docs"])
    elif parsed.subcommand == "audit-toolchain":
        return run_command(["audit-toolchain"])
    elif parsed.subcommand == "verify-slice":
        return run_command(["verify-slice"])

    return 1


if __name__ == "__main__":
    sys.exit(main())
