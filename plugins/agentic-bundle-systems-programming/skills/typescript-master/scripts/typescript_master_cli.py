#!/usr/bin/env python3
"""
typescript_master_cli.py - Universal Agent Driver for typescript-master platform.
Provides workspace discovery, command execution, and JSON reporting for agents.
All functions adhere to Cyclomatic Complexity <= 10.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_typescript_master_binary() -> Path | None:
    """Resolve compiled typescript-master binary or fallback."""
    base_dir = Path("/home/npirela/typescript-master")
    bin_path = base_dir / "bin" / "typescript-master"
    if bin_path.exists() and os.access(bin_path, os.X_OK):
        return bin_path

    system_bin = shutil.which("typescript-master")
    if system_bin:
        return Path(system_bin)

    return None


def run_typescript_master(args: list[str], cwd: Path | None = None) -> int:
    """Execute typescript-master launcher directly or via bun/node."""
    bin_path = find_typescript_master_binary()
    work_dir = cwd if cwd is not None else Path("/home/npirela/typescript-master")

    if bin_path:
        cmd = [str(bin_path)] + args
    else:
        cmd = ["bun", str(work_dir / "src" / "cli" / "main.ts")] + args

    print(f"Executing: {' '.join(cmd)} in {work_dir}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=work_dir, shell=False, check=False)
    return res.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Helper CLI for typescript-master autonomous platform")
    parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        default=Path("/home/npirela/typescript-master"),
        help="Base workspace path of typescript-master (default: /home/npirela/typescript-master)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Orchestrate
    orch_p = subparsers.add_parser("orchestrate", help="Run Lead Orchestrator across bounded slices")
    orch_p.add_argument("--goal", default="RATE-LIMITER", help="Goal identifier or description")

    # Verify
    subparsers.add_parser("verify", help="Execute adversarial verification gate")

    # Search Corpus
    search_p = subparsers.add_parser("search-corpus", help="BM25 literature search")
    search_p.add_argument("--query", "-q", required=True, help="Search query string")

    # Check Docs Cadence
    subparsers.add_parser("check-docs-cadence", help="Audit 30-day documentation freshness")

    # Update Docs
    up_p = subparsers.add_parser("update-docs", help="Refresh documentation manifest")
    up_p.add_argument("--force", action="store_true", help="Force manifest regeneration")

    # Toolchain
    subparsers.add_parser("toolchain", help="Inspect 38+ FOSS toolchain matrix")

    parsed_args = parser.parse_args()

    cli_args: list[str] = [parsed_args.command]
    if parsed_args.command == "orchestrate":
        cli_args.extend(["--goal", parsed_args.goal])
    elif parsed_args.command == "search-corpus":
        cli_args.extend(["--query", parsed_args.query])
    elif parsed_args.command == "update-docs" and parsed_args.force:
        cli_args.append("--force")

    ret = run_typescript_master(cli_args, cwd=parsed_args.workspace)
    sys.exit(ret)


if __name__ == "__main__":
    main()
