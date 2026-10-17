#!/usr/bin/env python3
"""
markup_master_cli.py - Universal Agent Driver for markup-master platform.
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


def find_markup_master_binary() -> Path | None:
    """Resolve compiled markup-master binary or fallback."""
    base_dir = Path("/home/npirela/markup-master")
    bin_path = base_dir / "bin" / "markup-master"
    if bin_path.exists() and os.access(bin_path, os.X_OK):
        return bin_path

    system_bin = shutil.which("markup-master")
    if system_bin:
        return Path(system_bin)

    return None


def run_markup_master(args: list[str], cwd: Path | None = None) -> int:
    """Execute markup-master launcher directly or via python3."""
    bin_path = find_markup_master_binary()
    work_dir = cwd if cwd is not None else Path("/home/npirela/markup-master")

    if bin_path:
        cmd = [str(bin_path)] + args
    else:
        cmd = ["python3", "-m", "markup_master.cli"] + args

    print(f"Executing: {' '.join(cmd)} in {work_dir}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=work_dir, shell=False, check=False)
    return res.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Helper CLI for markup-master autonomous platform")
    parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        default=Path("/home/npirela/markup-master"),
        help="Base workspace path of markup-master (default: /home/npirela/markup-master)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Orchestrate
    orch_p = subparsers.add_parser("orchestrate", help="Run Lead Orchestrator across target files")
    orch_p.add_argument("files", nargs="+", help="Target files to orchestrate")
    orch_p.add_argument("--write", action="store_true", help="Write healed files to disk")

    # Verify
    ver_p = subparsers.add_parser("verify", help="Run independent adversarial verification")
    ver_p.add_argument("files", nargs="+", help="Target files to verify")

    # Search
    search_p = subparsers.add_parser("search-corpus", help="Search offline standards corpus")
    search_p.add_argument("--query", "-q", required=True, help="Search query")
    search_p.add_argument("--top-k", "-k", type=int, default=5, help="Number of results")

    # Cadence
    subparsers.add_parser("check-docs-cadence", help="Inspect documentation freshness cadence")
    subparsers.add_parser("update-docs", help="Refresh documentation hashes")

    # Toolchain
    subparsers.add_parser("toolchain", help="Inspect 38+ FOSS markup tools matrix")

    parsed, remaining = parser.parse_known_args()
    forward_args = [parsed.command]

    if parsed.command == "orchestrate":
        forward_args.extend(parsed.files)
        if parsed.write:
            forward_args.append("--write")
    elif parsed.command == "verify":
        forward_args.extend(parsed.files)
    elif parsed.command == "search-corpus":
        forward_args.extend(["--query", parsed.query, "--top-k", str(parsed.top_k)])

    forward_args.extend(remaining)
    sys.exit(run_markup_master(forward_args, cwd=parsed.workspace))


if __name__ == "__main__":
    main()
