#!/usr/bin/env python3
"""
go_master_cli.py - Helper CLI for interacting with the go-master agent platform.
Provides workspace discovery, command execution, and JSON reporting for agents.
Adheres strictly to the Tool-Pragmatic Standard (external driver only).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_go_master_binary() -> Path | None:
    """Resolve compiled go-master binary or fallback."""
    base_dir = Path("/home/npirela/go-master")
    bin_path = base_dir / "bin" / "go-master"
    if bin_path.exists() and os.access(bin_path, os.X_OK):
        return bin_path

    system_bin = shutil.which("go-master")
    if system_bin:
        return Path(system_bin)

    return None


def run_go_master(args: list[str], cwd: Path | None = None) -> int:
    """Execute go-master command directly or via go run."""
    bin_path = find_go_master_binary()
    work_dir = cwd if cwd is not None else Path("/home/npirela/go-master")

    if bin_path:
        cmd = [str(bin_path)] + args
    else:
        cmd = ["go", "run", "./cmd/go-master"] + args

    print(f"Executing: {' '.join(cmd)} in {work_dir}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=work_dir, shell=False, check=False)
    return res.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Helper CLI for go-master autonomous platform")
    parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        default=Path("/home/npirela/go-master"),
        help="Base workspace path of go-master (default: /home/npirela/go-master)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Orchestrate
    orch_p = subparsers.add_parser("orchestrate", help="Run Lead Orchestrator across bounded slices")
    orch_p.add_argument("--contract", "-c", type=str, default="", help="Path to contract JSON")

    # Verify
    verify_p = subparsers.add_parser("verify", help="Run Independent Adversarial QA Gate")
    verify_p.add_argument("--contract", "-c", type=str, default="", help="Path to contract JSON")

    # Search Corpus
    search_p = subparsers.add_parser("search-corpus", help="Search canonical Go literature with TF-IDF")
    search_p.add_argument("--query", "-q", type=str, required=True, help="Search keywords")
    search_p.add_argument("--top", "-t", type=int, default=5, help="Number of results")

    # Cadence
    subparsers.add_parser("check-docs-cadence", help="Inspect 30-day documentation freshness manifest")
    subparsers.add_parser("update-docs", help="Refresh documentation manifest and scan corpus")

    # Toolchain
    subparsers.add_parser("toolchain-audit", help="Audit and detect 38+ canonical Go FOSS tools")

    # Agents
    subparsers.add_parser("list-agents", help="List specialized Go domain agents")

    # DevSecOps Gate
    gate_p = subparsers.add_parser("sec-gate", help="Run DevSecOps SecSDLC quality gate")
    gate_p.add_argument("target", nargs="?", default=".", help="Target directory for SecSDLC audit")

    parsed, remaining = parser.parse_known_args()

    if parsed.command == "orchestrate":
        cmd_args = ["orchestrate"]
        if parsed.contract:
            cmd_args.extend(["--contract", parsed.contract])
        sys.exit(run_go_master(cmd_args, parsed.workspace))

    elif parsed.command == "verify":
        cmd_args = ["verify-slice"]
        if parsed.contract:
            cmd_args.extend(["--contract", parsed.contract])
        sys.exit(run_go_master(cmd_args, parsed.workspace))

    elif parsed.command == "search-corpus":
        cmd_args = ["search-corpus", "--query", parsed.query, "--top", str(parsed.top)]
        sys.exit(run_go_master(cmd_args, parsed.workspace))

    elif parsed.command == "check-docs-cadence":
        sys.exit(run_go_master(["check-docs-cadence"], parsed.workspace))

    elif parsed.command == "update-docs":
        sys.exit(run_go_master(["update-docs"], parsed.workspace))

    elif parsed.command == "toolchain-audit":
        sys.exit(run_go_master(["toolchain-audit"], parsed.workspace))

    elif parsed.command == "list-agents":
        sys.exit(run_go_master(["list-agents"], parsed.workspace))

    elif parsed.command == "sec-gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/go_master_gate.py")
        cmd = [sys.executable, str(gate_script), parsed.target] + remaining
        res = subprocess.run(cmd, check=False)
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
