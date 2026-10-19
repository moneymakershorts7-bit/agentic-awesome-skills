#!/usr/bin/env python3
"""
kotlin_master_cli.py: Agent CLI wrapper and bridge for the kotlin-master autonomous platform.
Provides convenient programmatic and command-line execution of kotlin-master native workflows.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_kotlin_master_binary() -> str:
    """Locate the kotlin-master binary either in PATH or in known install directories."""
    # Check PATH first
    binary = shutil.which("kotlin-master")
    if binary:
        return binary

    # Check local candidate paths
    home = Path.home()
    candidates = [
        home / ".local" / "bin" / "kotlin-master",
        home / "kotlin-master" / "bin" / "kotlin-master",
        Path("/usr/local/bin/kotlin-master"),
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    return ""


def run_command(cmd: list[str]) -> int:
    """Execute a subprocess command, streaming output to stdout/stderr."""
    try:
        proc = subprocess.run(cmd, check=False)
        return proc.returncode
    except FileNotFoundError as e:
        sys.stderr.write(f"Error: Command '{cmd[0]}' not found: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error executing command: {e}\n")
        return 1


def cmd_orchestrate(args: argparse.Namespace) -> int:
    binary = find_kotlin_master_binary()
    if not binary:
        sys.stderr.write("Error: kotlin-master binary not found in PATH or ~/.local/bin\n")
        return 1
    return run_command([binary, "orchestrate", "--task", args.task])


def cmd_search_corpus(args: argparse.Namespace) -> int:
    binary = find_kotlin_master_binary()
    if not binary:
        sys.stderr.write("Error: kotlin-master binary not found in PATH or ~/.local/bin\n")
        return 1
    return run_command([binary, "search-corpus", "--query", args.query])


def cmd_cadence(args: argparse.Namespace) -> int:
    binary = find_kotlin_master_binary()
    if not binary:
        sys.stderr.write("Error: kotlin-master binary not found in PATH or ~/.local/bin\n")
        return 1
    return run_command([binary, "check-docs-cadence"])


def cmd_update_docs(args: argparse.Namespace) -> int:
    binary = find_kotlin_master_binary()
    if not binary:
        sys.stderr.write("Error: kotlin-master binary not found in PATH or ~/.local/bin\n")
        return 1
    cmd = [binary, "update-docs"]
    if args.force:
        cmd.append("--force")
    return run_command(cmd)


def cmd_toolchain(args: argparse.Namespace) -> int:
    binary = find_kotlin_master_binary()
    if not binary:
        sys.stderr.write("Error: kotlin-master binary not found in PATH or ~/.local/bin\n")
        return 1
    return run_command([binary, "toolchain"])


def cmd_gate(args: argparse.Namespace) -> int:
    gate_script = (
        Path.home()
        / ".agents"
        / "skills"
        / "devsecops-master"
        / "scripts"
        / "kotlin_master_gate.py"
    )
    if not gate_script.is_file():
        sys.stderr.write(f"Error: DevSecOps gate script not found at {gate_script}\n")
        return 1
    target_path = args.project_path or str(Path.home() / "kotlin-master")
    return run_command([sys.executable, str(gate_script), target_path])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="kotlin-master Agent CLI: Autonomous Kotlin 2.0+ Orchestration & Governance"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # orchestrate
    p_orch = subparsers.add_parser("orchestrate", help="Orchestrate a task slice via workers & verifier")
    p_orch.add_argument("--task", required=True, help="Path to TaskPlaybookContract JSON file")
    p_orch.set_defaults(func=cmd_orchestrate)

    # search-corpus
    p_search = subparsers.add_parser("search-corpus", help="Vectorless BM25 exact search across canonical literature")
    p_search.add_argument("--query", required=True, help="Search query string")
    p_search.set_defaults(func=cmd_search_corpus)

    # check-docs-cadence / cadence
    p_cadence = subparsers.add_parser("cadence", help="Audit 30-day documentation freshness cadence")
    p_cadence.set_defaults(func=cmd_cadence)

    # update-docs
    p_update = subparsers.add_parser("update-docs", help="Refresh documentation hashes in manifest")
    p_update.add_argument("--force", action="store_true", help="Force refresh even if not expired")
    p_update.set_defaults(func=cmd_update_docs)

    # toolchain
    p_toolchain = subparsers.add_parser("toolchain", help="Audit the 38+ FOSS Kotlin toolchain matrix")
    p_toolchain.set_defaults(func=cmd_toolchain)

    # gate
    p_gate = subparsers.add_parser("gate", help="Run the DevSecOps SecSDLC verification gate")
    p_gate.add_argument("project_path", nargs="?", default="", help="Path to Kotlin project (default: ~/kotlin-master)")
    p_gate.set_defaults(func=cmd_gate)

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
