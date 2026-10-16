#!/usr/bin/env python3
"""
java_master_cli.py - Helper CLI for interacting with the java-master platform.
Provides workspace discovery, command execution, and JSON reporting for agents.
Adheres strictly to the Tool-Pragmatic Standard (external driver only).
All functions adhere to Cyclomatic Complexity <= 10.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_java_master_binary() -> Path | None:
    """Resolve compiled java-master binary or fallback."""
    base_dir = Path("/home/npirela/java-master")
    bin_path = base_dir / "bin" / "java-master"
    if bin_path.exists() and os.access(bin_path, os.X_OK):
        return bin_path

    system_bin = shutil.which("java-master")
    if system_bin:
        return Path(system_bin)

    return None


def run_java_master(args: list[str], cwd: Path | None = None) -> int:
    """Execute java-master launcher directly or via Maven."""
    bin_path = find_java_master_binary()
    work_dir = cwd if cwd is not None else Path("/home/npirela/java-master")

    if bin_path:
        cmd = [str(bin_path)] + args
    else:
        cmd = ["./mvnw", "exec:java", "-Dexec.mainClass=com.master.Main", f"-Dexec.args={' '.join(args)}"]

    print(f"Executing: {' '.join(cmd)} in {work_dir}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=work_dir, shell=False, check=False)
    return res.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Helper CLI for java-master autonomous platform")
    parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        default=Path("/home/npirela/java-master"),
        help="Base workspace path of java-master (default: /home/npirela/java-master)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Orchestrate
    orch_p = subparsers.add_parser("orchestrate", help="Run Lead Orchestrator across bounded slices")
    orch_p.add_argument("--goal", "-g", type=str, default="Build Java enterprise system", help="Goal description")

    # Verify
    subparsers.add_parser("verify", help="Run Independent Adversarial QA Gate")

    # Search Corpus
    search_p = subparsers.add_parser("search-corpus", help="Search canonical Java literature with BM25 engine")
    search_p.add_argument("--query", "-q", type=str, required=True, help="Search keywords")

    # Cadence
    subparsers.add_parser("check-docs-cadence", help="Inspect 30-day documentation freshness manifest")
    update_p = subparsers.add_parser("update-docs", help="Refresh documentation manifest and scan corpus")
    update_p.add_argument("--force", action="store_true", help="Force refresh manifest")

    # Toolchain
    subparsers.add_parser("toolchain-matrix", help="Display 38+ canonical Java FOSS tools")

    # DevSecOps Gate
    gate_p = subparsers.add_parser("sec-gate", help="Run DevSecOps SecSDLC quality gate")
    gate_p.add_argument("target", nargs="?", default=".", help="Target directory for SecSDLC audit")

    parsed, remaining = parser.parse_known_args()

    if parsed.command == "orchestrate":
        sys.exit(run_java_master(["orchestrate", "--goal", parsed.goal], parsed.workspace))

    elif parsed.command == "verify":
        sys.exit(run_java_master(["verify"], parsed.workspace))

    elif parsed.command == "search-corpus":
        sys.exit(run_java_master(["search-corpus", "--query", parsed.query], parsed.workspace))

    elif parsed.command == "check-docs-cadence":
        sys.exit(run_java_master(["check-docs-cadence"], parsed.workspace))

    elif parsed.command == "update-docs":
        args = ["update-docs"]
        if parsed.force:
            args.append("--force")
        sys.exit(run_java_master(args, parsed.workspace))

    elif parsed.command == "toolchain-matrix":
        sys.exit(run_java_master(["toolchain-matrix"], parsed.workspace))

    elif parsed.command == "sec-gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/java_master_gate.py")
        cmd = [sys.executable, str(gate_script), parsed.target]
        res = subprocess.run(cmd, check=False)
        sys.exit(res.returncode)


if __name__ == "__main__":
    main()
