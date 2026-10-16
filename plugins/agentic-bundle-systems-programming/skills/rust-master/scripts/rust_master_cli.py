#!/usr/bin/env python3
"""
rust_master_cli.py - Helper CLI for interacting with rust-master agent engine.
Provides workspace discovery, command execution, and JSON reporting for agents.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def find_rust_master_binary() -> Path:
    # 1. Check local release/debug in /home/npirela/rust-master
    base_dir = Path("/home/npirela/rust-master")
    release_bin = base_dir / "target" / "release" / "rust-master"
    if release_bin.exists() and os.access(release_bin, os.X_OK):
        return release_bin

    debug_bin = base_dir / "target" / "debug" / "rust-master"
    if debug_bin.exists() and os.access(debug_bin, os.X_OK):
        return debug_bin

    return Path("rust-master")


def run_rust_master(args: list[str], cwd: Path | None = None) -> int:
    bin_path = find_rust_master_binary()
    manifest_path = Path("/home/npirela/rust-master/Cargo.toml")

    cmd: list[str]
    if bin_path.exists():
        cmd = [str(bin_path)] + args
    else:
        cmd = ["cargo", "run", "--manifest-path", str(manifest_path), "--"] + args

    work_dir = cwd if cwd is not None else Path("/home/npirela/rust-master")
    print(f"Executing: {' '.join(cmd)} in {work_dir}", file=sys.stderr)
    res = subprocess.run(cmd, cwd=work_dir, shell=False)
    return res.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Helper for rust-master autonomous platform")
    parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        default=Path("/home/npirela/rust-master"),
        help="Base workspace path of rust-master (default: /home/npirela/rust-master)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Orchestrate
    subparsers.add_parser("orchestrate", help="Run Lead Orchestrator across bounded slices")

    # Verify
    verify_p = subparsers.add_parser("verify", help="Run Independent Adversarial QA Gate")
    verify_p.add_argument("--target", default=".", help="Target workspace path")

    # Audit AST
    ast_p = subparsers.add_parser("audit-ast", help="Audit Rust AST for unsafe blocks and invariants")
    ast_p.add_argument("--file", required=True, help="File path to audit")

    # Search Corpus
    search_p = subparsers.add_parser("search-corpus", help="Search canonical Rust literature")
    search_p.add_argument("--query", required=True, help="Search query")
    search_p.add_argument("--limit", type=int, default=5, help="Number of results")

    # Cadence Check
    subparsers.add_parser("check-docs-cadence", help="Verify 30-day documentation freshness cadence")

    # Update Docs
    update_p = subparsers.add_parser("update-docs", help="Refresh documentation manifest and stamp new cadence")
    update_p.add_argument("--force", action="store_true", help="Force refresh")

    # List Tools
    subparsers.add_parser("list-tools", help="List all 38+ FOSS Rust tools and availability")

    # DevSecOps Gate
    gate_p = subparsers.add_parser("secsdlc-gate", help="Run DevSecOps SecSDLC gate audit")
    gate_p.add_argument("--target", default="/home/npirela/rust-master", help="Target crate path")

    args = parser.parse_args()
    ws = args.workspace

    if args.command == "orchestrate":
        sys.exit(run_rust_master(["orchestrate"], cwd=ws))
    elif args.command == "verify":
        sys.exit(run_rust_master(["verify", "--target", args.target], cwd=ws))
    elif args.command == "audit-ast":
        sys.exit(run_rust_master(["audit-ast", "--file", args.file], cwd=ws))
    elif args.command == "search-corpus":
        sys.exit(run_rust_master(["search-corpus", "--query", args.query, "--limit", str(args.limit)], cwd=ws))
    elif args.command == "check-docs-cadence":
        sys.exit(run_rust_master(["check-docs-cadence"], cwd=ws))
    elif args.command == "update-docs":
        cmd_args = ["update-docs"]
        if args.force:
            cmd_args.append("--force")
        sys.exit(run_rust_master(cmd_args, cwd=ws))
    elif args.command == "list-tools":
        sys.exit(run_rust_master(["list-tools"], cwd=ws))
    elif args.command == "secsdlc-gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/rust_master_gate.py")
        if gate_script.exists():
            res = subprocess.run([sys.executable, str(gate_script), args.target], cwd=ws, shell=False)
            sys.exit(res.returncode)
        else:
            print(f"Error: DevSecOps gate not found at {gate_script}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
