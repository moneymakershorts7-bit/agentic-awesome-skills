#!/usr/bin/env python3
"""
API Master CLI Helper Script for Agent Workflows.
Enables agents to orchestrate, search literature, validate contracts, generate Swagger UI, and execute gates.
"""

from __future__ import annotations

import argparse
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


def _exec_cmd(cmd: list[str]) -> int:
    """Execute command safely with explicit argument vector (shell=False)."""
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


def _build_command_argv(args: argparse.Namespace, api_master_bin: str) -> list[str]:
    """Build deterministic CLI argument list."""
    if args.command in ("status", "toolchain", "check-docs-cadence"):
        return [api_master_bin, args.command]
    if args.command == "update-docs":
        cmd = [api_master_bin, "update-docs"]
        if args.force:
            cmd.append("--force")
        return cmd
    if args.command == "search-corpus":
        return [api_master_bin, "search-corpus", "--query", args.query, "--top-k", str(args.top_k)]
    if args.command in ("validate-contract", "dispatch"):
        return [api_master_bin, args.command, "--file", args.file]
    if args.command == "generate-swagger-ui":
        cmd = [api_master_bin, "generate-swagger-ui", "--spec", args.spec, "--title", args.title]
        if args.output:
            cmd.extend(["--output", args.output])
        return cmd
    if args.command == "convert-swagger":
        cmd = [api_master_bin, "convert-swagger", "--input", args.input]
        if args.output:
            cmd.extend(["--output", args.output])
        return cmd
    if args.command == "generate-client":
        return [api_master_bin, "generate-client", "--spec", args.spec, "--lang", args.lang, "--output-dir", args.output_dir]
    return []


def main():
    parser = argparse.ArgumentParser(description="API Master Agent CLI Helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show platform status and agent fleet health")
    subparsers.add_parser("toolchain", help="Inspect 48+ FOSS toolchain matrix")

    search_p = subparsers.add_parser("search-corpus", help="Search canonical literature")
    search_p.add_argument("--query", "-q", required=True, help="Search query")
    search_p.add_argument("--top-k", "-k", type=int, default=5, help="Number of results")

    val_p = subparsers.add_parser("validate-contract", help="Validate TaskPlaybookContract JSON")
    val_p.add_argument("--file", "-f", required=True, help="Contract file path")

    disp_p = subparsers.add_parser("dispatch", help="Execute work slice through FSM")
    disp_p.add_argument("--file", "-f", required=True, help="Contract file path")

    subparsers.add_parser("check-docs-cadence", help="Verify 30-day documentation freshness")

    up_p = subparsers.add_parser("update-docs", help="Update docs manifest")
    up_p.add_argument("--force", action="store_true", help="Force manifest update")

    sui_p = subparsers.add_parser("generate-swagger-ui", help="Generate interactive Swagger UI portal")
    sui_p.add_argument("--spec", "-s", required=True, help="OpenAPI or Swagger spec path")
    sui_p.add_argument("--output", "-o", default=None, help="Output HTML file path")
    sui_p.add_argument("--title", "-t", default="Interactive API Explorer - Swagger UI", help="Portal title")

    conv_p = subparsers.add_parser("convert-swagger", help="Convert Swagger 2.0 to OpenAPI 3.1.0")
    conv_p.add_argument("--input", "-i", required=True, help="Input Swagger 2.0 file")
    conv_p.add_argument("--output", "-o", default=None, help="Output OpenAPI 3.1.0 file")

    gen_p = subparsers.add_parser("generate-client", help="Generate client SDK bundle")
    gen_p.add_argument("--spec", "-s", required=True, help="OpenAPI spec path")
    gen_p.add_argument("--lang", "-l", required=True, help="Target language (typescript, python, go, etc.)")
    gen_p.add_argument("--output-dir", "-o", default="./client", help="Output directory")

    gate_p = subparsers.add_parser("gate", help="Run DevSecOps API Master Gate")
    gate_p.add_argument("target", nargs="?", default="/home/npirela/api-master", help="Target dir")

    args = parser.parse_args()

    if args.command == "gate":
        gate_script = Path("/home/npirela/.agents/skills/devsecops-master/scripts/api_master_gate.py")
        if not gate_script.exists():
            print(f"Error: Gate script {gate_script} not found.", file=sys.stderr)
            sys.exit(1)
        sys.exit(_exec_cmd([sys.executable, str(gate_script), args.target]))

    api_master_bin = resolve_api_master_bin()
    if not api_master_bin:
        print("Error: api-master binary not found.", file=sys.stderr)
        sys.exit(1)

    cmd = _build_command_argv(args, api_master_bin)
    sys.exit(_exec_cmd(cmd))


if __name__ == "__main__":
    main()
