#!/usr/bin/env python3
"""
javascript_master_cli.py: Agent helper script for javascript-master operations.
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
    """Resolve the path to the javascript-master CLI binary."""
    local_bin = Path("/home/npirela/javascript-master/bin/javascript-master")
    if local_bin.exists() and os.access(local_bin, os.X_OK):
        return str(local_bin)
    which_bin = shutil.which("javascript-master")
    if which_bin:
        return which_bin
    return "javascript-master"


def run_command(args: list[str]) -> int:
    """Execute the javascript-master binary with the provided arguments."""
    binary = resolve_binary()
    cmd = [binary] + args
    res = subprocess.run(cmd, shell=False)
    return res.returncode


def display_agent_invariants(agent_name: str | None) -> int:
    """Display domain invariants for specialized enterprise agents."""
    invariants = {
        "ecma-architect": [
            "Transpiler-Free Type Safety: 100% of methods, parameters, and return types fully annotated with JSDoc",
            "True Private State: Enforce runtime encapsulation using #privateField rather than underscore conventions",
            "Immutability First: Domain states and value objects must be frozen via Object.freeze()",
            "Pattern Matching & Grouping: Utilize Object.groupBy() and Map.groupBy() for domain categorizations"
        ],
        "runtime-optimizer": [
            "V8 Shape Preservation: Initialize all object properties in constructor in identical order",
            "Cancellation Invariant: Every async I/O function must accept and respect AbortSignal",
            "Event Loop Protection: Zero synchronous CPU blocking in primary event loop",
            "Memory Leak Eradication: Always detach event listeners, cancel timers, and use WeakMap for metadata"
        ],
        "api-engineer": [
            "Native ESM Exclusivity: Mandate 'type': 'module' and explicit .js extensions; ban CommonJS",
            "Standard Library Leverage: Prioritize Node.js 22+ built-in modules over micro-dependencies",
            "Subpath Imports & Clean Exports: Use #internal/ subpath imports and package exports map",
            "Boundary Parsing: Validate untrusted inputs at network/API boundaries before reaching domain core"
        ],
        "security-auditor": [
            "Prototype Pollution Defense: Enforce Object.create(null) or Map for key-value stores; ban unsafe merges",
            "ReDoS Immunity: Enforce bounded input lengths and verify regular expressions against catastrophic backtracking",
            "Cryptographic Hygiene: Use node:crypto; strictly ban Math.random() in security contexts and MD5/SHA-1",
            "Supply Chain & Rootless Deployment: Enforce frozen lockfiles, vulnerability scanning, and USER node"
        ],
        "verifier-qa": [
            "JSDoc Type Gate: tsc --noEmit --allowJs --checkJs must pass with zero errors under strict: true",
            "Dead Code Gate: knip must confirm zero dead code, orphaned exports, or unlisted dependencies",
            "Mutation Testing Gate: Stryker Mutator score >= 80% on critical domain and algorithmic logic",
            "Generative Property Gate: fast-check property tests verifying state machine invariants across edge cases",
            "Quality & Linter Gate: Biome / ESLint strict ECMAScript configuration with zero warnings"
        ]
    }

    if agent_name and agent_name in invariants:
        print(f"=== Invariants for {agent_name} ===")
        for inv in invariants[agent_name]:
            print(f"  • {inv}")
    else:
        print("=== javascript-master Enterprise Agent Invariants ===")
        for agent, list_inv in invariants.items():
            print(f"\n[{agent}]")
            for inv in list_inv:
                print(f"  • {inv}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="javascript-master CLI agent helper")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    search_p = subparsers.add_parser("search-corpus", help="Search canonical JavaScript corpus")
    search_p.add_argument("--query", "-q", required=True, help="Search terms")

    subparsers.add_parser("check-docs-cadence", help="Verify 30-day documentation cadence")
    subparsers.add_parser("update-docs", help="Force refresh documentation hashes")

    decomp_p = subparsers.add_parser("orchestrate", help="Decompose and execute goal with workers and verifier")
    decomp_p.add_argument("--goal", required=True, help="Goal description")

    subparsers.add_parser("toolchain", help="Audit 40+ FOSS JavaScript toolchain")
    subparsers.add_parser("verify", help="Run platform verification gates")

    inv_p = subparsers.add_parser("agent-invariants", help="Display agent invariants")
    inv_p.add_argument("--agent", help="Filter by agent type")

    parsed, unknown = parser.parse_known_args()

    if parsed.subcommand == "search-corpus":
        return run_command(["search-corpus", "--query", parsed.query])
    if parsed.subcommand == "check-docs-cadence":
        return run_command(["check-docs-cadence"])
    if parsed.subcommand == "update-docs":
        return run_command(["update-docs", "--force"])
    if parsed.subcommand == "orchestrate":
        return run_command(["orchestrate", "--goal", parsed.goal])
    if parsed.subcommand == "toolchain":
        return run_command(["toolchain"])
    if parsed.subcommand == "verify":
        return run_command(["verify"])
    if parsed.subcommand == "agent-invariants":
        return display_agent_invariants(parsed.agent)

    return 0


if __name__ == "__main__":
    sys.exit(main())
