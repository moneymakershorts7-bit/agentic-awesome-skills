#!/usr/bin/env python3
"""
QA Master - Mutation Testing Evaluator
Generates synthetic mutations (boundary, equality, arithmetic, boolean) on target
source code, runs tests against each mutant, and evaluates the Mutation Score Index (MSI)
to ensure tests verify behavior rather than merely exercising lines.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Operator mutation map
MUTATIONS = [
    (r" == ", " != ", "EQUALITY_INVERT"),
    (r" != ", " == ", "INEQUALITY_INVERT"),
    (r" <= ", " < ", "BOUNDARY_LESS_EQUAL"),
    (r" >= ", " > ", "BOUNDARY_GREATER_EQUAL"),
    (r" < ", " <= ", "BOUNDARY_LESS"),
    (r" > ", " >= ", "BOUNDARY_GREATER"),
    (r" \+ ", " - ", "ARITHMETIC_ADD_SUB"),
    (r" - ", " + ", "ARITHMETIC_SUB_ADD"),
    (r"\bTrue\b", "False", "BOOLEAN_TRUE_FALSE"),
    (r"\bFalse\b", "True", "BOOLEAN_FALSE_TRUE"),
    (r"\band\b", "or", "LOGICAL_AND_OR"),
    (r"\bor\b", "and", "LOGICAL_OR_AND"),
]


def find_mutations_in_file(file_path: Path) -> List[Tuple[int, str, str, str]]:
    """Scan file and find candidate lines and mutations."""
    candidates = []
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for idx, line in enumerate(lines):
        # Ignore comments or docstrings
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        for pattern, replacement, mut_type in MUTATIONS:
            if re.search(pattern, line):
                mutated_line = re.sub(pattern, replacement, line, count=1)
                candidates.append((idx, line, mutated_line, mut_type))
    return candidates


def run_mutation_analysis(target_file: str, test_cmd: List[str], max_mutants: int = 15, cwd: str = ".") -> Dict[str, Any]:
    """Execute mutation analysis on a single target source file."""
    src_path = Path(target_file).resolve()
    if not src_path.is_file():
        return {"error": f"File not found: {target_file}"}

    original_code = src_path.read_text(encoding="utf-8")
    mutations = find_mutations_in_file(src_path)

    # First verify test passes on clean code
    clean_run = subprocess.run(test_cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if clean_run.returncode != 0:
        return {
            "error": "Baseline test suite failed on unmodified code. Clean tests must pass before mutation analysis.",
            "clean_stderr": clean_run.stderr[-500:]
        }

    total_mutants = min(len(mutations), max_mutants)
    mutants_killed = 0
    mutants_survived = 0
    results = []

    for i in range(total_mutants):
        line_idx, orig_line, mut_line, mut_type = mutations[i]
        
        # Apply mutation
        lines = original_code.splitlines()
        lines[line_idx] = mut_line
        mutated_code = "\n".join(lines)
        if original_code.endswith("\n"):
            mutated_code += "\n"

        try:
            src_path.write_text(mutated_code, encoding="utf-8")
            # Run tests
            res = subprocess.run(test_cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                # Test failed => mutant killed (Desired outcome)
                mutants_killed += 1
                status = "KILLED"
            else:
                # Test passed => mutant survived (Assertion gap)
                mutants_survived += 1
                status = "SURVIVED"

            results.append({
                "mutant_id": i + 1,
                "line": line_idx + 1,
                "type": mut_type,
                "original": orig_line.strip(),
                "mutated": mut_line.strip(),
                "status": status
            })
        finally:
            # Always restore original code safely
            src_path.write_text(original_code, encoding="utf-8")

    msi = round((mutants_killed / max(1, total_mutants)) * 100, 2) if total_mutants > 0 else 100.0

    return {
        "version": "1.0.0",
        "target_file": str(src_path),
        "total_mutants_evaluated": total_mutants,
        "mutants_killed": mutants_killed,
        "mutants_survived": mutants_survived,
        "mutation_score_index": msi,
        "verdict": "PASSED" if msi >= 70.0 else "WARNING",
        "mutants": results
    }


def main():
    parser = argparse.ArgumentParser(description="QA Master - Mutation Testing Evaluator")
    parser.add_argument("--file", required=True, help="Target source file to mutate")
    parser.add_argument("--test-cmd", required=True, help="Test command to verify mutations")
    parser.add_argument("--max-mutants", type=int, default=10, help="Max number of mutants to test (default: 10)")
    parser.add_argument("--threshold", type=float, default=70.0, help="Minimum acceptable MSI percentage (default: 70.0)")
    parser.add_argument("--cwd", default=".", help="Working directory (default: .)")
    parser.add_argument("--output", default=None, help="Output JSON path")
    args = parser.parse_args()

    cmd = args.test_cmd.split()
    report = run_mutation_analysis(args.file, cmd, max_mutants=args.max_mutants, cwd=args.cwd)

    print(json.dumps(report, indent=2))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    if report.get("mutation_score_index", 0) < args.threshold:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
