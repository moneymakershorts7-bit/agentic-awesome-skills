#!/usr/bin/env python3
"""
QA Master - Flaky Test Detector
Executes a target test command multiple times to determine if failures are
intermittent/flaky or deterministic, measuring execution time variance and
generating quarantine recommendations.
"""

import argparse
import json
import math
import subprocess
import sys
import time
from typing import Any, Dict, List


def run_flaky_detection(cmd: List[str], runs: int = 5, cwd: str = ".") -> Dict[str, Any]:
    """Execute command N times and track results."""
    history = []
    durations = []
    passed = 0
    failed = 0

    for i in range(1, runs + 1):
        t0 = time.time()
        proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        dur = round(time.time() - t0, 3)
        durations.append(dur)

        is_success = (proc.returncode == 0)
        if is_success:
            passed += 1
        else:
            failed += 1

        history.append({
            "run": i,
            "status": "PASSED" if is_success else "FAILED",
            "exit_code": proc.returncode,
            "duration_seconds": dur,
            "stderr_snippet": (proc.stderr or "")[-300:] if not is_success else ""
        })

    # Duration stats
    mean_dur = sum(durations) / len(durations)
    variance = sum((x - mean_dur) ** 2 for x in durations) / len(durations)
    stddev = round(math.sqrt(variance), 3)

    is_flaky = (passed > 0 and failed > 0)
    if is_flaky:
        classification = "FLAKY"
        recommendation = "QUARANTINE IMMEDIATELY: Test is non-deterministic. Isolate from blocking CI gate."
    elif failed == runs:
        classification = "DETERMINISTIC_FAILURE"
        recommendation = "FAILING: Bug or broken assertion detected consistently in every run."
    else:
        classification = "STABLE_PASS"
        recommendation = "STABLE: Test consistently passed across all iterations."

    flake_rate = round((failed / runs) * 100, 2) if is_flaky else 0.0

    return {
        "version": "1.0.0",
        "command": " ".join(cmd),
        "total_runs": runs,
        "passed": passed,
        "failed": failed,
        "classification": classification,
        "is_flaky": is_flaky,
        "flake_rate_pct": flake_rate,
        "timing_stats": {
            "mean_seconds": round(mean_dur, 3),
            "min_seconds": min(durations),
            "max_seconds": max(durations),
            "stddev_seconds": stddev
        },
        "recommendation": recommendation,
        "history": history
    }


def main():
    parser = argparse.ArgumentParser(description="QA Master - Flaky Test Detector")
    parser.add_argument("--cmd", required=True, help="Test command to execute (e.g. 'python3 -m unittest test_api.py')")
    parser.add_argument("--runs", type=int, default=5, help="Number of repetitions (default: 5)")
    parser.add_argument("--cwd", default=".", help="Working directory (default: .)")
    parser.add_argument("--output", default=None, help="Output JSON path")
    args = parser.parse_args()

    cmd_parts = args.cmd.split()
    results = run_flaky_detection(cmd_parts, runs=args.runs, cwd=args.cwd)

    print(json.dumps(results, indent=2))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

    if results["is_flaky"]:
        sys.exit(2)  # Exit code 2 for flake
    elif results["failed"] == args.runs:
        sys.exit(1)  # Exit code 1 for failure
    sys.exit(0)


if __name__ == "__main__":
    main()
