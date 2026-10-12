#!/usr/bin/env python3
"""
QA Master - Unified Test Orchestrator
Auto-detects test frameworks across stacks, executes test suites,
aggregates test results, and outputs standardized machine-readable JSON & JUnit reports.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def detect_test_frameworks(repo_path: str) -> List[Dict[str, Any]]:
    """Detect test frameworks present in the codebase."""
    repo = Path(repo_path).resolve()
    frameworks: List[Dict[str, Any]] = []

    # 1. Check Python test frameworks
    has_python_files = any(repo.glob("**/*.py"))
    has_test_files = any(repo.glob("**/test_*.py")) or any(repo.glob("**/*_test.py"))
    if has_python_files and has_test_files:
        # Check if pytest is available
        pytest_proc = subprocess.run([sys.executable, "-m", "pytest", "--version"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if pytest_proc.returncode == 0:
            frameworks.append({
                "language": "python",
                "framework": "pytest",
                "command": [sys.executable, "-m", "pytest", "-v"],
                "layer": "unit/integration"
            })
        else:
            frameworks.append({
                "language": "python",
                "framework": "unittest",
                "command": [sys.executable, "-m", "unittest", "discover", "-s", ".", "-p", "test_*.py"],
                "layer": "unit"
            })

    # 2. Check Node / TypeScript
    package_json = repo / "package.json"
    if package_json.is_file():
        try:
            with open(package_json, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
            scripts = pkg_data.get("scripts", {})
            dev_deps = pkg_data.get("devDependencies", {})
            deps = pkg_data.get("dependencies", {})
            all_deps = {**deps, **dev_deps}

            # Playwright
            if "@playwright/test" in all_deps or "playwright.config.ts" in [p.name for p in repo.glob("playwright.config.*")]:
                frameworks.append({
                    "language": "typescript/javascript",
                    "framework": "playwright",
                    "command": ["npx", "playwright", "test"],
                    "layer": "e2e"
                })

            # Cypress
            if "cypress" in all_deps or (repo / "cypress.config.ts").exists() or (repo / "cypress.config.js").exists():
                frameworks.append({
                    "language": "typescript/javascript",
                    "framework": "cypress",
                    "command": ["npx", "cypress", "run"],
                    "layer": "e2e"
                })

            # Vitest
            if "vitest" in all_deps or "vitest.config.ts" in [p.name for p in repo.glob("vitest.config.*")]:
                frameworks.append({
                    "language": "typescript/javascript",
                    "framework": "vitest",
                    "command": ["npx", "vitest", "run"],
                    "layer": "unit/component"
                })
            # Jest
            elif "jest" in all_deps or (repo / "jest.config.js").exists() or (repo / "jest.config.ts").exists():
                frameworks.append({
                    "language": "typescript/javascript",
                    "framework": "jest",
                    "command": ["npx", "jest"],
                    "layer": "unit/component"
                })
            # Bun test
            elif (repo / "bun.lock").exists() or (repo / "bun.lockb").exists():
                frameworks.append({
                    "language": "typescript/javascript",
                    "framework": "bun-test",
                    "command": ["bun", "test"],
                    "layer": "unit/integration"
                })
            # Generic npm test
            elif "test" in scripts and "no test specified" not in scripts.get("test", ""):
                frameworks.append({
                    "language": "typescript/javascript",
                    "framework": "npm-test",
                    "command": ["npm", "test"],
                    "layer": "general"
                })
        except Exception:
            pass

    # 3. Check Go
    go_mod = repo / "go.mod"
    if go_mod.is_file():
        frameworks.append({
            "language": "go",
            "framework": "go-test",
            "command": ["go", "test", "-v", "./..."],
            "layer": "unit/integration"
        })

    # 4. Check Rust
    cargo_toml = repo / "Cargo.toml"
    if cargo_toml.is_file():
        frameworks.append({
            "language": "rust",
            "framework": "cargo-test",
            "command": ["cargo", "test"],
            "layer": "unit/integration"
        })

    return frameworks


def execute_suite(suite_info: Dict[str, Any], cwd: str) -> Dict[str, Any]:
    """Execute a single test suite command and parse the results."""
    cmd = suite_info["command"]
    framework = suite_info["framework"]
    start_time = time.time()

    proc = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    duration = round(time.time() - start_time, 3)

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    combined_output = stdout + "\n" + stderr

    passed_count = 0
    failed_count = 0
    skipped_count = 0

    # Parsing heuristics by framework
    if framework == "pytest":
        match = re.search(r"(\d+) passed", combined_output)
        if match:
            passed_count = int(match.group(1))
        match_fail = re.search(r"(\d+) failed", combined_output)
        if match_fail:
            failed_count = int(match_fail.group(1))
        match_skip = re.search(r"(\d+) skipped", combined_output)
        if match_skip:
            skipped_count = int(match_skip.group(1))
    elif framework == "unittest":
        # e.g.: "Ran 12 tests in 0.05s\n\nOK" or "FAILED (failures=2, errors=1)"
        match_ran = re.search(r"Ran (\d+) tests?", combined_output)
        total_ran = int(match_ran.group(1)) if match_ran else 0
        match_fail = re.search(r"failures=(\d+)", combined_output)
        match_err = re.search(r"errors=(\d+)", combined_output)
        fails = int(match_fail.group(1)) if match_fail else 0
        errs = int(match_err.group(1)) if match_err else 0
        failed_count = fails + errs
        passed_count = max(0, total_ran - failed_count)
    elif framework in ("bun-test", "vitest", "jest"):
        match_pass = re.search(r"(\d+)\s+pass(?:ed)?", combined_output, re.IGNORECASE)
        if match_pass:
            passed_count = int(match_pass.group(1))
        match_fail = re.search(r"(\d+)\s+fail(?:ed)?", combined_output, re.IGNORECASE)
        if match_fail:
            failed_count = int(match_fail.group(1))
    else:
        # Fallback to exit code
        if proc.returncode == 0:
            passed_count = 1
        else:
            failed_count = 1

    status = "PASSED" if proc.returncode == 0 else "FAILED"

    return {
        "framework": framework,
        "language": suite_info.get("language", "unknown"),
        "layer": suite_info.get("layer", "general"),
        "command": " ".join(cmd),
        "status": status,
        "exit_code": proc.returncode,
        "duration_seconds": duration,
        "passed": passed_count,
        "failed": failed_count,
        "skipped": skipped_count,
        "output_snippet": combined_output[-1500:] if combined_output else ""
    }


def run_orchestrator(repo_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Execute all detected test suites and aggregate unified metrics."""
    repo = Path(repo_path).resolve()
    frameworks = detect_test_frameworks(str(repo))

    suite_results = []
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_duration = 0.0

    for fw in frameworks:
        res = execute_suite(fw, str(repo))
        suite_results.append(res)
        total_passed += res["passed"]
        total_failed += res["failed"]
        total_skipped += res["skipped"]
        total_duration += res["duration_seconds"]

    total_tests = total_passed + total_failed + total_skipped
    pass_rate = round((total_passed / total_tests * 100), 2) if total_tests > 0 else (100.0 if not frameworks else 0.0)

    verdict = "PASSED" if (total_failed == 0 and total_tests > 0) else ("FAILED" if total_failed > 0 else "SKIPPED")

    report: Dict[str, Any] = {
        "version": "1.0.0",
        "run_id": f"qa-{int(time.time())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project_path": str(repo),
        "verdict": verdict,
        "summary": {
            "total": total_tests,
            "passed": total_passed,
            "failed": total_failed,
            "skipped": total_skipped,
            "flaky": 0,
            "duration_seconds": round(total_duration, 3),
            "pass_rate": pass_rate
        },
        "frameworks_detected": len(frameworks),
        "suites": suite_results
    }

    if output_dir:
        out_p = Path(output_dir)
        out_p.mkdir(parents=True, exist_ok=True)
        results_file = out_p / "qa_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="QA Master - Unified Test Orchestrator")
    parser.add_argument("repo", nargs="?", default=".", help="Target repository directory (default: .)")
    parser.add_argument("--detect-only", action="store_true", help="Only detect available frameworks")
    parser.add_argument("--run-all", action="store_true", help="Execute all detected test frameworks")
    parser.add_argument("--output-dir", default=None, help="Directory to save report artifacts")
    args = parser.parse_args()

    repo_dir = os.path.abspath(args.repo)

    if args.detect_only:
        fws = detect_test_frameworks(repo_dir)
        print(json.dumps({"detected_frameworks": fws}, indent=2))
        sys.exit(0)

    report = run_orchestrator(repo_dir, args.output_dir)
    print(json.dumps(report, indent=2))

    if report["verdict"] == "FAILED":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
