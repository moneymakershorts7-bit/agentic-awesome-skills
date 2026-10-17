#!/usr/bin/env python3
"""
JavaScript Master SecSDLC Quality Gate for DevSecOps Master
Executes deterministic modern JavaScript (ES2024+ / Node.js 22+ LTS) validation battery:
- SAST / Suppression Guard: Block unjustified /* eslint-disable */, // @ts-ignore, and // @ts-nocheck
- Insecure Primitives Defense: Block Math.random(), eval(), new Function(), md5/sha1, and direct __proto__
- SCA & Supply Chain: Enforce committed lockfile (package-lock.json, pnpm-lock.yaml, bun.lock)
- Container Hardening: Dockerfile non-root execution (USER node:node or UID 1000)
- CI Pipeline Integrity: 40-character immutable commit SHAs for third-party GitHub Actions
- Documentation Cadence: Enforce 30-day freshness cadence manifest (.docs_manifest.json)

Emits normalized SecSDLC JSON/Markdown scorecards and enforces PR blocker thresholds.
All functions adhere to Cyclomatic Complexity <= 10.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JavaScriptMasterGate:
    """Deterministic JavaScript SecSDLC verification gate."""

    def __init__(self, target_dir: str = "."):
        self.root = Path(target_dir).resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise ValueError(f"Target directory does not exist: {target_dir}")
        self.findings: list[dict[str, Any]] = []
        self.scores: dict[str, float] = {}

    def _resolve_js_master(self) -> str | None:
        local_bin = self.root / "bin" / "javascript-master"
        if local_bin.exists() and os.access(local_bin, os.X_OK):
            return str(local_bin)
        default_bin = Path("/home/npirela/javascript-master/bin/javascript-master")
        if default_bin.exists() and os.access(default_bin, os.X_OK):
            return str(default_bin)
        return shutil.which("javascript-master")

    def run_suppression_scan(self) -> dict[str, Any]:
        """Scan JavaScript files for banned or unjustified analyzer suppressions."""
        src_files = [
            f for f in self.root.glob("**/*.js")
            if "node_modules" not in str(f) and "/tests/" not in str(f)
        ]

        if not src_files:
            return {"passed": True, "note": "No JavaScript source files found"}

        violations = []
        suppress_pattern = re.compile(r"(@ts-(?:ignore|nocheck)|eslint-disable)")
        ticket_pattern = re.compile(r"ticket:\s*[A-Za-z0-9_-]+|issue|reason:", re.IGNORECASE)

        for js_file in src_files:
            lines = js_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                stripped = line.strip()
                is_comment = stripped.startswith(("//", "*", "/*"))
                if is_comment and suppress_pattern.search(line):
                    if not ticket_pattern.search(line):
                        violations.append(
                            f"{js_file.name}:L{idx} suppression lacks mandatory inline ticket or rationale reference"
                        )

        passed = len(violations) == 0
        status = "PASS" if passed else "FAIL"
        msg = (
            f"Audited {len(src_files)} JavaScript files; zero unjustified suppressions detected."
            if passed
            else f"Unjustified suppressions detected: {violations}"
        )
        self.findings.append({
            "category": "SAST",
            "status": status,
            "tool": "js-suppression-guard",
            "message": msg,
        })
        return {"passed": passed, "violations": violations}

    def run_insecure_primitives_scan(self) -> dict[str, Any]:
        """Detect insecure language primitives and dynamic code evaluation."""
        src_files = [
            f for f in self.root.glob("src/**/*.js")
            if "node_modules" not in str(f)
        ]

        violations = []
        insecure_patterns = [
            (re.compile(r"\bMath\.random\s*\(\s*\)"), "Insecure PRNG Math.random() in production source"),
            (re.compile(r"\beval\s*\("), "Dynamic code evaluation eval() risks Remote Code Execution"),
            (re.compile(r"\bnew\s+Function\s*\("), "Function constructor evaluation risks Remote Code Execution"),
            (re.compile(r"\.__proto__\b"), "Direct __proto__ access risks Prototype Pollution"),
            (re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]\)", re.IGNORECASE), "Insecure legacy hash algorithm (MD5/SHA1)")
        ]

        for js_file in src_files:
            content = js_file.read_text(encoding="utf-8", errors="ignore")
            # Skip security test/audit utility implementations themselves
            if "SecurityAuditorAgent.js" in js_file.name:
                continue
            for pattern, desc in insecure_patterns:
                if pattern.search(content):
                    violations.append(f"{js_file.name}: {desc}")

        passed = len(violations) == 0
        status = "PASS" if passed else "FAIL"
        self.findings.append({
            "category": "SAST",
            "status": status,
            "tool": "js-insecure-primitives-guard",
            "message": f"Insecure primitives scan: {'PASS (Zero violations)' if passed else '; '.join(violations)}",
        })
        return {"passed": passed, "violations": violations}

    def run_sca_lockfile_scan(self) -> dict[str, Any]:
        """Enforce committed and immutable dependency lockfiles."""
        lockfiles = ["package-lock.json", "pnpm-lock.yaml", "bun.lock", "bun.lockb"]
        found = [lf for lf in lockfiles if (self.root / lf).exists()]

        passed = len(found) > 0
        status = "PASS" if passed else "FAIL"
        msg = (
            f"Committed lockfile detected: {', '.join(found)}"
            if passed
            else "CRITICAL: No lockfile found (package-lock.json, pnpm-lock.yaml, or bun.lock required)"
        )
        self.findings.append({
            "category": "SCA",
            "status": status,
            "tool": "js-lockfile-guard",
            "message": msg,
        })
        return {"passed": passed, "found_lockfiles": found}

    def run_container_hardening_scan(self) -> dict[str, Any]:
        """Verify Dockerfile specifies non-root USER execution."""
        dockerfile = self.root / "Dockerfile"
        if not dockerfile.exists():
            return {"passed": True, "note": "No Dockerfile found"}

        content = dockerfile.read_text(encoding="utf-8", errors="ignore")
        user_match = re.search(r"^\s*USER\s+([a-zA-Z0-9_-]+(?::[a-zA-Z0-9_-]+)?)", content, re.MULTILINE)

        if not user_match:
            passed = False
            msg = "Dockerfile lacks explicit USER instruction; container runs as root (UID 0)"
        else:
            user = user_match.group(1).lower()
            passed = user not in ("root", "0", "0:0")
            msg = f"Dockerfile executes as unprivileged user: '{user_match.group(1)}'" if passed else f"Insecure root user '{user}'"

        status = "PASS" if passed else "FAIL"
        self.findings.append({
            "category": "Container",
            "status": status,
            "tool": "js-dockerfile-guard",
            "message": msg,
        })
        return {"passed": passed}

    def run_pipeline_integrity_scan(self) -> dict[str, Any]:
        """Enforce immutable 40-character commit SHAs for CI actions."""
        wf_dir = self.root / ".github" / "workflows"
        if not wf_dir.exists():
            return {"passed": True, "note": "No GitHub workflows directory"}

        violations = []
        yaml_files = list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))

        for yf in yaml_files:
            lines = yf.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                match = re.search(r"uses:\s+([a-zA-Z0-9._/-]+)@([^\s#]+)", line)
                if match:
                    action, ref = match.group(1), match.group(2)
                    if not re.match(r"^[0-9a-f]{40}$", ref):
                        violations.append(
                            f"{yf.name}:L{idx} Action '{action}' pinned to mutable ref '@{ref}'. 40-char SHA required."
                        )

        passed = len(violations) == 0
        status = "PASS" if passed else "FAIL"
        msg = (
            f"Audited {len(yaml_files)} workflow files; all actions pinned to immutable 40-character SHAs."
            if passed
            else f"Mutable action refs detected: {violations}"
        )
        self.findings.append({
            "category": "CI/CD",
            "status": status,
            "tool": "pipeline-integrity-guard",
            "message": msg,
        })
        return {"passed": passed, "violations": violations}

    def run_platform_cadence_scan(self) -> dict[str, Any]:
        """Verify 30-day documentation freshness cadence manifest."""
        manifest_file = self.root / ".docs_manifest.json"
        if not manifest_file.exists():
            status = "FAIL"
            msg = "Missing .docs_manifest.json state manifest"
            self.findings.append({
                "category": "Cadence",
                "status": status,
                "tool": "js-cadence-guard",
                "message": msg,
            })
            return {"passed": False, "reason": msg}

        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            next_due_str = data.get("next_review_due")
            if not next_due_str:
                passed = False
                msg = "Manifest missing next_review_due"
            else:
                due_dt = datetime.fromisoformat(next_due_str.replace("Z", "+00:00"))
                now_dt = datetime.now(timezone.utc)
                passed = now_dt <= due_dt
                msg = f"Cadence valid until {next_due_str}" if passed else f"Cadence expired on {next_due_str}"
        except Exception as e:
            passed = False
            msg = f"Error reading manifest: {e}"

        status = "PASS" if passed else "FAIL"
        self.findings.append({
            "category": "Cadence",
            "status": status,
            "tool": "js-cadence-guard",
            "message": msg,
        })
        return {"passed": passed, "message": msg}

    def evaluate(self) -> dict[str, Any]:
        """Run all verification checks and calculate overall score."""
        r1 = self.run_suppression_scan()
        r2 = self.run_insecure_primitives_scan()
        r3 = self.run_sca_lockfile_scan()
        r4 = self.run_container_hardening_scan()
        r5 = self.run_pipeline_integrity_scan()
        r6 = self.run_platform_cadence_scan()

        checks = [r1, r2, r3, r4, r5, r6]
        passed_count = sum(1 for c in checks if c.get("passed", False))
        total_count = len(checks)
        score = round((passed_count / total_count) * 100.0, 1)

        overall_passed = score >= 90.0 and all(c.get("passed", False) for c in [r1, r2, r3, r5])

        return {
            "project": "javascript-master",
            "score": score,
            "passed": overall_passed,
            "checks_passed": f"{passed_count}/{total_count}",
            "findings": self.findings,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="JavaScript Master SecSDLC Quality Gate")
    parser.add_argument("target_dir", nargs="?", default=".", help="Target project directory")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    gate = JavaScriptMasterGate(args.target_dir)
    results = gate.evaluate()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"=== JavaScript Master SecSDLC Gate ===")
        print(f"Target: {Path(args.target_dir).resolve()}")
        print(f"Score:  {results['score']}/100.0 [{'PASS' if results['passed'] else 'FAIL'}]")
        print(f"Checks: {results['checks_passed']}\n")
        for f in results["findings"]:
            mark = "[OK]" if f["status"] == "PASS" else "[FAIL]"
            print(f"{mark} {f['category']:<12} | {f['tool']:<28} | {f['message']}")

    sys.exit(0 if results["passed"] else 1)


if __name__ == "__main__":
    main()
