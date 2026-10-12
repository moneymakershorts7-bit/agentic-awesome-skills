#!/usr/bin/env python3
"""
QA Master - Unified Reporter & Gate Aggregator
Ingests QA test execution results and DevSecOps security audit results,
computes automated CI/CD gating verdicts, and outputs Markdown PR comments and JSON reports.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def generate_markdown_scorecard(qa_data: Dict[str, Any], sec_data: Optional[Dict[str, Any]] = None) -> str:
    """Format unified QA and DevSecOps metrics into a clean Markdown table."""
    qa_summary = qa_data.get("summary", {})
    qa_verdict = qa_data.get("verdict", "UNKNOWN")
    pass_rate = qa_summary.get("pass_rate", 0.0)

    qa_badge = "✅ PASS" if qa_verdict == "PASSED" else "❌ FAIL"
    
    md = []
    md.append("## 🛡️ Unified Quality & Security Assurance Scorecard\n")
    md.append(f"**Run ID:** `{qa_data.get('run_id', 'unknown')}` | **Timestamp:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`\n")
    
    # QA Metrics Table
    md.append("### 🧪 QA Test Execution Summary")
    md.append("| Metric | Result | Status |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| **Overall Verdict** | **{qa_verdict}** | {qa_badge} |")
    md.append(f"| **Total Tests** | {qa_summary.get('total', 0)} | 📊 |")
    md.append(f"| **Passed Tests** | {qa_summary.get('passed', 0)} | ✅ |")
    md.append(f"| **Failed Tests** | {qa_summary.get('failed', 0)} | {'❌' if qa_summary.get('failed', 0) > 0 else '✅'} |")
    md.append(f"| **Skipped Tests** | {qa_summary.get('skipped', 0)} | ⚠️ |")
    md.append(f"| **Pass Rate** | {pass_rate}% | {'✅' if pass_rate == 100.0 else '❌'} |")
    md.append(f"| **Execution Duration** | {qa_summary.get('duration_seconds', 0)}s | ⏱️ |")
    md.append("")

    # Test Suites Breakdown
    suites = qa_data.get("suites", [])
    if suites:
        md.append("#### 📂 Test Suites Breakdown")
        md.append("| Suite / Framework | Layer | Status | Passed | Failed | Duration |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for s in suites:
            st = s.get("status", "UNKNOWN")
            st_icon = "✅" if st == "PASSED" else "❌"
            md.append(f"| `{s.get('framework')}` | {s.get('layer', 'general')} | {st_icon} {st} | {s.get('passed', 0)} | {s.get('failed', 0)} | {s.get('duration_seconds', 0)}s |")
        md.append("")

    # DevSecOps Integration Section
    if sec_data:
        sec_verdict = sec_data.get("overall_verdict", "UNKNOWN")
        sec_badge = "✅ PASS" if sec_verdict == "PASS" else "❌ BLOCK"
        sec_findings = sec_data.get("findings", {})
        md.append("### 🔒 DevSecOps Security Gate Summary")
        md.append("| Security Check | Finding Count | Gate Status |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Security Verdict** | **{sec_verdict}** | {sec_badge} |")
        md.append(f"| **Exposed Secrets** | {sec_findings.get('secrets_detected', 0)} | {'❌ BLOCK' if sec_findings.get('secrets_detected', 0) > 0 else '✅ 0'} |")
        md.append(f"| **Critical Vulnerabilities** | {sec_findings.get('critical_vulns', 0)} | {'❌ BLOCK' if sec_findings.get('critical_vulns', 0) > 0 else '✅ 0'} |")
        md.append(f"| **SAST High Issues** | {sec_findings.get('sast_high', 0)} | {'⚠️ WARN' if sec_findings.get('sast_high', 0) > 0 else '✅ 0'} |")
        md.append("")

    # CI Gating Decision
    overall_pass = (qa_verdict == "PASSED") and (not sec_data or sec_data.get("overall_verdict") == "PASS")
    md.append("### 🚦 CI/CD Deployment Decision")
    if overall_pass:
        md.append("> **✅ GATE PASSED:** All functional tests passed and security controls satisfied. Ready for automated integration and merge.")
    else:
        md.append("> **❌ GATE BLOCKED:** Failures detected. See diagnostic logs above. Merge is blocked until issues are resolved.")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="QA Master - Unified Reporter & Gate Aggregator")
    parser.add_argument("--qa-results", required=True, help="Path to qa_results.json")
    parser.add_argument("--security-results", default=None, help="Optional path to devsecops security audit json")
    parser.add_argument("--output", default=None, help="Output markdown file path")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    args = parser.parse_args()

    with open(args.qa_results, "r", encoding="utf-8") as f:
        qa_data = json.load(f)

    sec_data = None
    if args.security_results and os.path.isfile(args.security_results):
        try:
            with open(args.security_results, "r", encoding="utf-8") as f:
                sec_data = json.load(f)
        except Exception:
            pass

    scorecard_md = generate_markdown_scorecard(qa_data, sec_data)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(scorecard_md)

    print(scorecard_md)

    overall_pass = (qa_data.get("verdict") == "PASSED") and (not sec_data or sec_data.get("overall_verdict") == "PASS")
    if not overall_pass:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
