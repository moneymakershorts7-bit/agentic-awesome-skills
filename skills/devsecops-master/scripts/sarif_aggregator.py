#!/usr/bin/env python3
"""
SARIF Aggregator & Quality Gate Evaluator
Ingests multiple SARIF reports (Semgrep, Trivy, Bandit, Checkov, Hadolint),
aggregates findings, calculates unified security metrics, and evaluates break-build quality gates.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class SarifAggregator:
    def __init__(self, sarif_files: list[str]):
        self.files = sarif_files
        self.total_errors = 0
        self.total_warnings = 0
        self.total_notes = 0
        self.results_by_tool: dict[str, dict[str, Any]] = {}
        self.critical_findings: list[dict[str, Any]] = []

    def process(self) -> dict[str, Any]:
        for filepath in self.files:
            p = Path(filepath)
            if not p.exists():
                continue

            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            runs = data.get("runs", [])
            for run in runs:
                tool_name = run.get("tool", {}).get("driver", {}).get("name", "Unknown-Tool")
                if tool_name not in self.results_by_tool:
                    self.results_by_tool[tool_name] = {
                        "errors": 0,
                        "warnings": 0,
                        "notes": 0,
                        "rules": set()
                    }

                results = run.get("results", [])
                for res in results:
                    level = res.get("level", "warning").lower()
                    rule_id = res.get("ruleId", "unknown-rule")
                    msg = res.get("message", {}).get("text", "")
                    
                    loc_uri = "unknown"
                    loc_line = 0
                    locs = res.get("locations", [])
                    if locs:
                        phys = locs[0].get("physicalLocation", {})
                        loc_uri = phys.get("artifactLocation", {}).get("uri", "unknown")
                        loc_line = phys.get("region", {}).get("startLine", 0)

                    self.results_by_tool[tool_name]["rules"].add(rule_id)

                    if level == "error":
                        self.total_errors += 1
                        self.results_by_tool[tool_name]["errors"] += 1
                        self.critical_findings.append({
                            "tool": tool_name,
                            "rule_id": rule_id,
                            "level": "error",
                            "file": loc_uri,
                            "line": loc_line,
                            "message": msg
                        })
                    elif level == "warning":
                        self.total_warnings += 1
                        self.results_by_tool[tool_name]["warnings"] += 1
                    else:
                        self.total_notes += 1
                        self.results_by_tool[tool_name]["notes"] += 1

        # Convert set to count for JSON serialization
        tools_summary = {}
        for tname, tdata in self.results_by_tool.items():
            tools_summary[tname] = {
                "errors": tdata["errors"],
                "warnings": tdata["warnings"],
                "notes": tdata["notes"],
                "unique_rules_flagged": len(tdata["rules"])
            }

        return {
            "files_scanned": len(self.files),
            "summary": {
                "total_errors": self.total_errors,
                "total_warnings": self.total_warnings,
                "total_notes": self.total_notes,
                "total_findings": self.total_errors + self.total_warnings + self.total_notes
            },
            "by_tool": tools_summary,
            "critical_findings": self.critical_findings
        }


def format_markdown(report: dict[str, Any], max_errors: int) -> str:
    passed = report["summary"]["total_errors"] <= max_errors
    status_badge = "✅ PASSED" if passed else "❌ FAILED (GATE BREACH)"

    lines = [
        "# 🛡️ Unified Security Gate Scorecard (SARIF Aggregation)",
        f"- **Gate Evaluation:** **{status_badge}** (Threshold: $\\le {max_errors}$ errors)",
        f"- **Scanned Reports:** {report['files_scanned']}",
        f"- **Total Errors (Blockers):** `{report['summary']['total_errors']}`",
        f"- **Total Warnings:** `{report['summary']['total_warnings']}`",
        f"- **Total Notes:** `{report['summary']['total_notes']}`",
        "",
        "## Results by Scanner Tool",
        "| Scanner Tool | Errors | Warnings | Notes | Unique Rules |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]

    for tool, data in report["by_tool"].items():
        lines.append(f"| {tool} | {data['errors']} | {data['warnings']} | {data['notes']} | {data['unique_rules_flagged']} |")

    if report["critical_findings"]:
        lines.extend([
            "",
            "## 🚨 Critical Blocking Findings",
            "| Tool | Rule ID | Location | Message |",
            "| :--- | :--- | :--- | :--- |"
        ])
        for crit in report["critical_findings"][:15]:
            lines.append(f"| {crit['tool']} | `{crit['rule_id']}` | `{crit['file']}:{crit['line']}` | {crit['message'][:60]} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Aggregate SARIF reports and evaluate quality gates.")
    parser.add_argument("--inputs", nargs="+", required=True, help="Path to SARIF files to aggregate")
    parser.add_argument("--max-errors", type=int, default=0, help="Maximum allowed errors before gate failure (default: 0)")
    parser.add_argument("--output", help="Optional output JSON filepath")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    args = parser.parse_args()

    aggregator = SarifAggregator(args.inputs)
    report = aggregator.process()

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_markdown(report, args.max_errors))

    if report["summary"]["total_errors"] > args.max_errors:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
