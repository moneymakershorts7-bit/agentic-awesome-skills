"""MinimalGenerator: Minimal report generation for sec-userspace under extreme load."""
import os
from datetime import datetime, timezone
from typing import List


def generate_minimal_report(self, judgment: dict, evidences: List,
                            system_info: dict, module_stats: List[dict],
                            performance: dict, summary: 'ReportSummary' = None,
                            load_ratio: float = None) -> str:
    """Generate minimal markdown report for extreme load scenarios.

    This is optimized for speed, containing only essential information:
    - Scan mode and timestamp
    - Detection conclusion and risk score
    - Alert summary (top alerts only)
    - Basic remediation advice

    P2-2026-04-13: Accept load_ratio parameter to avoid redundant os.getloadavg() calls
    """
    lines = []

    # Header section
    lines.append("# 安全入侵检测报告")
    lines.append("")
    lines.append("## 检测结论")
    lines.append("")
    lines.append(f"- **检测模式**: 自适应扫描")
    lines.append(f"- **检测时间**: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- **目标主机**: {system_info.get('hostname', 'unknown')}")
    lines.append(f"- **检测结论**: {judgment['conclusion']}")
    lines.append(f"- **风险评分**: {judgment['total_score']}/100")
    lines.append("")

    # Add summary if available
    if summary:
        lines.append(summary.generate_summary_text())
        lines.append("")

    evidence_count = len(evidences)

    if evidence_count == 0:
        agg_groups = []
        agg_groups_count = 0
    else:
        if load_ratio is None:
            try:
                load_1min = os.getloadavg()[0]
                cpu_count = os.cpu_count() or 1
                load_ratio = load_1min / cpu_count
            except OSError:
                load_ratio = 1.0

        # Skip aggregation under moderate load (>3x)
        should_skip_aggregation = (load_ratio > 3.0)

        if should_skip_aggregation:
            agg_groups = []
            agg_groups_count = evidence_count
        else:
            from ..aggregation import aggregate_evidences
            agg_groups = aggregate_evidences(evidences, limit=10)
            agg_groups_count = len(agg_groups)

    # Alert summary
    sc = judgment["severity_counts"]
    total_evidence_count = judgment.get("evidence_count", len(evidences))

    lines.append("## 告警统计")
    lines.append("")
    lines.append(f"- **告警总数**: {total_evidence_count} 条事件")
    lines.append(f"- **合并告警**: {agg_groups_count} 条")
    lines.append(f"- **严重等级**: CRITICAL({sc['CRITICAL']}) HIGH({sc['HIGH']}) MEDIUM({sc['MEDIUM']}) LOW({sc['LOW']})")
    lines.append("")

    # Top alerts table - only show if we have aggregated groups
    if agg_groups:
        lines.extend([
            "## 重要告警",
            "",
            "| 严重度 | 告警名称 | ATT&CK | 置信度 |",
            "|--------|----------|--------|--------|",
        ])

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_groups = sorted(agg_groups,
                               key=lambda g: severity_order.get(g.severity.name, 4))

        for group in sorted_groups[:5]:
            attack = group.attack_id if group.attack_id else "-"
            lines.append(
                f"| {group.severity.name} | {group.title} | {attack} | {group.confidence:.0%} |"
            )

        lines.append("")

        critical = [g for g in sorted_groups if g.severity.name == 'CRITICAL']
        if critical:
            lines.extend(["## 高危告警详情", ""])
            for group in critical[:1]:
                rep = group.representative
                desc = rep.description
                if len(desc) > 200:
                    desc = desc[:200] + "..."

                header = f"### [{group.severity.name}] {group.title}"
                if rep.logid:
                    header = f"### [{group.severity.name}] {rep.logid}: {group.title}"

                lines.append(header)
                lines.append(f"- **描述**: {desc}")

                if group.attack_id:
                    lines.append(f"- **ATT&CK 技术**: {group.attack_id}")

                if group.remediation:
                    rem = group.remediation[:100] + "..." if len(group.remediation) > 100 else group.remediation
                    lines.append(f"- **修复建议**: {rem}")

                lines.append("")

    lines.extend([
        "## 扫描性能",
        "",
        f"- **总耗时**: {performance['total_duration']}s",
        f"- **峰值内存**: {performance['peak_memory_mb']}MB",
        "",
    ])

    return "\n".join(lines)
