"""MarkdownReportGenerator: Markdown report generation for sec-userspace."""
import json
import logging
import math
import os
import re
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ...utils.redact import redact_credential, redact_in_text
from ..report_optimization import (
    truncate_alerts_for_report,
    get_truncation_markdown,
)
from ..evidence import Evidence

logger = logging.getLogger(__name__)

# Pre-compiled redaction regex patterns
_SSH_KEY_PATTERN = re.compile(r'(ssh-\w+\s+)[A-Za-z0-9+/=]{20,}')
_HASH_PATTERN = re.compile(r'\$[0-9]\$[A-Za-z0-9./]{10,}')


class SafeJsonEncoder(json.JSONEncoder):
    """Safe JSON encoder: Replaces NaN/Inf with null to avoid invalid JSON output"""
    _MAX_SANITIZE_DEPTH = 50  # Prevent stack overflow on deeply nested structures

    def default(self, obj):
        return super().default(obj)

    def encode(self, o):
        return super().encode(self._sanitize(o, depth=0))

    def _sanitize(self, obj, depth=0):
        # P1-2.3: Recursion depth limit to prevent stack overflow
        if depth > self._MAX_SANITIZE_DEPTH:
            return "<max depth exceeded>"
        # P2-2026-04-13: Fast path for common types - avoid recursion when possible
        if isinstance(obj, float):
            if math.isnan(obj) or math.isinf(obj):
                return None
            return obj
        if isinstance(obj, str):
            return obj
        if obj is None or isinstance(obj, (bool, int)):
            return obj
        if isinstance(obj, dict):
            # Only create new dict if there are actually floats to sanitize
            sanitized = {}
            for k, v in obj.items():
                sv = self._sanitize(v, depth + 1) if isinstance(v, (dict, list, float, tuple)) else v
                sanitized[k] = sv
            return sanitized
        if isinstance(obj, (list, tuple)):
            # Only create new list if there are actually floats to sanitize
            sanitized = []
            for v in obj:
                sv = self._sanitize(v, depth + 1) if isinstance(v, (dict, list, float, tuple)) else v
                sanitized.append(sv)
            return sanitized
        return obj


def _lazy_load_detection_coverage():
    """Lazy-load detection_coverage module to avoid import overhead."""
    from ..detection_coverage import DetectionCoverageReport, coverage_to_dict, coverage_to_markdown
    return DetectionCoverageReport, coverage_to_dict, coverage_to_markdown


def sanitize_evidence(evidence: Evidence) -> Evidence:
    """Redact sensitive data in Evidence"""
    sensitive_keys = ["key", "password", "secret", "token", "private_key"]
    raw_data = evidence.raw_data.copy() if evidence.raw_data else {}
    for key in list(raw_data.keys()):
        for sensitive in sensitive_keys:
            if sensitive in key.lower():
                # Use proper credential redaction instead of static string
                original_value = str(raw_data[key]) if raw_data[key] else ""
                raw_data[key] = redact_credential(original_value)
                break

    desc = evidence.description
    desc = _SSH_KEY_PATTERN.sub(r'\1...REDACTED', desc)
    desc = _HASH_PATTERN.sub('***HASH_REDACTED***', desc)
    desc = redact_in_text(desc)

    # Also redact remediation text
    remediation = redact_in_text(evidence.remediation) if evidence.remediation else ""

    return Evidence(
        id=evidence.id, module=evidence.module, title=evidence.title, description=desc,
        severity=evidence.severity, confidence=evidence.confidence,
        attack_id=evidence.attack_id, attack_tactic=evidence.attack_tactic,
        source_path=evidence.source_path, timestamp=evidence.timestamp,
        raw_data=raw_data, remediation=remediation,
    )


def aggregate_evidences(evidences: List[Evidence], limit: int = 0):
    """Aggregate security events into groups (lazy-import to avoid circular deps)"""
    from ..aggregation import aggregate_evidences as _agg
    return _agg(evidences, limit)


def collect_performance(start_time: float = None) -> dict:
    """Collect performance metrics"""
    import resource

    usage = resource.getrusage(resource.RUSAGE_SELF)
    cpu_time = usage.ru_utime + usage.ru_stime

    peak_memory_mb = 0
    try:
        with open("/proc/self/status", "r", errors='replace', encoding='utf-8') as f:
            for line in f:
                if line.startswith("VmPeak:"):
                    peak_memory_mb = int(line.split()[1]) // 1024
                    break
    except (FileNotFoundError, PermissionError):
        pass

    total_duration = 0.0
    if start_time:
        total_duration = time.monotonic() - start_time

    return {"total_duration": round(total_duration, 2), "peak_memory_mb": peak_memory_mb, "cpu_time": round(cpu_time, 2)}


class MarkdownReportGenerator:
    """Markdown report generator"""

    def generate(self, judgment: dict, evidences: List[Evidence], timeline: List[dict],
                 system_info: dict, module_stats: List[dict], performance: dict,
                 summary: 'ReportSummary' = None,
                 improvement_plan: Optional['ImprovementPlanData'] = None,
                 whitelist_metadata: Dict[str, Any] = None,
                 correlation_summary: Optional[Dict[str, Any]] = None,
                 coverage_report: Optional['DetectionCoverageReport'] = None,
                 start_time: Optional[float] = None,
                 ) -> str:
        """Generate Markdown report."""

        evidences, was_truncated, truncation_stats = truncate_alerts_for_report(
            evidences, max_alerts=1000, top_to_show=50
        )

        lines = ["# 安全入侵检测报告", "", ""]

        # Add summary at the beginning if available
        if summary:
            lines.append(summary.generate_summary_text())
            lines.extend(["", ""])

        lines.extend(["## 执行摘要", ""])
        sc = judgment["severity_counts"]
        total_evidence_count = judgment.get("evidence_count", len(evidences))
        agg_groups = aggregate_evidences(evidences)
        agg_groups = [g for g in agg_groups if g is not None]
        lines.extend([
            f"- **检测时间**: {datetime.now(timezone.utc).isoformat()}",
            f"- **目标主机**: {system_info.get('hostname', 'unknown')}",
            f"- **操作系统**: {system_info.get('os_release', 'unknown')}",
            f"- **检测结论**: {judgment['conclusion']}",
            f"- **风险评分**: {judgment['total_score']}/100",
            f"- **告警统计**: {total_evidence_count} 条事件合并为 {len(agg_groups)} 条告警",
            f"- **严重等级分布**: CRITICAL({sc['CRITICAL']}) HIGH({sc['HIGH']}) MEDIUM({sc['MEDIUM']}) LOW({sc['LOW']})",
            "", "## 安全告警", "",
            "| 严重度 | 告警名称 | 数量 | ATT&CK | 来源模块 | 置信度 |",
            "|--------|----------|------|--------|----------|--------|",
        ])

        if was_truncated:
            lines.append(get_truncation_markdown(truncation_stats))

        for group in agg_groups:
            count_badge = f"x{group.count}" if group.count > 1 else "1"
            attack = group.attack_id if group.attack_id else "-"
            lines.append(
                f"| {group.severity.name} | {group.title} | {count_badge} | {attack} | {group.module} | {group.confidence:.0%} |"
            )

        lines.extend(["", "## 告警详情", ""])
        for group in agg_groups:
            sanitized = sanitize_evidence(group.representative)
            header = f"### [{group.severity.name}] {group.title}"
            if group.count > 1:
                header += f" (共 {group.count} 条)"

            # Add logid if available
            rep = group.representative
            if rep.logid:
                header = f"### [{group.severity.name}] {rep.logid}: {group.title}"

            # Show verified_status if not pending
            vs = rep.verified_status
            if vs == "likely_fp":
                header += " [可能误报]"
            elif vs == "whitelisted":
                header += " [已白名单]"
            lines.append(header)
            lines.append(f"- **描述**: {sanitized.description}")
            if vs == "likely_fp":
                fp_reason = rep.raw_data.get("fp_reason", "") if rep.raw_data else ""
                if fp_reason:
                    lines.append(f"- **误报原因**: {fp_reason}")

            # Add correlation context if present
            corr = rep.raw_data.get("correlation") if rep.raw_data else None
            if corr:
                related = corr.get("related_analyzers", [])
                if related:
                    lines.append(f"- **关联分析器**: {', '.join(related)}")
                orig_sev = corr.get("original_severity")
                if orig_sev:
                    lines.append(f"- **原始严重度**: {orig_sev} (关联升级)")
                group_id = corr.get("group_id")
                if group_id:
                    lines.append(f"- **关联组ID**: {group_id}")

            if group.source_paths:
                if len(group.source_paths) <= 3:
                    lines.append(f"- **证据来源**: {', '.join(group.source_paths)}")
                else:
                    shown = ', '.join(group.source_paths[:3])
                    lines.append(f"- **证据来源**: {shown} 等 {len(group.source_paths)} 处")
            if group.attack_id:
                lines.append(f"- **ATT&CK 技术**: {group.attack_id}")

            self._render_evidence_details(rep, lines)

            if group.remediation:
                lines.append(f"- **修复建议**: {group.remediation}")

            self._render_remediation_commands(rep, lines)

            lines.append("")

        lines.extend(["## 检测模块执行状态", "", "| 模块 | 状态 | 发现数 | 耗时 |", "|------|------|--------|------|"])
        for stat in module_stats:
            lines.append(f"| {stat['name']} | {stat['status']} | {stat['findings']} | {stat['duration']:.1f}s |")
        lines.extend(["", "## 入侵时间线", ""])

        if timeline:
            lines.extend(["| 时间 | 严重度 | 来源模块 | 发现 | ATT&CK |", "|------|--------|---------|------|--------|"])
            for entry in timeline:
                ts = entry["timestamp"].replace("T", " ").split(".")[0][:19] if "T" in entry["timestamp"] else entry["timestamp"]
                lines.append(f"| {ts} | {entry['severity']} | {entry['module']} | {entry['title']} | {entry['attack_id']} |")
        else:
            lines.append("无入侵事件记录")

        try:
            from ...threat_intel.ioc_loader import get_loader
            loader = get_loader()
            stats = loader.stats
            lines.extend([
                "", "## 威胁情报版本", "",
                f"- **版本**: {stats.get('version', 'unknown')}",
                f"- **更新日期**: {stats.get('created', 'unknown')}",
                f"- **来源**: sec-userspace assets",
                f"- **恶意端口数量**: {stats.get('c2_ports', 0)}",
                f"- **矿池域名数量**: {stats.get('mining_pools', 0)}",
                f"- **C2 端口数量**: {stats.get('mining_ports', 0)}",
                f"- **总 IoC 数量**: {stats.get('total', 0)}", ""
            ])
        except (ImportError, KeyError, TypeError, ValueError) as e:
            logger.debug(f"Failed to render threat intel section: {e}")

        # Add whitelist version information from EBPFAnalyzer
        if whitelist_metadata:
            try:
                source_text = {
                    'cloud': '云端同步',
                    'cache': '本地缓存',
                    'local': '本地白名单',
                    'error': '获取失败'
                }.get(whitelist_metadata.get('whitelist_source', 'unknown'), '未知')

                lines.extend([
                    "", "## eBPF 白名单版本", "",
                    f"- **版本**: {whitelist_metadata.get('whitelist_version', 'unknown')}",
                    f"- **来源**: {source_text}",
                    f"- **缓存状态**: {'有效' if whitelist_metadata.get('whitelist_cache_valid', False) else '无效/未使用'}",
                    ""
                ])
            except (KeyError, TypeError, ValueError) as e:
                logger.debug(f"Failed to render whitelist metadata: {e}")

        if correlation_summary:
            lines.extend(self._generate_correlation_summary_markdown(correlation_summary))

        lines.extend([
            "", "## 系统信息摘要", "", "| 项目 | 值 |", "|------|------|",
            f"| 主机名 | {system_info.get('hostname', 'unknown')} |",
            f"| 操作系统 | {system_info.get('os_release', 'unknown')} |",
            f"| 内核版本 | {system_info.get('kernel_version', 'unknown')} |",
            f"| CPU 核心数 | {system_info.get('cpu_count', 0)} |",
            f"| 内存总量 | {system_info.get('memory_total_mb', 0)}MB |",
            "", "## 性能指标", "",
            f"- **执行总耗时**: {performance['total_duration']}s",
            f"- **峰值内存**: {performance['peak_memory_mb']}MB",
            f"- **CPU 时间**: {performance['cpu_time']}s", ""
        ])

        if coverage_report and hasattr(coverage_report, 'scan_mode'):
            _, _, coverage_to_markdown = _lazy_load_detection_coverage()
            lines.append(coverage_to_markdown(coverage_report))

        if improvement_plan:
            lines.extend(self._generate_improvement_plan_markdown(improvement_plan))

        if start_time is not None:
            elapsed = time.time() - start_time
            logger.debug(f"Report generation completed in {elapsed:.2f}s")

        return "\n".join(lines)

    def _render_evidence_details(self, evidence: Evidence, lines: List[str]):
        """Render evidence detail fields for precise location and context."""
        details = evidence.evidence_details
        if not details:
            return

        # File-based evidence
        if details.file_path:
            lines.append(f"- **文件路径**: `{details.file_path}`")
            if details.line_number:
                lines.append(f"- **行号**: {details.line_number}")

            # 显示文件元数据（如果可用）
            if details.size:
                lines.append(f"- **文件大小**: {details.size}")
            if details.file_type:
                lines.append(f"- **文件类型**: {details.file_type}")

            if details.content:
                lines.append("")
                lines.append("**证据内容**:")
                lines.append("```")
                # 显示上下文（前后各3行）
                for ctx_line in details.context_before[-3:]:
                    lines.append(f"  {ctx_line}")
                lines.append(f">> {details.content}")
                for ctx_line in details.context_after[:3]:
                    lines.append(f"  {ctx_line}")
                lines.append("```")

        # Process-based evidence
        if details.pid:
            lines.append(f"- **PID**: {details.pid}")
            if details.cmdline:
                lines.append(f"- **命令行**: `{details.cmdline}`")
            if details.user:
                lines.append(f"- **用户**: {details.user}")
            if details.start_time:
                lines.append(f"- **启动时间**: {details.start_time}")
            if details.parent_pid:
                lines.append(f"- **父进程ID**: {details.parent_pid}")
            if details.executable:
                lines.append(f"- **可执行文件**: `{details.executable}`")
            if details.cwd:
                lines.append(f"- **工作目录**: `{details.cwd}`")
            if details.service_type:
                lines.append(f"- **服务类型**: {details.service_type}")

        # Network-based evidence
        if details.local_address or details.remote_address:
            if details.local_address:
                lines.append(f"- **本地地址**: {details.local_address}")
            if details.remote_address:
                lines.append(f"- **远程地址**: {details.remote_address}")
            if details.connection_state:
                lines.append(f"- **连接状态**: {details.connection_state}")

        # Credential assessment info
        if details.credential_type:
            lines.append(f"- **凭证类型**: {details.credential_type}")
        if details.permission_level:
            lines.append(f"- **权限范围**: {details.permission_level}")
        if details.rotation_url:
            lines.append(f"- **轮换地址**: {details.rotation_url}")
        if details.rotation_command:
            lines.append(f"- **轮换命令**: `{details.rotation_command}`")

    def _render_remediation_commands(self, evidence: Evidence, lines: List[str]):
        """Render remediation commands if available."""
        if not evidence.remediation_commands:
            return

        lines.append("")
        lines.append("**修复命令**:")
        lines.append("```bash")
        for cmd in evidence.remediation_commands:
            lines.append(cmd)
        lines.append("```")

    def _generate_correlation_summary_markdown(self, correlation_summary: Dict[str, Any]) -> List[str]:
        """Generate Markdown section for cross-analyzer correlation summary"""
        lines = ["", "## 跨分析器关联摘要", ""]

        # Summary statistics
        lines.extend([
            f"- **关联组总数**: {correlation_summary.get('total_groups', 0)}",
            f"- **跨分析器组**: {correlation_summary.get('cross_analyzer_groups', 0)}",
            f"- **升级告警数**: {correlation_summary.get('upgraded_count', 0)}",
            f"- **关联率**: {correlation_summary.get('correlation_rate', 0):.1%}",
            "",
        ])

        # Group details
        groups = correlation_summary.get('groups', [])
        if groups:
            lines.extend([
                "### 关联组详情",
                "",
                "| 组ID | 实体 | 分析器 | ATT&CK | 最大严重度 | 关联强度 |",
                "|------|------|--------|--------|-----------|---------|",
            ])

            for grp in groups[:20]:  # Limit to 20 groups
                group_id = grp.get('group_id', '-')
                entity = grp.get('entity_key', '-')
                analyzers = ', '.join(grp.get('analyzers', [])[:3])
                attack_ids = ', '.join(grp.get('attack_ids', [])[:3]) or '-'
                max_sev = grp.get('max_severity', '-')
                strength = f"{grp.get('correlation_strength', 0):.0%}"

                lines.append(
                    f"| {group_id} | {entity} | {analyzers} | {attack_ids} | {max_sev} | {strength} |"
                )

            if len(groups) > 20:
                lines.append(f"\n*... 还有 {len(groups) - 20} 个关联组，详见 JSON 报告*")

            lines.append("")

        return lines

    def _generate_improvement_plan_markdown(self, plan: 'ImprovementPlanData') -> List[str]:
        """Generate Markdown section for improvement plan"""
        lines = ["", "## 改进计划 (Improvement Plan)", ""]

        # Status summary
        status_text = {
            "enabled": "已启用",
            "disabled": "未启用",
            "anonymized": "已启用（脱敏）",
            "blocked": "已阻止",
        }.get(plan.reporting_status, plan.reporting_status)

        lines.extend([
            "### 数据上报状态",
            "",
            f"- **部署类型**: {plan.deployment_type}",
            f"- **改进计划**: {status_text}",
            f"- **改进建议数量**: {plan.suggestions_count}条",
            f"- **可上报数量**: {plan.reportable_count}条",
            f"- **脱敏处理数量**: {plan.anonymized_count}条",
            "",
        ])

        if plan.privacy_notice:
            lines.append(f"> {plan.privacy_notice}")
            lines.append("")

        # Show suggestions if enabled
        if plan.enabled and plan.suggestions:
            lines.extend([
                "### 改进建议详情",
                "",
            ])

            for sug in plan.suggestions[:10]:  # Limit to top 10
                severity_badge = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🔵",
                }.get(sug.get("severity", "MEDIUM"), "⚪")

                priority_text = {
                    "critical": "紧急",
                    "high": "高",
                    "medium": "中",
                    "low": "低",
                }.get(sug.get("fix_priority", "medium"), "中")

                lines.extend([
                    f"#### {sug.get('id', 'N/A')}: {sug.get('title', '无标题')} [{severity_badge} {sug.get('severity', 'N/A')}]",
                    "",
                    f"- **分类**: {sug.get('category', 'N/A')}",
                    f"- **描述**: {sug.get('description', '无描述')}",
                    f"- **建议**: {sug.get('recommendation', '无建议')}",
                    f"- **修复优先级**: {priority_text}",
                    "",
                ])

            if len(plan.suggestions) > 10:
                lines.append(f"*... 还有 {len(plan.suggestions) - 10} 条建议，详见 JSON 报告*")
                lines.append("")
        else:
            if not plan.enabled:
                lines.append("### 改进计划未启用")
                lines.append("")
                lines.append("加入改进计划可帮助我们发现新的安全威胁模式并优化检测规则。")
                lines.append("")

        return lines

    def save(self, content: str, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        filepath = os.path.join(output_dir, f"sec-report-{date_str}.md")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    def generate_minimal_report(self, judgment: dict, evidences: List[Evidence],
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
