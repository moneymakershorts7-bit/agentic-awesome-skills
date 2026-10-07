"""Chinese report generator for sec-userspace.

This module generates localized Chinese Markdown reports from English internal data.
All JSON reports remain in English for programmatic processing.
"""

import os
import logging
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from .evidence import Evidence
from .report import (
    MarkdownReportGenerator,
    JsonReportGenerator,
    ReportSummary,
    ImprovementPlanData,
    aggregate_evidences,
    sanitize_evidence
)
from .detection_coverage import DetectionCoverageReport, coverage_to_markdown
from ..utils.i18n import (
    translate_conclusion,
    translate_severity,
    translate_module
)


_logger = None
_logger_lock = threading.Lock()


def _get_logger():
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                _logger = logging.getLogger('sec-userspace')
    return _logger


class ChineseReportGenerator:
    """Generate Chinese localized Markdown reports."""

    def generate(
        self,
        judgment: dict,
        evidences: List[Evidence],
        timeline: List[dict],
        system_info: dict,
        module_stats: List[dict],
        performance: dict,
        summary: 'ReportSummary' = None,
        improvement_plan: Optional['ImprovementPlanData'] = None,
        whitelist_metadata: Dict[str, Any] = None,
        correlation_summary: Optional[Dict[str, Any]] = None,
        coverage_report: Optional['DetectionCoverageReport'] = None
    ) -> str:
        """Generate Chinese Markdown report.
        
        Args:
            judgment: Judgment result from JudgmentEngine
            evidences: List of evidence items
            timeline: Timeline of events
            system_info: System information
            module_stats: Module execution statistics
            performance: Performance metrics
            summary: Report summary statistics
            
        Returns:
            Chinese Markdown report content
        """
        lines = ["# Security Intrusion Detection Report", "", ""]
        
        # Add summary at the beginning if available
        if summary:
            lines.append(summary.generate_summary_text())
            lines.extend(["", ""])
        
        lines.extend(["## Executive Summary", ""])
        
        sc = judgment["severity_counts"]
        total_evidence_count = judgment.get("evidence_count", len(evidences))
        agg_groups = aggregate_evidences(evidences)
        
        # Translate conclusion
        en_conclusion = judgment["conclusion"]
        zh_conclusion = translate_conclusion(en_conclusion)
        
        lines.extend([
            f"- **Detection Time**: {datetime.now(timezone.utc).isoformat()}",
            f"- **Target Host**: {system_info.get('hostname', 'unknown')}",
            f"- **Operating System**: {system_info.get('os_release', 'unknown')}",
            f"- **Detection Conclusion**: {zh_conclusion}",
            f"- **Risk Score**: {judgment['total_score']}/100",
            f"- **Alert Statistics**: {total_evidence_count} events merged into {len(agg_groups)} alerts",
            "",
            "### Severity Distribution",
            "",
            f"| Severity | Count |",
            f"|----------|------|",
            f"| CRITICAL | {sc['CRITICAL']} |",
            f"| HIGH | {sc['HIGH']} |",
            f"| MEDIUM | {sc['MEDIUM']} |",
            f"| LOW | {sc['LOW']} |",
            "",
            "## Security Alerts Summary",
            "",
            "| Severity | Alert Name | Count | ATT&CK | Source Module | Confidence |",
            "|--------|----------|------|--------|----------|--------|",
        ])
        
        for group in agg_groups:
            zh_severity = translate_severity(group.severity.value)
            zh_module = translate_module(group.module)
            count_badge = f"x{group.count}" if group.count > 1 else "1"
            attack = group.attack_id if group.attack_id else "-"
            
            lines.append(
                f"| {zh_severity} | {group.title} | {count_badge} | {attack} | {zh_module} | {group.confidence:.0%} |"
            )
        
        lines.extend(["", "## Alert Details", ""])
        
        for group in agg_groups:
            sanitized = sanitize_evidence(group.representative)
            zh_severity = translate_severity(group.severity.value)
            zh_module = translate_module(group.module)
            
            header = f"### [{zh_severity}] {group.title}"
            if group.count > 1:
                header += f" (Total {group.count} items)"
            
            lines.append(header)
            lines.append(f"- **Description**: {sanitized.description}")
            lines.append(f"- **Detection Module**: {zh_module} ({group.module})")
            
            # Add correlation context if present
            corr = group.representative.raw_data.get("correlation") if group.representative.raw_data else None
            if corr:
                related = corr.get("related_analyzers", [])
                if related:
                    lines.append(f"- **Correlated Analyzers**: {', '.join(related)}")
                orig_sev = corr.get("original_severity")
                if orig_sev:
                    orig_sev_zh = translate_severity(orig_sev)
                    lines.append(f"- **Original Severity**: {orig_sev_zh} (correlation upgraded)")
                group_id = corr.get("group_id")
                if group_id:
                    lines.append(f"- **Correlation Group ID**: {group_id}")
            
            if group.source_paths:
                if len(group.source_paths) <= 3:
                    paths_str = ', '.join(group.source_paths)
                    lines.append(f"- **Evidence Source**: {paths_str}")
                else:
                    shown = ', '.join(group.source_paths[:3])
                    lines.append(f"- **Evidence Source**: {shown} and {len(group.source_paths)} more")
            
            if group.attack_id:
                lines.append(f"- **ATT&CK Technique**: {group.attack_id}")
            
            # Render evidence details for precise location and context
            self._render_evidence_details(group.representative, lines)
            
            if group.remediation:
                lines.append(f"- **Remediation**: {group.remediation}")
            
            # Render remediation commands if available
            self._render_remediation_commands(group.representative, lines)
            
            lines.append("")
        
        # Module execution status
        lines.extend([
            "## Module Execution Status",
            "",
            "| Module | Status | Findings | Duration |",
            "|------|------|--------|------|"
        ])
        
        for stat in module_stats:
            zh_name = translate_module(stat['name'])
            status_map = {
                "success": "Success",
                "skipped": "Skipped",
                "error": "Error"
            }
            zh_status = status_map.get(stat['status'], stat['status'])
            lines.append(
                f"| {zh_name} | {zh_status} | {stat['findings']} | {stat['duration']:.1f}s |"
            )
        
        # Timeline
        lines.extend(["", "## Intrusion Timeline", ""])
        
        if timeline:
            lines.extend([
                "| Time | Severity | Source Module | Finding | ATT&CK |",
                "|------|--------|---------|------|--------|"
            ])
            
            for entry in timeline:
                ts = entry["timestamp"].replace("T", " ").split(".")[0][:19] if "T" in entry["timestamp"] else entry["timestamp"]
                zh_sev = translate_severity(entry['severity'])
                zh_mod = translate_module(entry['module'])
                lines.append(
                    f"| {ts} | {zh_sev} | {zh_mod} | {entry['title']} | {entry['attack_id']} |"
                )
        else:
            lines.append("No intrusion events recorded")
        
        # Threat intel version
        try:
            from ..threat_intel.ioc_loader import get_loader
            loader = get_loader()
            stats = loader.stats
            
            lines.extend([
                "", "## Threat Intelligence Version", "",
                f"- **Version**: {stats.get('version', 'unknown')}",
                f"- **Update Date**: {stats.get('created', 'unknown')}",
                f"- **Source**: sec-userspace assets",
                f"- **Malicious Port Count**: {stats.get('c2_ports', 0)}",
                f"- **Mining Pool Count**: {stats.get('mining_pools', 0)}",
                f"- **C2 Port Count**: {stats.get('mining_ports', 0)}",
                f"- **Total IoC Count**: {stats.get('total', 0)}",
                ""
            ])
        except (KeyError, TypeError, ValueError) as e:
            _get_logger().debug(f"Failed to render threat intel section: {e}")
        
        # Whitelist version information from EBPFAnalyzer
        if whitelist_metadata:
            try:
                source_text = {
                    'cloud': 'Cloud Sync',
                    'cache': 'Local Cache',
                    'local': 'Local Whitelist',
                    'error': 'Fetch Failed'
                }.get(whitelist_metadata.get('whitelist_source', 'unknown'), 'Unknown')
                
                cache_status = 'Valid' if whitelist_metadata.get('whitelist_cache_valid', False) else 'Invalid/Not Used'
                
                lines.extend([
                    "", "## eBPF Whitelist Version", "",
                    f"- **Version**: {whitelist_metadata.get('whitelist_version', 'unknown')}",
                    f"- **Source**: {source_text}",
                    f"- **Cache Status**: {cache_status}",
                    ""
                ])
            except (KeyError, TypeError, ValueError) as e:
                _get_logger().debug(f"Failed to render whitelist metadata: {e}")
        
        # Add cross-analyzer correlation summary section
        if correlation_summary:
            lines.extend(self._generate_correlation_summary_markdown_cn(correlation_summary))
        
        # System info
        lines.extend([
            "", "## System Information Summary", "",
            "| Item | Value |",
            "|------|------|",
            f"| Hostname | {system_info.get('hostname', 'unknown')} |",
            f"| Operating System | {system_info.get('os_release', 'unknown')} |",
            f"| Kernel Version | {system_info.get('kernel_version', 'unknown')} |",
            f"| CPU Cores | {system_info.get('cpu_count', 0)} |",
            f"| Total Memory | {system_info.get('memory_total_mb', 0)}MB |",
            "",
            "## Performance Metrics",
            "",
            f"- **Total Execution Time**: {performance['total_duration']}s",
            f"- **Peak Memory**: {performance['peak_memory_mb']}MB",
            f"- **CPU Time**: {performance['cpu_time']}s",
            ""
        ])
        
        # Add detection coverage analysis
        if coverage_report:
            lines.append(coverage_to_markdown(coverage_report))
        
        # Add improvement plan section if available
        if improvement_plan:
            lines.extend(self._generate_improvement_plan_cn(improvement_plan))
        
        return "\n".join(lines)
    
    def _generate_correlation_summary_markdown_cn(self, correlation_summary: Dict[str, Any]) -> List[str]:
        """Generate Chinese Markdown section for cross-analyzer correlation summary"""
        lines = ["", "## Cross-Analyzer Correlation Summary", ""]
        
        # Summary statistics
        lines.extend([
            f"- **Total Correlation Groups**: {correlation_summary.get('total_groups', 0)}",
            f"- **Cross-Analyzer Groups**: {correlation_summary.get('cross_analyzer_groups', 0)}",
            f"- **Upgraded Alerts**: {correlation_summary.get('upgraded_count', 0)}",
            f"- **Correlation Rate**: {correlation_summary.get('correlation_rate', 0):.1%}",
            "",
        ])
        
        # Group details
        groups = correlation_summary.get('groups', [])
        if groups:
            lines.extend([
                "### Correlation Group Details",
                "",
                "| Group ID | Entity | Analyzers | ATT&CK | Max Severity | Strength |",
                "|------|------|--------|--------|-----------|---------|",
            ])
            
            for grp in groups[:20]:
                group_id = grp.get('group_id', '-')
                entity = grp.get('entity_key', '-')
                analyzers = ', '.join(grp.get('analyzers', [])[:3])
                attack_ids = ', '.join(grp.get('attack_ids', [])[:3]) or '-'
                max_sev = translate_severity(grp.get('max_severity', '-'))
                strength = f"{grp.get('correlation_strength', 0):.0%}"
                
                lines.append(
                    f"| {group_id} | {entity} | {analyzers} | {attack_ids} | {max_sev} | {strength} |"
                )
            
            if len(groups) > 20:
                lines.append(f"\n*... {len(groups) - 20} more groups, see JSON report*")
            
            lines.append("")
        
        return lines
    
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
            lines.append(f"- **进程ID**: {details.pid}")
            if details.cmdline:
                lines.append(f"- **命令行**: `{details.cmdline}`")
            if details.executable:
                lines.append(f"- **可执行文件**: `{details.executable}`")
            if details.user:
                lines.append(f"- **运行用户**: {details.user}")
            if details.start_time:
                lines.append(f"- **启动时间**: {details.start_time}")
            if details.parent_pid:
                lines.append(f"- **父进程ID**: {details.parent_pid}")
            if details.cwd:
                lines.append(f"- **工作目录**: `{details.cwd}`")
            if details.service_type:
                lines.append(f"- **服务类型**: {details.service_type}")

        # Network-based evidence
        if details.local_address or details.remote_address:
            lines.append("")
            lines.append("**网络连接信息**:")
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
        lines.append("**Remediation Commands**:")
        lines.append("```bash")
        for cmd in evidence.remediation_commands:
            lines.append(cmd)
        lines.append("```")

    def _generate_improvement_plan_cn(self, plan: 'ImprovementPlanData') -> List[str]:
        """Generate Chinese Markdown section for improvement plan"""
        lines = ["", "## 改进计划 (Improvement Plan)", ""]
        
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
        
        if plan.enabled and plan.suggestions:
            lines.extend([
                "### 改进建议详情",
                "",
            ])
            
            priority_map = {
                "critical": "紧急",
                "high": "高",
                "medium": "中",
                "low": "低",
            }
            
            for sug in plan.suggestions[:10]:
                severity_zh = {
                    "CRITICAL": "严重",
                    "HIGH": "高危",
                    "MEDIUM": "中等",
                    "LOW": "低危",
                }.get(sug.get("severity", "MEDIUM"), "中等")
                
                lines.extend([
                    f"#### {sug.get('id', 'N/A')}: {sug.get('title', '无标题')} [{severity_zh}]",
                    "",
                    f"- **分类**: {sug.get('category', 'N/A')}",
                    f"- **描述**: {sug.get('description', '无描述')}",
                    f"- **建议**: {sug.get('recommendation', '无建议')}",
                    f"- **修复优先级**: {priority_map.get(sug.get('fix_priority', 'medium'), '中')}",
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
        """Save Chinese report to file.
        
        Args:
            content: Report content
            output_dir: Output directory
            
        Returns:
            Path to saved file
        """
        os.makedirs(output_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        filepath = os.path.join(output_dir, f"sec-report-{date_str}-cn.md")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    def generate_minimal_report(
        self,
        judgment: dict,
        evidences: List[Evidence],
        system_info: dict,
        module_stats: List[dict],
        performance: dict,
        summary: 'ReportSummary' = None,
        load_ratio: float = 0.0
    ) -> str:
        """Generate a minimal Chinese report (for quick scans).
        
        Args:
            judgment: Judgment result from JudgmentEngine
            evidences: List of evidence items
            system_info: System information
            module_stats: Module execution statistics
            performance: Performance metrics
            summary: Report summary statistics
            load_ratio: System load ratio
            
        Returns:
            Chinese Markdown report content
        """
        return self.generate(
            judgment=judgment,
            evidences=evidences,
            timeline=[],
            system_info=system_info,
            module_stats=module_stats,
            performance=performance,
            summary=summary,
        )


def generate_bilingual_reports(
    judgment: dict,
    evidences: List[Evidence],
    timeline: List[dict],
    system_info: dict,
    module_stats: List[dict],
    performance: dict,
    output_dir: str,
    summary: 'ReportSummary' = None,
    improvement_plan: Optional['ImprovementPlanData'] = None,
    whitelist_metadata: Dict[str, Any] = None,
    correlation_summary: Optional[Dict[str, Any]] = None,
    coverage_report: Optional['DetectionCoverageReport'] = None
) -> Dict[str, str]:
    """Generate both English and Chinese reports.
    
    Args:
        judgment: Judgment result
        evidences: Evidence list
        timeline: Timeline
        system_info: System info
        module_stats: Module stats
        performance: Performance metrics
        output_dir: Output directory
        summary: Report summary statistics
        improvement_plan: Improvement plan data
        whitelist_metadata: Whitelist metadata from EBPFAnalyzer
        correlation_summary: Cross-analyzer correlation summary
        coverage_report: Detection coverage analysis report
        
    Returns:
        Dictionary with paths to generated reports
    """
    md_gen = MarkdownReportGenerator()
    cn_gen = ChineseReportGenerator()
    json_gen = JsonReportGenerator()
    
    # Generate English Markdown
    en_content = md_gen.generate(
        judgment, evidences, timeline, system_info, module_stats, performance, summary, improvement_plan,
        whitelist_metadata=whitelist_metadata, correlation_summary=correlation_summary, coverage_report=coverage_report
    )
    en_path = md_gen.save(en_content, output_dir)
    
    # Generate Chinese Markdown
    cn_content = cn_gen.generate(
        judgment, evidences, timeline, system_info, module_stats, performance, summary, improvement_plan,
        whitelist_metadata=whitelist_metadata, correlation_summary=correlation_summary, coverage_report=coverage_report
    )
    cn_path = cn_gen.save(cn_content, output_dir)
    
    # Generate JSON (always English)
    json_content = json_gen.generate(
        judgment, evidences, system_info, module_stats, performance, 
        summary=summary, improvement_plan=improvement_plan,
        whitelist_metadata=whitelist_metadata, correlation_summary=correlation_summary,
        coverage_report=coverage_report
    )
    json_path = json_gen.save(json_content, output_dir)
    
    return {
        "english": en_path,
        "chinese": cn_path,
        "json": json_path
    }
