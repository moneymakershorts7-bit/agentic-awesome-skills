"""ReportSummary: Report summary statistics for sec-userspace."""
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class ReportSummary:
    """Report summary statistics"""
    start_time: float
    end_time: float
    total_analyzers: int
    executed_analyzers: int
    successful_analyzers: int
    failed_analyzers: int
    skipped_analyzers: int
    total_alerts: int
    deduplicated_alerts: int
    fp_filtered: int
    confirmed_alerts: int
    suppressed_alerts: int = 0  # Number of suppressed alerts
    severity_counts: Dict[str, int] = field(default_factory=dict)
    whitelist_stats: Dict[str, int] = field(default_factory=dict)
    memory_usage: Dict[str, float] = field(default_factory=dict)  # Memory stats in MB
    analyzer_times: List[Dict[str, Any]] = field(default_factory=list)  # Per-analyzer execution times
    performance_regressions: List[Dict[str, Any]] = field(default_factory=list)  # Performance regression alerts
    skipped_analyzer_details: List[Dict[str, str]] = field(default_factory=list)  # Details of skipped analyzers
    detection_coverage: Dict[str, Any] = field(default_factory=dict)  # Detection coverage metrics
    analyzer_baselines: Dict[str, float] = field(default_factory=dict)  # Historical baseline durations per analyzer
    collector_completeness: Dict[str, Any] = field(default_factory=dict)  # Collector completeness scores
    quality_confidence: str = ""  # Data quality confidence level (HIGH/MEDIUM/LOW)
    quality_warnings: List[str] = field(default_factory=list)  # Data quality warning messages
    quality_coverage: Dict[str, Any] = field(default_factory=dict)  # Data coverage metrics

    data_quality_summary: Dict[str, Any] = field(default_factory=dict)  # Overall data quality summary
    degraded_collectors: List[str] = field(default_factory=list)  # Collectors with degraded data
    overall_data_completeness: float = 1.0  # Overall data completeness (0.0-1.0)
    confidence_adjusted_alerts: int = 0  # Number of alerts with adjusted confidence

    preload_status: Dict[str, Any] = field(default_factory=dict)  # Preload status (success/timeout/skipped/failed)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        # Validate timestamp is reasonable (not in the past/future beyond tolerance)
        current_time = time.time()
        one_year_seconds = 365 * 24 * 3600

        # Sanity check: start_time should be within last year and not in future
        if self.start_time <= 0 or self.start_time > current_time + 60 or self.start_time < current_time - one_year_seconds:
            logger.warning(
                f"Invalid scan start_time: {self.start_time}, "
                f"current_time: {current_time}. Using current time."
            )
            self.start_time = current_time

        # Ensure end_time is after start_time
        if self.end_time < self.start_time:
            logger.warning(
                f"end_time ({self.end_time}) before start_time ({self.start_time}). "
                f"Correcting end_time."
            )
            self.end_time = self.start_time

        result = {
            "scan_mode": "adaptive",
            "scan_timestamp": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "scan_duration_seconds": round(self.end_time - self.start_time, 2),
            "analyzer_execution": {
                "total": self.total_analyzers,
                "executed": self.executed_analyzers,
                "successful": self.successful_analyzers,
                "failed": self.failed_analyzers,
                "skipped": self.skipped_analyzers,
            },
            "skipped_analyzers": self.skipped_analyzer_details,
            "detection_results": {
                "total_alerts": self.total_alerts,
                "deduplicated": self.deduplicated_alerts,
                "fp_filtered": self.fp_filtered,
                "suppressed": self.suppressed_alerts,
                "confirmed": self.confirmed_alerts,
            },
            "severity_distribution": self.severity_counts,
            "whitelist_stats": self.whitelist_stats,
            "memory_usage_mb": self.memory_usage,
        }

        # Add top-10 slowest analyzers
        if self.analyzer_times:
            result["analyzer_performance"] = {
                "top_10_slowest": self._get_top_10_slowest(),
            }

        # Add performance regressions if any
        if self.performance_regressions:
            if "analyzer_performance" not in result:
                result["analyzer_performance"] = {}
            result["analyzer_performance"]["performance_regressions"] = self.performance_regressions

        # Add detection coverage if available
        if self.detection_coverage:
            result["detection_coverage"] = self.detection_coverage

        # Add analyzer baselines if available
        if self.analyzer_baselines:
            if "analyzer_performance" not in result:
                result["analyzer_performance"] = {}
            result["analyzer_performance"]["baselines"] = self.analyzer_baselines

        # Add collector completeness if available
        if self.collector_completeness:
            result["collector_completeness"] = self.collector_completeness

        # Add data quality summary (P2-2026-04-13)
        if self.data_quality_summary or self.degraded_collectors or self.overall_data_completeness < 1.0:
            result["data_quality"] = {
                "overall_completeness": round(self.overall_data_completeness, 2),
                "confidence_level": self.quality_confidence or "UNKNOWN",
                "degraded_collectors": self.degraded_collectors,
                "summary": self.data_quality_summary,
                "warnings": self.quality_warnings,
                "coverage": self.quality_coverage,
                "confidence_adjusted_alerts": self.confidence_adjusted_alerts,
            }
        elif self.quality_confidence or self.quality_warnings or self.quality_coverage:
            # Fallback to legacy format if new fields not set
            result["data_quality"] = {
                "confidence": self.quality_confidence or "UNKNOWN",
                "warnings": self.quality_warnings,
                "coverage": self.quality_coverage,
            }

        # Add preload status if available (P2-2026-04-13)
        if self.preload_status:
            result["preload_status"] = self.preload_status

        return result

    def _get_top_10_slowest(self) -> List[Dict[str, Any]]:
        """Get top 10 slowest analyzers"""
        if not self.analyzer_times:
            return []

        sorted_analyzers = sorted(
            self.analyzer_times,
            key=lambda x: x.get("duration", 0),
            reverse=True
        )

        return sorted_analyzers[:10]

    def _generate_preload_status_markdown(self) -> List[str]:
        """Generate Markdown section for preload completion status.

        Returns Markdown lines showing preload status when not 100% success.
        """
        lines = [
            "",
            "### 预加载状态",
            "",
        ]

        status = self.preload_status.get("status", "unknown")
        completion_rate = self.preload_status.get("completion_rate", 0)
        preloaded = self.preload_status.get("preloaded_analyzers", [])
        missing = self.preload_status.get("missing_analyzers", [])
        timeout_occurred = self.preload_status.get("timeout_occurred", False)

        status_text = {
            "success": "完全成功",
            "partial_success": "部分成功",
            "timeout": "超时",
            "failed": "失败",
            "skipped": "已跳过",
        }.get(status, status)

        lines.extend([
            f"- **预加载完成度**: {completion_rate:.0%} ({len(preloaded)}/{len(preloaded) + len(missing)})",
            f"- **预加载状态**: {status_text}",
        ])

        if missing:
            lines.append(f"- **未预加载的分析器**: {', '.join(missing)}")

        if timeout_occurred:
            lines.append(f"- **超时发生**: 是 - 预加载过程中发生超时")

        if status == "partial_success":
            lines.extend([
                "",
                "> **影响**: 部分分析器需在分析阶段按需加载，可能增加扫描时间。",
            ])
        elif status in ("timeout", "failed"):
            lines.extend([
                "",
                "> **警告**: 预加载失败，所有分析器将在分析阶段按需加载，显著增加扫描时间。",
            ])
        elif status == "skipped":
            lines.extend([
                "",
                "> **说明**: 预加载被跳过（可能在极简模式下运行）。",
            ])

        return lines
    def generate_summary_text(self) -> str:
        """Generate human-readable summary text"""
        return self._generate_full_summary_text()

    def _generate_full_summary_text(self) -> str:
        """Generate full summary text for complete scans."""
        lines = [
            "## 安全检测总结",
            "",
            "### 检测概览",
            f"- **检测模式**: Adaptive Scan",
            f"- **运行时间**: {datetime.fromtimestamp(self.start_time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **扫描时长**: {self.end_time - self.start_time:.1f}秒",
            "",
            "### Analyzer 执行情况",
            f"- **总 Analyzer 数量**: {self.total_analyzers}个",
            f"- **实际执行**: {self.executed_analyzers}个",
            f"- **执行成功**: {self.successful_analyzers}个",
            f"- **执行失败**: {self.failed_analyzers}个",
            f"- **跳过执行**: {self.skipped_analyzers}个",
            "",
            "### 检测结果",
            f"- **总告警数**: {self.total_alerts}个",
            f"- **去重后告警**: {self.deduplicated_alerts}个",
            f"- **误报过滤**: {self.fp_filtered}个",
            f"- **最终确认告警**: {self.confirmed_alerts}个",
            "",
            "### 风险评级",
        ]

        sev = self.severity_counts
        critical_action = "需要立即处理" if sev.get("CRITICAL", 0) > 0 else "-"
        high_action = "建议尽快处理" if sev.get("HIGH", 0) > 0 else "-"

        lines.extend([
            f"- **CRITICAL**: {sev.get('CRITICAL', 0)}个 ({critical_action})",
            f"- **HIGH**: {sev.get('HIGH', 0)}个 ({high_action})",
            f"- **MEDIUM**: {sev.get('MEDIUM', 0)}个",
            f"- **LOW**: {sev.get('LOW', 0)}个",
            "",
            "### 安全状态",
        ])

        if self.confirmed_alerts == 0 and self.failed_analyzers == 0:
            lines.append(f"✅ **{self.successful_analyzers}个 Analyzer 安全通过** - 未发现异常")
        elif self.confirmed_alerts > 0:
            lines.append(f"⚠️ **{self.confirmed_alerts}个告警需要关注** - 详见下方详情")
        else:
            lines.append("ℹ️ **部分 Analyzer 执行失败** - 请检查模块状态")

        if self.fp_filtered > 0:
            lines.append(f"🛡️ **已自动过滤 {self.fp_filtered}个误报** (白名单/环境匹配)")

        if self.suppressed_alerts > 0:
            lines.append(f"🔇 **已抑制 {self.suppressed_alerts}个告警** (抑制规则)")

        # Single adaptive mode - always show data quality
        if self.quality_confidence or self.quality_warnings or self.quality_coverage:
            lines.extend([
                "",
                "### 数据完整性评估",
                "",
            ])

            # Show confidence rating prominently
            confidence = self.quality_confidence or "UNKNOWN"
            if confidence == "HIGH":
                lines.append(f"- **数据可信度**: HIGH (高) - 本次扫描数据完整，结果可信")
            elif confidence == "MEDIUM":
                lines.extend([
                    "- **数据可信度**: MEDIUM (中) - 本次扫描基于部分数据，结果仅供参考",
                    "> 建议: 在系统负载较低时运行完整扫描获取完整结果。",
                ])
            elif confidence == "LOW":
                lines.extend([
                    "- **数据可信度**: LOW (低) - 本次扫描数据严重不足，结果不可信",
                    "> **警告**: 当前扫描仅分析了极小比例的攻击面，不能作为安全判定依据。",
                    "> 强烈建议: 立即运行完整扫描获取完整检测结果。",
                ])

            # Show process coverage if available
            proc_coverage = self.quality_coverage.get("process", {})
            if proc_coverage:
                collected = proc_coverage.get("collected", 0)
                total = proc_coverage.get("total_estimate", 0)
                pct = proc_coverage.get("coverage_percent", 0)
                lines.extend([
                    "",
                    f"- **进程采集**: {collected}/{total} (覆盖率 {pct:.1f}%)",
                ])
                if pct < 25:
                    lines.append(f"  > ⚠️ 覆盖率低于 25%，{total - collected} 个进程未分析")
                elif pct < 50:
                    lines.append(f"  > 部分进程未分析，检测结果可能不完整")

            # Show quality warnings
            if self.quality_warnings:
                lines.extend([
                    "",
                    "**详细警告**:",
                    "",
                ])
                for warning in self.quality_warnings:
                    lines.append(f"- {warning}")

        # Add skipped analyzers details
        if self.skipped_analyzer_details:
            lines.extend([
                "",
                "### 跳过的 Analyzer 详情",
                "",
                "以下 Analyzer 在当前扫描中被跳过（通常因数据质量问题）:",
                "",
                "| Analyzer | 跳过原因 |",
                "|----------|----------|",
            ])

            for skipped in self.skipped_analyzer_details:
                name = skipped.get("name", "unknown")
                reason = skipped.get("reason", "unknown")
                lines.append(f"| {name} | {reason} |")

        # Add top-10 slowest analyzers
        if self.analyzer_times:
            lines.extend([
                "",
                "### Analyzer 性能排行 (Top 10 最慢)",
                "",
                "| 排名 | Analyzer | 耗时 (秒) | 状态 | 发现数 |",
                "|------|----------|-----------|------|--------|",
            ])

            top_10 = self._get_top_10_slowest()
            for idx, analyzer_info in enumerate(top_10, 1):
                name = analyzer_info.get("name", "unknown")
                duration = analyzer_info.get("duration", 0)
                status = analyzer_info.get("status", "unknown")
                findings = analyzer_info.get("findings", 0)
                lines.append(f"| {idx} | {name} | {duration:.2f} | {status} | {findings} |")

        # Add performance regression warnings
        if self.performance_regressions:
            lines.extend([
                "",
                "### ⚠️ 性能回归警告",
                "",
                f"检测到 {len(self.performance_regressions)} 个 Analyzer 出现性能回归:",
                "",
            ])

            for regression in self.performance_regressions:
                name = regression.get("analyzer_name", "unknown")
                current_duration = regression.get("current_duration", 0)
                baseline_duration = regression.get("baseline_duration", 0)
                increase_pct = regression.get("increase_percentage", 0)

                # Check if baseline is meaningful (>= 0.5s threshold from perf_regression.py)
                MIN_REPORTABLE_BASELINE = 0.5
                if baseline_duration >= MIN_REPORTABLE_BASELINE:
                    lines.append(f"- **{name}**: {current_duration:.2f}s (基线: {baseline_duration:.2f}s, 增加 {increase_pct:.0f}%)")
                elif baseline_duration > 0:
                    lines.append(f"- **{name}**: {current_duration:.2f}s (基线: {baseline_duration:.2f}s, 历史数据不稳定)")
                else:
                    lines.append(f"- **{name}**: {current_duration:.2f}s (基线: 暂无可靠历史数据)")

        # Add per-collector memory breakdown if available
        if self.memory_usage and "collector_deltas" in self.memory_usage:
            collector_deltas = self.memory_usage["collector_deltas"]
            if collector_deltas:
                lines.extend([
                    "",
                    "### Collector 内存使用详情",
                    "",
                    "| Collector | 内存前 (MB) | 内存后 (MB) | 增量 (MB) |",
                    "|-----------|-------------|-------------|-----------|",
                ])

                # Sort by delta_mb descending to show heaviest collectors first
                sorted_collectors = sorted(
                    collector_deltas.items(),
                    key=lambda x: x[1].get("delta_mb", 0),
                    reverse=True
                )

                for name, delta_info in sorted_collectors:
                    before_mb = delta_info.get("before_mb", 0)
                    after_mb = delta_info.get("after_mb", 0)
                    delta_mb = delta_info.get("delta_mb", 0)
                    lines.append(f"| {name} | {before_mb:.1f} | {after_mb:.1f} | {delta_mb:+.1f} |")

                    # Display per-phase memory breakdown if available
                    extra_stats = delta_info.get("extra_stats", {})
                    memory_phases = extra_stats.get("memory_phases", {})
                    if memory_phases:
                        lines.append(f"|   **{name} - Phase Breakdown** | | | |")
                        for phase_name, phase_data in memory_phases.items():
                            phase_delta = phase_data.get("delta_mb", 0)
                            phase_total = phase_data.get("total_mb", 0)
                            truncated = phase_data.get("truncated", False)
                            trunc_marker = " [T]" if truncated else ""
                            lines.append(
                                f"|     {phase_name}{trunc_marker} | - | {phase_total:.1f} | {phase_delta:+.1f} |"
                            )

                        # Add phase summary
                        peak_phase = extra_stats.get("peak_phase_mb", 0)
                        gc_freed = extra_stats.get("gc_freed_mb", 0)
                        truncations = extra_stats.get("truncations_applied", 0)
                        if peak_phase or gc_freed or truncations:
                            summary_parts = []
                            if peak_phase:
                                summary_parts.append(f"Peak Phase: {peak_phase:.1f}MB")
                            if gc_freed:
                                summary_parts.append(f"GC Freed: {gc_freed:.1f}MB")
                            if truncations:
                                summary_parts.append(f"Truncations: {truncations}")
                            lines.append(f"|   **Summary** | | | {', '.join(summary_parts)} |")

                # Add summary stats
                baseline = self.memory_usage.get("baseline_mb", 0)
                peak = self.memory_usage.get("peak_mb", 0)
                current = self.memory_usage.get("current_mb", 0)
                budget = self.memory_usage.get("per_collector_budget_mb", 0)

                lines.extend([
                    "",
                    f"- **内存基线**: {baseline:.1f}MB (加载模块后，采集前)",
                    f"- **当前内存**: {current:.1f}MB",
                    f"- **峰值内存**: {peak:.1f}MB",
                    f"- **单 Collector 预算**: {budget:.1f}MB",
                ])

        # Add detection coverage section
        if self.detection_coverage:
            coverage = self.detection_coverage
            lines.extend([
                "",
                "### 检测覆盖度",
                "",
            ])

            # Detection coverage info
            lines.extend([
                f"- **检测覆盖度**: {coverage.get('overall_coverage_pct', 0):.1f}%",
                f"- **注册 Analyzer 总数**: {coverage.get('total_registered_analyzers', 0)}",
                f"- **已加载**: {coverage.get('loaded_analyzers', 0)}",
                f"- **成功执行**: {coverage.get('executed_analyzers', 0)}",
                "",
            ])

            # Add effectiveness rating
            effectiveness = coverage.get("effectiveness", {})
            if effectiveness:
                rating = effectiveness.get("rating", "UNKNOWN")
                recommendation = effectiveness.get("recommendation", "")
                rating_icons = {
                    "HIGH": "✅",
                    "MEDIUM": "⚠️",
                    "LOW": "🔶",
                    "MINIMAL": "❌",
                    "FULL": "✅",
                }
                icon = rating_icons.get(rating, "❓")
                lines.extend([
                    f"### 检测有效性评级",
                    "",
                    f"- **评级**: {icon} **{rating}**",
                    f"- **建议**: {recommendation}",
                    "",
                ])

            # Add coverage gap warnings
            gap_warnings = coverage.get("coverage_gap_warnings", [])
            if gap_warnings:
                high_warnings = [w for w in gap_warnings if w.get("severity") == "HIGH"]
                medium_warnings = [w for w in gap_warnings if w.get("severity") == "MEDIUM"]

                if high_warnings or medium_warnings:
                    lines.extend([
                        "### ⚠️ 检测覆盖缺口警告",
                        "",
                        f"当前扫描覆盖率 **{coverage.get('overall_coverage_pct', 0):.1f}%**，存在以下检测缺口:",
                        "",
                    ])

                    if high_warnings:
                        lines.extend([
                            "**高优先级缺口**:",
                            "",
                        ])
                        for w in high_warnings[:5]:
                            lines.append(f"- **{w['message']}**")
                            if w.get("analyzers_skipped"):
                                skipped = w["analyzers_skipped"][:3]
                                lines.append(f"  - 跳过检测器: {', '.join(skipped)}")
                        lines.append("")

                    if medium_warnings:
                        lines.extend([
                            "**中优先级缺口**:",
                            "",
                        ])
                        for w in medium_warnings[:5]:
                            lines.append(f"- {w['message']}")
                        lines.append("")

                    lines.extend([
                        "> 💡 **建议**: 在生产服务器上运行完整扫描以获取全面检测覆盖。",
                        "",
                    ])

            # Category coverage summary
            category_coverage = coverage.get("category_coverage", {})
            if category_coverage:
                # Count fully covered, partially covered, and skipped
                full_coverage = sum(1 for c in category_coverage.values() if c.get("coverage_pct", 0) == 100.0)
                partial_coverage = sum(1 for c in category_coverage.values() if 0 < c.get("coverage_pct", 0) < 100.0)
                no_coverage = sum(1 for c in category_coverage.values() if c.get("coverage_pct", 0) == 0.0)

                lines.extend([
                    f"- **安全类别覆盖**: {full_coverage}个完全覆盖, {partial_coverage}个部分覆盖, {no_coverage}个未覆盖",
                    "",
                ])

        # Add collector completeness section
        if self.collector_completeness:
            lines.extend([
                "",
                "### 数据采集完整度",
                "",
                "以下显示各数据采集模块的完整度评分，反映扫描结果的可信度:",
                "",
                "| 采集模块 | 完整度 | 状态 | 说明 |",
                "|----------|--------|------|------|",
            ])

            for collector, comp in self.collector_completeness.items():
                score = comp.get("score", 0)
                data_sufficient = comp.get("data_sufficient", True)
                warnings = comp.get("warnings", [])

                # Determine status icon
                if score >= 0.8:
                    status = "✅ 完整"
                elif score >= 0.5:
                    status = "⚠️ 部分"
                else:
                    status = "❌ 不足"

                # Get description from phases or warning
                description = "-"
                if warnings:
                    description = warnings[0][:50]
                elif not data_sufficient:
                    description = "数据不足"

                lines.append(f"| {collector} | {score:.0%} | {status} | {description} |")

            # Add overall assessment
            low_completeness = [
                (c, comp) for c, comp in self.collector_completeness.items()
                if comp.get("score", 0) < 0.5
            ]

            if low_completeness:
                lines.extend([
                    "",
                    "> ⚠️ **警告**: 部分采集模块完整度低于 50%，扫描结果可能不完整。",
                    "> 建议在系统负载较低时运行完整扫描获取完整结果。",
                    "",
                ])

        # Add preload status if not 100% success (P2-2026-04-13)
        if self.preload_status and self.preload_status.get("status") not in ("success",):
            lines.extend(self._generate_preload_status_markdown())

        return "\n".join(lines)
