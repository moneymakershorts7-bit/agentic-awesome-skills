"""SummaryGenerator: Build ReportSummary and compute module statistics for sec-userspace reports."""
import logging
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def compute_module_stats(module_stats: List[dict]):
    """Compute aggregated module statistics.

    Returns dict with total_analyzers, executed_analyzers, successful_analyzers,
    failed_analyzers, skipped_analyzers.
    """
    total_analyzers = 0
    executed_analyzers = 0
    successful_analyzers = 0
    failed_analyzers = 0
    skipped_analyzers = 0

    if module_stats:
        total_analyzers = len(module_stats)
        for m in module_stats:
            status = m.get("status", "unknown")
            if status == "success":
                successful_analyzers += 1
                executed_analyzers += 1
            elif status == "failed":
                failed_analyzers += 1
                executed_analyzers += 1
            elif status == "skipped":
                skipped_analyzers += 1

    return {
        "total_analyzers": total_analyzers,
        "executed_analyzers": executed_analyzers,
        "successful_analyzers": successful_analyzers,
        "failed_analyzers": failed_analyzers,
        "skipped_analyzers": skipped_analyzers,
    }


def build_skipped_analyzer_details(module_stats: List[dict]) -> List[Dict[str, str]]:
    """Build list of skipped analyzer details with names and reasons."""
    skipped_analyzer_details = []
    for module in module_stats:
        if module.get("status") == "skipped" and module.get("skip_reason"):
            skipped_analyzer_details.append({
                "name": module["name"],
                "reason": module["skip_reason"],
            })
    return skipped_analyzer_details


def compute_extended_stats(module_stats: List[dict], stream_out) -> Dict[str, float]:
    """Compute extended execution statistics (avg/max duration)."""
    try:
        extended_stats = {
            'total_modules': len(module_stats),
            'avg_duration': sum(m.get('duration', 0) for m in module_stats) / max(len(module_stats), 1),
            'max_duration': max((m.get('duration', 0) for m in module_stats), default=0),
        }
        stream_out.info(f"Extended stats: avg={extended_stats['avg_duration']:.2f}s, max={extended_stats['max_duration']:.2f}s")
        return extended_stats
    except (ValueError, KeyError, TypeError, ZeroDivisionError) as e:
        stream_out.info(f"Extended execution stats skipped (error: {e})")
        return {}


def get_memory_usage(throttle_ctrl) -> Dict[str, float]:
    """Get memory usage from throttle controller."""
    memory_usage = {}
    if throttle_ctrl is not None:
        try:
            memory_usage = throttle_ctrl.get_memory_report()
        except (KeyError, AttributeError):
            memory_usage = {}
    return memory_usage


def extract_quality_assessment(quality_assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract quality assessment data into a normalized dict."""
    collector_completeness = {}
    quality_confidence = ""
    quality_warnings = []
    quality_coverage = {}
    data_quality_summary = {}
    degraded_collectors = []
    overall_data_completeness = 1.0

    if quality_assessment:
        collector_completeness = quality_assessment.get("collector_completeness", {})
        quality_confidence = quality_assessment.get("confidence", "")
        quality_warnings = quality_assessment.get("warnings", [])
        quality_coverage = quality_assessment.get("coverage", {})
        dq_meta = quality_assessment
        data_quality_summary = {
            "collection_mode": dq_meta.get("collection_mode", "normal"),
            "total_collectors": len(dq_meta.get("completeness_scores", {})),
            "degraded_count": len(dq_meta.get("degraded_modules", [])),
        }
        degraded_collectors = dq_meta.get("degraded_modules", [])
        overall_data_completeness = dq_meta.get("overall_completeness", 1.0)

    return {
        "collector_completeness": collector_completeness,
        "quality_confidence": quality_confidence,
        "quality_warnings": quality_warnings,
        "quality_coverage": quality_coverage,
        "data_quality_summary": data_quality_summary,
        "degraded_collectors": degraded_collectors,
        "overall_data_completeness": overall_data_completeness,
    }


def build_report_summary(
    ReportSummary_cls,
    ImprovementPlanData_cls,
    start_wall_time: Optional[float],
    evidences: List,
    deduped_evidences: List,
    suppressed_alerts_count: int,
    review_stats: Dict[str, int],
    judgment: Dict[str, Any],
    whitelist_stats: Dict[str, Any],
    memory_usage: Dict[str, float],
    analyzer_times: List[Dict[str, Any]],
    performance_regressions: List[Dict[str, Any]],
    skipped_analyzer_details: List[Dict[str, str]],
    detection_coverage: Dict[str, Any],
    analyzer_baselines: Dict[str, float],
    quality_data: Dict[str, Any],
    confidence_adjusted_alerts: int,
    preload_status: Optional[Dict[str, Any]],
    module_stats_computed: Dict[str, int],
) -> Any:
    """Build ReportSummary with all computed data.

    Returns a ReportSummary instance.
    """
    summary = ReportSummary_cls(
        start_time=start_wall_time or time.time(),
        end_time=time.time(),
        total_analyzers=module_stats_computed["total_analyzers"],
        executed_analyzers=module_stats_computed["executed_analyzers"],
        successful_analyzers=module_stats_computed["successful_analyzers"],
        failed_analyzers=module_stats_computed["failed_analyzers"],
        skipped_analyzers=module_stats_computed["skipped_analyzers"],
        total_alerts=len(evidences) + suppressed_alerts_count,
        deduplicated_alerts=len(deduped_evidences),
        fp_filtered=review_stats.get('filtered', 0) + review_stats.get('likely_fp', 0),
        suppressed_alerts=suppressed_alerts_count,
        confirmed_alerts=len(deduped_evidences),
        severity_counts=judgment["severity_counts"],
        whitelist_stats=whitelist_stats,
        memory_usage=memory_usage,
        analyzer_times=analyzer_times,
        performance_regressions=performance_regressions,
        skipped_analyzer_details=skipped_analyzer_details,
        detection_coverage=detection_coverage,
        analyzer_baselines=analyzer_baselines,
        collector_completeness=quality_data.get("collector_completeness", {}),
        quality_confidence=quality_data.get("quality_confidence", ""),
        quality_warnings=quality_data.get("quality_warnings", []),
        quality_coverage=quality_data.get("quality_coverage", {}),
        data_quality_summary=quality_data.get("data_quality_summary", {}),
        degraded_collectors=quality_data.get("degraded_collectors", []),
        overall_data_completeness=quality_data.get("overall_data_completeness", 1.0),
        confidence_adjusted_alerts=confidence_adjusted_alerts,
        preload_status=preload_status or {},
    )
    return summary


class SummaryGenerator:
    """Generate report summary data and statistics."""

    def compute_stats(self, module_stats: List[dict]) -> Dict[str, int]:
        """Compute aggregated module statistics."""
        return compute_module_stats(module_stats)

    def build_skipped_details(self, module_stats: List[dict]) -> List[Dict[str, str]]:
        """Build skipped analyzer details list."""
        return build_skipped_analyzer_details(module_stats)

    def get_memory_usage(self, throttle_ctrl) -> Dict[str, float]:
        """Get memory usage from throttle controller."""
        return get_memory_usage(throttle_ctrl)

    def extract_quality(self, quality_assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract and normalize quality assessment data."""
        return extract_quality_assessment(quality_assessment)

    def build_summary(
        self,
        ReportSummary_cls,
        ImprovementPlanData_cls,
        start_wall_time: Optional[float],
        evidences: List,
        deduped_evidences: List,
        suppressed_alerts_count: int,
        review_stats: Dict[str, int],
        judgment: Dict[str, Any],
        whitelist_stats: Dict[str, Any],
        memory_usage: Dict[str, float],
        analyzer_times: List[Dict[str, Any]],
        performance_regressions: List[Dict[str, Any]],
        skipped_analyzer_details: List[Dict[str, str]],
        detection_coverage: Dict[str, Any],
        analyzer_baselines: Dict[str, float],
        quality_data: Dict[str, Any],
        confidence_adjusted_alerts: int,
        preload_status: Optional[Dict[str, Any]],
        module_stats_computed: Dict[str, int],
    ) -> Any:
        """Build ReportSummary with all computed data."""
        return build_report_summary(
            ReportSummary_cls=ReportSummary_cls,
            ImprovementPlanData_cls=ImprovementPlanData_cls,
            start_wall_time=start_wall_time,
            evidences=evidences,
            deduped_evidences=deduped_evidences,
            suppressed_alerts_count=suppressed_alerts_count,
            review_stats=review_stats,
            judgment=judgment,
            whitelist_stats=whitelist_stats,
            memory_usage=memory_usage,
            analyzer_times=analyzer_times,
            performance_regressions=performance_regressions,
            skipped_analyzer_details=skipped_analyzer_details,
            detection_coverage=detection_coverage,
            analyzer_baselines=analyzer_baselines,
            quality_data=quality_data,
            confidence_adjusted_alerts=confidence_adjusted_alerts,
            preload_status=preload_status,
            module_stats_computed=module_stats_computed,
        )
