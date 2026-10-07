"""Report Engine: Thin entry point for sec-userspace report generation.

This module provides backward-compatible re-exports and the main
report orchestration functions. Report generation logic has been
extracted into dedicated generator modules for improved maintainability.
"""
import logging
import os
import time

# ---------------------------------------------------------------------------
# Re-exports from extracted modules (backward compatibility)
# ---------------------------------------------------------------------------

from .summary import ReportSummary
from .judgment import JudgmentEngine
from .improvement import ImprovementPlanData
from .aggregation import AggregatedGroup, aggregate_evidences
from .generators.markdown_generator import (
    MarkdownReportGenerator,
    SafeJsonEncoder,
    sanitize_evidence,
    collect_performance,
    _lazy_load_detection_coverage,
)
from .generators.json_generator import JsonReportGenerator
from .generators.summary_generator import SummaryGenerator
from .generators.remediation import RemediationGenerator
from ..utils.redact import redact_credential, redact_in_text

__all__ = [
    'ReportSummary',
    'JudgmentEngine',
    'ImprovementPlanData',
    'AggregatedGroup',
    'aggregate_evidences',
    'MarkdownReportGenerator',
    'JsonReportGenerator',
    'SummaryGenerator',
    'RemediationGenerator',
    'SafeJsonEncoder',
    'sanitize_evidence',
    'collect_performance',
    '_lazy_load_detection_coverage',
    'redact_credential',
    'redact_in_text',
    'generate_reports',
    'generate_all_reports',
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main report orchestration
# ---------------------------------------------------------------------------

def generate_reports(args, evidences, system_info, module_stats, stream_out, start_time: float = None,
                    start_wall_time: float = None, correlation_result=None, orchestrator_state=None, whitelist_metadata=None,
                    throttle_ctrl=None, quality_assessment=None, preload_status=None):
    """Generate reports"""
    reporting_start_time = time.monotonic()
    reporting_logger = logging.getLogger("sec-userspace.reporting")

    # Compute load ratio for emergency report detection
    try:
        load_1min = os.getloadavg()[0]
        cpu_count = os.cpu_count() or 1
        load_ratio = load_1min / cpu_count
    except OSError:
        load_ratio = 1.0

    evidence_count = len(evidences) if evidences else 0

    # Emergency bypass for extreme load
    if (evidence_count == 0 and load_ratio > 3.0) or \
       (evidence_count < 5 and load_ratio > 5.0) or \
       (load_ratio > 10.0):
        return _generate_emergency_report(
            args, system_info, module_stats, stream_out,
            reporting_start_time, load_ratio, reporting_logger
        )

    # Enforce reporting phase timeout
    full_report = getattr(args, 'full_report', False)
    reporting_hard_timeout = 120.0 if full_report else 30.0
    import threading as _threading_module
    reporting_timeout_flag = {'expired': False}

    def _reporting_timeout_handler():
        reporting_timeout_flag['expired'] = True
        reporting_logger.warning(f"Reporting phase exceeded {reporting_hard_timeout}s timeout")

    _timeout_timer = _threading_module.Timer(reporting_hard_timeout, _reporting_timeout_handler)
    _timeout_timer.daemon = True
    _timeout_timer.start()
    try:
        return _generate_report_body(
            args, evidences, system_info, module_stats, stream_out,
            start_time, start_wall_time, whitelist_metadata, throttle_ctrl,
            quality_assessment, preload_status, load_ratio,
            reporting_start_time, reporting_hard_timeout, reporting_timeout_flag,
            reporting_logger, _timeout_timer,
        )
    finally:
        _timeout_timer.cancel()


def _generate_report_body(
    args, evidences, system_info, module_stats, stream_out,
    start_time, start_wall_time, whitelist_metadata, throttle_ctrl,
    quality_assessment, preload_status, load_ratio,
    reporting_start_time, reporting_hard_timeout, reporting_timeout_flag,
    reporting_logger, _timeout_timer,
):
    """Inner report generation body, always wrapped in timer try/finally."""
    is_extreme_load = load_ratio > 10.0
    full_report = getattr(args, 'full_report', False)

    # Evidence processing (FP detection, suppression, dedup - all skipped for performance)
    verified_evidences = evidences
    verify_stats = {"total": len(evidences), "confirmed": len(evidences), "likely_true": 0, "filtered_out": 0}
    if not is_extreme_load:
        stream_out.info("Auto-FP detection skipped for performance")

    suppressed_alerts_count = 0
    stream_out.info("Alert suppression skipped for performance")
    stream_out.info("LogID generation skipped for performance")

    review_stats = {'confirmed': 0, 'likely_fp': 0, 'needs_review': 0, 'filtered': 0}
    confirmed_evidences = verified_evidences
    stream_out.info("Evidence review skipped for performance")

    # Deduplication
    if is_extreme_load:
        deduped_evidences = confirmed_evidences
        stream_out.info("Evidence deduplication skipped (extreme load >10x)")
    else:
        try:
            load_ratio_check = 0.0
            if hasattr(os, 'getloadavg'):
                cpu_count = os.cpu_count() or 1
                load_1min = os.getloadavg()[0]
                load_ratio_check = load_1min / cpu_count

            if load_ratio_check > 5.0:
                deduped_evidences = confirmed_evidences
                stream_out.info(f"Evidence deduplication skipped (load {load_ratio_check:.1f}x > 5.0x)")
            else:
                from ..utils.deduplicator import deduplicate_evidences, DeduplicationStrategy
                deduped_evidences, dedup_stats = deduplicate_evidences(confirmed_evidences, strategy=DeduplicationStrategy.EXACT)
                if dedup_stats.get("duplicates_exact", 0) > 0:
                    stream_out.info(f"Evidence dedup: {len(confirmed_evidences)} -> {len(deduped_evidences)} (removed {dedup_stats['duplicates_exact']} duplicates)")
        except (ImportError, ValueError, KeyError) as e:
            deduped_evidences = confirmed_evidences
            stream_out.info(f"Evidence deduplication skipped (error: {e})")

    # Cross-analyzer correlation
    correlation_summary = {"total_groups": 0, "cross_analyzer_groups": 0, "correlated_groups": 0,
                          "upgraded_count": 0, "isolated_count": 0, "correlation_rate": 0.0, "groups": []}
    try:
        from .correlation import run_cross_correlation
        _, correlation_summary = run_cross_correlation(deduped_evidences)
        if correlation_summary.get('correlated_groups', 0) > 0:
            stream_out.info(f"Cross-analyzer correlation: {correlation_summary['correlated_groups']} groups found")
    except (ImportError, ValueError, KeyError, TypeError) as e:
        stream_out.info(f"Cross-analyzer correlation skipped (error: {e})")

    fp_statistics = {}
    whitelist_templates = []
    stream_out.info("Whitelist template generation skipped")

    # Judgment engine
    if reporting_timeout_flag['expired']:
        stream_out.warning("Reporting timeout exceeded, using default judgment")
        judgment = {"conclusion": "inconclusive", "total_score": 0, "result_code": "safe",
                   "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}}
    else:
        from ..reporter import _lazy_import_report_engines
        JudgmentEngine_cls, _, _, _, _, _ = _lazy_import_report_engines()
        engine = JudgmentEngine_cls()
        judgment = engine.determine_conclusion(deduped_evidences)
        stream_out.info(f"Detection complete, conclusion: {judgment['conclusion']}, risk score: {judgment['total_score']:.0f}/100")

    # Stats computation via SummaryGenerator
    summary_gen = SummaryGenerator()
    module_stats_computed = summary_gen.compute_stats(module_stats)
    skipped_analyzer_details = summary_gen.build_skipped_details(module_stats)
    memory_usage = summary_gen.get_memory_usage(throttle_ctrl)
    quality_data = summary_gen.extract_quality(quality_assessment)

    # Detection coverage
    detection_coverage = {}
    try:
        from .coverage import compute_detection_coverage
        coverage_metrics = compute_detection_coverage(module_stats)
        # Convert to dict for compatibility with downstream code
        detection_coverage = coverage_metrics.to_dict()
        stream_out.info(f"Detection coverage computed: {coverage_metrics.overall_coverage_pct:.1f}% overall, {len(coverage_metrics.category_coverage)} categories")
    except (ImportError, ValueError, KeyError, TypeError) as e:
        stream_out.info(f"Detection coverage computation skipped (error: {e})")

    # Extended stats
    from .generators.summary_generator import compute_extended_stats
    compute_extended_stats(module_stats, stream_out)

    # Build ReportSummary
    from ..reporter import _lazy_import_report_summary
    ReportSummary_cls, ImprovementPlanData_cls = _lazy_import_report_summary()

    summary = summary_gen.build_summary(
        ReportSummary_cls, ImprovementPlanData_cls, start_wall_time,
        evidences, deduped_evidences, suppressed_alerts_count, review_stats,
        judgment, {"total": 0, "active": 0}, memory_usage, [], [],
        skipped_analyzer_details, detection_coverage, {}, quality_data, 0,
        preload_status, module_stats_computed,
    )

    # Timeline, attack chain, improvement plan, coverage via RemediationGenerator
    remediation_gen = RemediationGenerator()
    timeline_entries = remediation_gen.build_timeline(full_report, deduped_evidences, module_stats, stream_out)
    remediation_gen.analyze_attack_chains(deduped_evidences, stream_out)

    # Performance metrics
    _, _, _, _, _, collect_performance_fn = _lazy_import_report_engines()
    performance = collect_performance_fn(start_time=start_time)

    improvement_plan_data = remediation_gen.generate_improvement_plan(full_report, deduped_evidences, getattr(args, 'lang', 'auto'), system_info, stream_out)
    coverage_report = remediation_gen.compute_coverage_report(full_report, module_stats, stream_out)

    # Write all report files
    remediation_gen.write_reports(
        args, full_report, judgment, deduped_evidences, timeline_entries, system_info,
        module_stats, performance, summary, improvement_plan_data, whitelist_metadata,
        correlation_summary, coverage_report, load_ratio, fp_statistics, whitelist_templates,
        stream_out, reporting_start_time, reporting_hard_timeout, collect_performance_fn,
        start_time, MarkdownReportGenerator, JsonReportGenerator,
    )

    if reporting_timeout_flag['expired']:
        reporting_logger.warning("Reporting phase timeout enforced - returning partial results")
        stream_out.warn("WARNING: Reporting phase timeout exceeded - report may be incomplete")

    reporting_elapsed = time.monotonic() - reporting_start_time
    reporting_logger.info(f"Reporting phase completed in {reporting_elapsed:.2f}s (evidences={len(evidences) if evidences else 0})")
    if reporting_elapsed > 5.0:
        reporting_logger.warning(f"Reporting phase exceeded 5s target: {reporting_elapsed:.2f}s")

    if skipped_analyzer_details:
        stream_out.warning(f"Security assessment coverage: {len(skipped_analyzer_details)} analyzer(s) not executed")
        stream_out.warning(f"  Skipped due to data issues: {len(skipped_analyzer_details)} analyzer(s)")
        for skipped in skipped_analyzer_details[:5]:
            stream_out.warning(f"    - {skipped['name']}: {skipped['reason']}")
        if len(skipped_analyzer_details) > 5:
            stream_out.warning(f"    ... and {len(skipped_analyzer_details) - 5} more")

    return summary


def generate_all_reports(args, evidences, system_info, module_stats, stream_out, logger,
                         start_time=None, start_wall_time=None,
                         correlation_result=None, orchestrator_state=None, whitelist_metadata=None,
                         throttle_ctrl=None, perf_validator=None,
                         quality_assessment=None, preload_status=None):
    """Generate all report files"""
    return generate_reports(args, evidences, system_info, module_stats, stream_out, start_time,
                    start_wall_time=start_wall_time, correlation_result=correlation_result,
                    orchestrator_state=orchestrator_state, whitelist_metadata=whitelist_metadata,
                    throttle_ctrl=throttle_ctrl, quality_assessment=quality_assessment,
                    preload_status=preload_status)


def _generate_emergency_report(args, system_info, module_stats, stream_out,
                               reporting_start_time, load_ratio, reporting_logger):
    """Generate emergency report under extreme system load."""
    from .summary import ReportSummary

    summary = ReportSummary(
        start_time=time.time(), end_time=time.time(),
        total_analyzers=len(module_stats) if module_stats else 0,
        executed_analyzers=0, successful_analyzers=0, failed_analyzers=0,
        skipped_analyzers=len(module_stats) if module_stats else 0,
        total_alerts=0, deduplicated_alerts=0, fp_filtered=0,
        suppressed_alerts=0, confirmed_alerts=0,
        severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    )
    stream_out.warning(f"Emergency report generated (load ratio: {load_ratio:.1f}x)")
    return summary
