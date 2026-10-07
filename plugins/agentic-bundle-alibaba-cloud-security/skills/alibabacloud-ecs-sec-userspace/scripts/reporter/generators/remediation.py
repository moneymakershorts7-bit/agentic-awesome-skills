"""RemediationGenerator: Improvement plan and remediation recommendations for sec-userspace reports."""
import logging
import os
import time
from datetime import date
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def write_markdown_report(
    md_gen, judgment, deduped_evidences, timeline_entries, system_info, module_stats,
    performance, summary, improvement_plan_data, whitelist_metadata, correlation_summary,
    coverage_report, full_report, load_ratio, report_dir, date_str, stream_out,
    reporting_start_time, reporting_hard_timeout,
) -> bool:
    """Write markdown report (and optionally Chinese report). Returns True if written."""
    reporting_elapsed = time.monotonic() - reporting_start_time
    if reporting_elapsed > reporting_hard_timeout:
        stream_out.warning(f"Report generation skipped (reporting timeout {reporting_elapsed:.1f}s > {reporting_hard_timeout:.1f}s)")
        return False

    from ...core.orchestrator import _detect_locale
    lang_mode = _detect_locale()

    if full_report:
        report_content = md_gen.generate(
            judgment, deduped_evidences, timeline_entries, system_info, module_stats, performance,
            summary=summary, improvement_plan=improvement_plan_data,
            whitelist_metadata=whitelist_metadata,
            correlation_summary=correlation_summary,
            coverage_report=coverage_report,
        )
        stream_out.info("Full report generated (with timeline, attack chain, coverage)")
    else:
        report_content = md_gen.generate_minimal_report(
            judgment, deduped_evidences, system_info, module_stats, performance, summary,
            load_ratio=load_ratio
        )
        stream_out.info("Minimal report generated (core findings only)")

    report_path = os.path.join(report_dir, f"sec-report-{date_str}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    stream_out.info(f"Markdown report output to {report_path}")

    if lang_mode in ('zh', 'both'):
        try:
            from ..chinese_report import ChineseReportGenerator
            cn_gen = ChineseReportGenerator()
            if full_report:
                cn_report_content = cn_gen.generate(
                    judgment, deduped_evidences, timeline_entries, system_info, module_stats, performance,
                    summary=summary, improvement_plan=improvement_plan_data,
                    whitelist_metadata=whitelist_metadata,
                    correlation_summary=correlation_summary,
                    coverage_report=coverage_report,
                )
            else:
                cn_report_content = cn_gen.generate_minimal_report(
                    judgment, deduped_evidences, system_info, module_stats, performance, summary,
                    load_ratio=load_ratio
                )
            cn_suffix = "-cn" if lang_mode == 'zh' else ""
            cn_report_path = os.path.join(report_dir, f"sec-report{cn_suffix}-{date_str}-cn.md")
            with open(cn_report_path, "w", encoding="utf-8") as f:
                f.write(cn_report_content)
            stream_out.info(f"Chinese report output to {cn_report_path}")
        except (ImportError, OSError, ValueError, KeyError) as e:
            stream_out.info(f"Chinese report generation skipped (error: {e})")
    else:
        stream_out.info("Chinese report generation skipped (use --lang zh or --lang both)")

    return True


def write_json_report(
    JsonReportGenerator_cls, judgment, deduped_evidences, system_info, module_stats,
    performance, fp_statistics, whitelist_templates, summary, improvement_plan_data,
    whitelist_metadata, correlation_summary, coverage_report, load_ratio,
    report_dir, stream_out,
) -> bool:
    """Write JSON report. Returns True if written."""
    try:
        json_gen = JsonReportGenerator_cls()
        json_content = json_gen.generate(judgment, deduped_evidences, system_info, module_stats, performance,
                                         fp_statistics=fp_statistics, whitelist_templates=whitelist_templates,
                                         summary=summary, improvement_plan=improvement_plan_data,
                                         whitelist_metadata=whitelist_metadata,
                                         correlation_summary=correlation_summary,
                                         coverage_report=coverage_report,
                                         load_ratio=load_ratio)
        json_path = json_gen.save(json_content, report_dir)
        stream_out.info(f"JSON report output to {json_path}")
        return True
    except (ImportError, OSError, ValueError, TypeError) as e:
        stream_out.info(f"JSON report generation skipped (error: {e})")
        return False


def write_all_reports(
    args, full_report, judgment, deduped_evidences, timeline_entries, system_info,
    module_stats, performance, summary, improvement_plan_data, whitelist_metadata,
    correlation_summary, coverage_report, load_ratio, fp_statistics, whitelist_templates,
    stream_out, reporting_start_time, reporting_hard_timeout, collect_performance_fn,
    start_time, MarkdownReportGenerator_cls, JsonReportGenerator_cls,
):
    """Write all report files (markdown, Chinese, JSON) based on args.format."""
    report_dir = os.path.join(getattr(args, "workspace_dir", args.output_dir), "report")
    os.makedirs(report_dir, exist_ok=True)
    date_str = date.today().isoformat()

    generate_json = args.format in ("json", "both") or full_report

    if args.format in ("markdown", "both"):
        md_gen = MarkdownReportGenerator_cls()
        write_markdown_report(
            md_gen=md_gen, judgment=judgment, deduped_evidences=deduped_evidences,
            timeline_entries=timeline_entries, system_info=system_info,
            module_stats=module_stats, performance=performance, summary=summary,
            improvement_plan_data=improvement_plan_data, whitelist_metadata=whitelist_metadata,
            correlation_summary=correlation_summary, coverage_report=coverage_report,
            full_report=full_report, load_ratio=load_ratio, report_dir=report_dir,
            date_str=date_str, stream_out=stream_out,
            reporting_start_time=reporting_start_time, reporting_hard_timeout=reporting_hard_timeout,
        )

    if generate_json:
        write_json_report(
            JsonReportGenerator_cls=JsonReportGenerator_cls, judgment=judgment,
            deduped_evidences=deduped_evidences, system_info=system_info,
            module_stats=module_stats, performance=performance, fp_statistics=fp_statistics,
            whitelist_templates=whitelist_templates, summary=summary,
            improvement_plan_data=improvement_plan_data, whitelist_metadata=whitelist_metadata,
            correlation_summary=correlation_summary, coverage_report=coverage_report,
            load_ratio=load_ratio, report_dir=report_dir, stream_out=stream_out,
        )

    stream_out.info(f"Reports output to {report_dir}/")
    stream_out.info("Timestamp validation skipped")

    return report_dir


def generate_improvement_plan(
    full_report: bool,
    deduped_evidences: List,
    args_lang_mode: str,
    system_info: Dict[str, Any],
    stream_out,
) -> Optional[Any]:
    """Generate improvement plan data for full report mode.

    Returns ImprovementPlanData instance or None if not generated.
    """
    if not full_report:
        stream_out.info("Improvement plan generation skipped")
        return None

    improvement_plan_data = None
    try:
        from ..improvement_generator import ImprovementGenerator
        from .. import _lazy_import_report_summary
        ReportSummary_cls, ImprovementPlanData_cls = _lazy_import_report_summary()

        imp_gen = ImprovementGenerator()
        imp_plan = imp_gen.generate(deduped_evidences, "full", system_info)
        improvement_plan_data = ImprovementPlanData_cls(
            enabled=True,
            reporting_status="enabled",
            suggestions_count=len(imp_plan.suggestions),
            suggestions=[s.to_dict() for s in imp_plan.suggestions],
        )
        if improvement_plan_data.suggestions:
            stream_out.info(f"Improvement plan: {len(improvement_plan_data.suggestions)} suggestions generated")
    except (ImportError, OSError, ValueError, KeyError) as e:
        stream_out.info(f"Improvement plan generation skipped (error: {e})")

    return improvement_plan_data


def compute_coverage_report(
    full_report: bool,
    module_stats: List[Dict[str, Any]],
    stream_out,
) -> Optional[Any]:
    """Compute detection coverage report for full report mode.

    Returns coverage report data or None.
    """
    if not full_report:
        stream_out.info("Coverage report computation skipped")
        return None

    coverage_report = None
    try:
        from .. import _get_compute_detection_coverage
        coverage_compute = _get_compute_detection_coverage()
        coverage_report = coverage_compute(module_stats)
        stream_out.info("Detection coverage report computed")
    except (ImportError, OSError, ValueError, KeyError) as e:
        stream_out.info(f"Coverage report computation skipped (error: {e})")

    return coverage_report


def build_timeline_entries(
    full_report: bool,
    deduped_evidences: List,
    module_stats: List[Dict[str, Any]],
    stream_out,
) -> List[Dict[str, Any]]:
    """Build timeline entries for full report mode.

    Returns list of timeline entry dicts.
    """
    timeline_entries = []
    if full_report:
        try:
            from ..timeline import build_timeline
            timeline_data = build_timeline(deduped_evidences, module_stats)
            timeline_entries = timeline_data.get("entries", [])
            if timeline_entries:
                stream_out.info(f"Timeline built: {len(timeline_entries)} events")
        except (ImportError, OSError, ValueError, KeyError) as e:
            stream_out.info(f"Timeline building skipped (error: {e})")
    else:
        stream_out.info("Timeline building skipped")

    return timeline_entries


def run_attack_chain_analysis(
    deduped_evidences: List,
    stream_out,
) -> None:
    """Run attack chain analysis if evidences exist."""
    if not deduped_evidences:
        return

    try:
        from ..attack_chain import analyze_attack_chains
        analyze_attack_chains(deduped_evidences)
    except (ImportError, OSError, ValueError, KeyError) as e:
        stream_out.info(f"Attack chain analysis skipped (error: {e})")


class RemediationGenerator:
    """Generate remediation recommendations and improvement plans."""

    def generate_improvement_plan(
        self,
        full_report: bool,
        deduped_evidences: List,
        args_lang_mode: str,
        system_info: Dict[str, Any],
        stream_out,
    ) -> Optional[Any]:
        """Generate improvement plan data for full report mode."""
        return generate_improvement_plan(
            full_report=full_report,
            deduped_evidences=deduped_evidences,
            args_lang_mode=args_lang_mode,
            system_info=system_info,
            stream_out=stream_out,
        )

    def compute_coverage_report(
        self,
        full_report: bool,
        module_stats: List[Dict[str, Any]],
        stream_out,
    ) -> Optional[Any]:
        """Compute detection coverage report for full report mode."""
        return compute_coverage_report(
            full_report=full_report,
            module_stats=module_stats,
            stream_out=stream_out,
        )

    def build_timeline(
        self,
        full_report: bool,
        deduped_evidences: List,
        module_stats: List[Dict[str, Any]],
        stream_out,
    ) -> List[Dict[str, Any]]:
        """Build timeline entries for full report mode."""
        return build_timeline_entries(
            full_report=full_report,
            deduped_evidences=deduped_evidences,
            module_stats=module_stats,
            stream_out=stream_out,
        )

    def analyze_attack_chains(
        self,
        deduped_evidences: List,
        stream_out,
    ) -> None:
        """Run attack chain analysis if evidences exist."""
        return run_attack_chain_analysis(
            deduped_evidences=deduped_evidences,
            stream_out=stream_out,
        )

    def write_reports(
        self,
        args, full_report, judgment, deduped_evidences, timeline_entries, system_info,
        module_stats, performance, summary, improvement_plan_data, whitelist_metadata,
        correlation_summary, coverage_report, load_ratio, fp_statistics, whitelist_templates,
        stream_out, reporting_start_time, reporting_hard_timeout, collect_performance_fn,
        start_time, MarkdownReportGenerator_cls, JsonReportGenerator_cls,
    ):
        """Write all report files based on args.format."""
        return write_all_reports(
            args=args, full_report=full_report, judgment=judgment,
            deduped_evidences=deduped_evidences, timeline_entries=timeline_entries,
            system_info=system_info, module_stats=module_stats, performance=performance,
            summary=summary, improvement_plan_data=improvement_plan_data,
            whitelist_metadata=whitelist_metadata, correlation_summary=correlation_summary,
            coverage_report=coverage_report, load_ratio=load_ratio,
            fp_statistics=fp_statistics, whitelist_templates=whitelist_templates,
            stream_out=stream_out, reporting_start_time=reporting_start_time,
            reporting_hard_timeout=reporting_hard_timeout,
            collect_performance_fn=collect_performance_fn, start_time=start_time,
            MarkdownReportGenerator_cls=MarkdownReportGenerator_cls,
            JsonReportGenerator_cls=JsonReportGenerator_cls,
        )
