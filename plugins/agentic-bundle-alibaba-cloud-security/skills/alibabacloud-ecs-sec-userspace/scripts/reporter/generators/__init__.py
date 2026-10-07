"""Report generators for sec-userspace.

This package contains all report generation classes.
"""
from .markdown_generator import MarkdownReportGenerator, SafeJsonEncoder
from .json_generator import JsonReportGenerator
from .summary_generator import (
    SummaryGenerator,
    compute_module_stats,
    build_skipped_analyzer_details,
    compute_extended_stats,
    get_memory_usage,
    extract_quality_assessment,
    build_report_summary,
)
from .remediation import (
    RemediationGenerator,
    generate_improvement_plan,
    compute_coverage_report,
    build_timeline_entries,
    run_attack_chain_analysis,
    write_all_reports,
    write_markdown_report,
    write_json_report,
)

__all__ = [
    'MarkdownReportGenerator',
    'JsonReportGenerator',
    'SafeJsonEncoder',
    'SummaryGenerator',
    'compute_module_stats',
    'build_skipped_analyzer_details',
    'compute_extended_stats',
    'get_memory_usage',
    'extract_quality_assessment',
    'build_report_summary',
    'RemediationGenerator',
    'generate_improvement_plan',
    'compute_coverage_report',
    'build_timeline_entries',
    'run_attack_chain_analysis',
    'write_all_reports',
    'write_markdown_report',
    'write_json_report',
]
