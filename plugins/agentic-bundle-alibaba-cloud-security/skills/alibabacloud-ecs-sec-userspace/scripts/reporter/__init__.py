"""Reporter module for sec-userspace."""
from .severity import Severity
from .evidence import Evidence

# Lazy-load ReportSummary and ImprovementPlanData to avoid importing report.py (56.9KB) at module level
def _lazy_import_report_summary():
    """Lazy-load ReportSummary and ImprovementPlanData."""
    from .report import ReportSummary, ImprovementPlanData
    return ReportSummary, ImprovementPlanData

# Lazy-load heavy report modules to avoid import overhead in quick mode
def _lazy_import_report_engines():
    """Lazy-load report generation engines (only needed during report phase)."""
    from .report import (
        JudgmentEngine,
        MarkdownReportGenerator,
        JsonReportGenerator,
        aggregate_evidences,
        sanitize_evidence,
        collect_performance,
    )
    return JudgmentEngine, MarkdownReportGenerator, JsonReportGenerator, aggregate_evidences, sanitize_evidence, collect_performance


def _lazy_import_chinese_report():
    """Lazy-load Chinese report generator."""
    from .chinese_report import ChineseReportGenerator, generate_bilingual_reports
    return ChineseReportGenerator, generate_bilingual_reports


def _lazy_import_deduplicator():
    """Lazy-load evidence deduplicator (unified version)."""
    from ..utils.deduplicator import EvidenceDeduplicator, deduplicate_evidences
    return EvidenceDeduplicator, deduplicate_evidences



def _get_compute_detection_coverage():
    from .coverage import compute_detection_coverage
    return compute_detection_coverage

def _get_DetectionCoverageCalculator():
    from .coverage import DetectionCoverageCalculator
    return DetectionCoverageCalculator

def _get_CoverageMetrics():
    from .coverage import CoverageMetrics
    return CoverageMetrics

def _get_SECURITY_CATEGORIES():
    from .coverage import SECURITY_CATEGORIES
    return SECURITY_CATEGORIES

def _get_ATTACK_TACTIC_MAP():
    from .coverage import ATTACK_TACTIC_MAP
    return ATTACK_TACTIC_MAP

def _lazy_import_detection_coverage():
    """Lazy-load detection_coverage report modules."""
    from .detection_coverage import (
        build_coverage_report,
        DetectionCoverageReport,
        coverage_to_dict,
        coverage_to_markdown,
        SECURITY_CATEGORIES as DETECTION_SECURITY_CATEGORIES,
    )
    return build_coverage_report, DetectionCoverageReport, coverage_to_dict, coverage_to_markdown, DETECTION_SECURITY_CATEGORIES

__all__ = [
    'Severity',
    'Evidence',
    '_lazy_import_report_summary',
    '_lazy_import_report_engines',
    '_lazy_import_chinese_report',
    '_lazy_import_deduplicator',
    '_get_compute_detection_coverage',
    '_get_DetectionCoverageCalculator',
    '_get_CoverageMetrics',
    '_get_SECURITY_CATEGORIES',
    '_get_ATTACK_TACTIC_MAP',
    '_lazy_import_detection_coverage',
]
