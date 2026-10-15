"""JsonReportGenerator: JSON report generation for sec-userspace."""
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class JsonReportGenerator:
    """JSON report generator"""

    def generate(self, judgment: dict, evidences: List, system_info: dict,
                 module_stats: List[dict], performance: dict,
                 fp_statistics: dict = None, whitelist_templates: list = None,
                 summary: 'ReportSummary' = None,
                 improvement_plan: Optional['ImprovementPlanData'] = None,
                 whitelist_metadata: Dict[str, Any] = None,
                 correlation_summary: Optional[Dict[str, Any]] = None,
                 coverage_report: Optional['DetectionCoverageReport'] = None,
                 load_ratio: float = None) -> str:
        # P2-2026-04-13: Accept load_ratio parameter to avoid redundant os.getloadavg() call
        if load_ratio is None:
            import os as _os
            try:
                load_1min = _os.getloadavg()[0]
                cpu_count = _os.cpu_count() or 1
                load_ratio = load_1min / cpu_count
            except OSError:
                load_ratio = 1.0

        if not evidences:
            agg_groups = []
        # Only aggregate under moderate load (<10x) and reasonable evidence count
        elif load_ratio < 10.0 and len(evidences) <= 100:
            from ..aggregation import aggregate_evidences
            agg_groups = aggregate_evidences(evidences)
        else:
            # Extreme load or too many evidences: skip aggregation
            agg_groups = []

        # Compute verified_status distribution
        status_counts = {"pending": 0, "likely_fp": 0, "confirmed_tp": 0, "whitelisted": 0}
        for e in evidences:
            status = e.verified_status or "pending"
            if status in status_counts:
                status_counts[status] += 1

        # Import SafeJsonEncoder from sibling module
        from .markdown_generator import SafeJsonEncoder

        data = {
            "version": "2.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "system": {
                "hostname": system_info.get("hostname", ""),
                "os_release": system_info.get("os_release", ""),
                "kernel_version": system_info.get("kernel_version", ""),
                "cpu_count": system_info.get("cpu_count", 0),
                "memory_total_mb": system_info.get("memory_total_mb", 0),
            },
            "conclusion": {
                "level": judgment["conclusion"],
                "description": judgment.get("conclusion_description", ""),
                "result_code": judgment["result_code"],
                "confirmed_intrusions": judgment.get("confirmed_intrusions", 0),
                "security_issues": judgment.get("security_issues", 0),
                "recommendations": judgment.get("recommendations", 0),
            },
            "total_score": judgment["total_score"],
            "severity_counts": judgment["severity_counts"],
            "total_evidence_count": judgment.get("evidence_count", len(evidences)),
            "aggregated_alert_count": len(agg_groups),
            "verified_status_counts": status_counts,
            "aggregated_alerts": [g.to_dict() for g in agg_groups],
            "modules": module_stats,
            "performance": performance,
        }

        # Add summary if available
        if summary:
            data["summary"] = summary.to_dict()

        # Add FP statistics dashboard
        if fp_statistics:
            data["fp_statistics"] = fp_statistics

        # Add whitelist templates for one-click whitelist generation
        if whitelist_templates:
            data["whitelist_suggestions"] = whitelist_templates

        # Add improvement plan
        if improvement_plan:
            data["improvement_plan"] = improvement_plan.to_dict()

        # Add whitelist metadata from EBPFAnalyzer
        if whitelist_metadata:
            data["whitelist_metadata"] = whitelist_metadata

        # Add cross-analyzer correlation summary
        if correlation_summary:
            data["correlation_summary"] = correlation_summary

        # Add detection coverage analysis
        if coverage_report and hasattr(coverage_report, 'scan_mode'):
            from ..detection_coverage import coverage_to_dict
            data["detection_coverage"] = coverage_to_dict(coverage_report)

        return json.dumps(data, indent=2, ensure_ascii=False, cls=SafeJsonEncoder)

    def save(self, content: str, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        filepath = os.path.join(output_dir, f"sec-report-{date_str}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath
