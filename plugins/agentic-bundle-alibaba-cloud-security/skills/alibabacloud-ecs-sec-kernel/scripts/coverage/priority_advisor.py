"""
Priority Advisor — ranks uncovered CVEs by development priority.

Weighted scoring:
  - CVSS score: 30%
  - Exploitability: 30% (HIGH=1.0, MEDIUM=0.6, LOW=0.3)
  - Impact range: 20% (number of version ranges affected)
  - Type match: 20% (LPE=1.0 matches project focus, others lower)
"""
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

EXPLOITABILITY_SCORE = {
    "HIGH": 1.0,
    "MEDIUM": 0.6,
    "LOW": 0.3,
}

TYPE_SCORE = {
    "LPE": 1.0,
    "RCE": 0.8,
    "DoS": 0.3,
    "InfoLeak": 0.5,
}

WEIGHT_CVSS = 0.30
WEIGHT_EXPLOITABILITY = 0.30
WEIGHT_IMPACT_RANGE = 0.20
WEIGHT_TYPE_MATCH = 0.20


class PriorityAdvisor:
    """Ranks uncovered CVEs by development priority."""

    def __init__(self, project_root: Optional[Path] = None):
        from .cve_map import _resolve_project_root
        self._root = project_root or _resolve_project_root()

    def rank_uncovered(self, kernel_version: str, top_n: int = 10) -> List[Dict]:
        """Rank uncovered CVEs by priority score.

        Returns list of dicts sorted by score descending:
          - cve_id, score, cvss, type, exploitability, impact_ranges
        """
        from .cve_map import CoverageMap

        coverage = CoverageMap(self._root)
        result = coverage.compute_coverage(kernel_version)
        uncovered = result['uncovered']

        if not uncovered:
            return []

        db = coverage._load_cve_database()
        metadata = db.get('cve_metadata', {})
        version_ranges = db.get('version_ranges', {})

        # Precompute impact range count per CVE
        cve_range_count = {}
        for cve_list in version_ranges.values():
            for cve_id in cve_list:
                cve_range_count[cve_id] = cve_range_count.get(cve_id, 0) + 1

        max_range_count = max(cve_range_count.values()) if cve_range_count else 1

        scored = []
        for cve_id in uncovered:
            meta = metadata.get(cve_id, {})
            cvss = meta.get('cvss', 5.0)
            exploit_str = meta.get('exploitability', 'LOW')
            cve_type = meta.get('type', 'DoS')

            cvss_norm = cvss / 10.0
            exploit_norm = EXPLOITABILITY_SCORE.get(exploit_str, 0.3)
            range_count = cve_range_count.get(cve_id, 1)
            impact_norm = range_count / max_range_count
            type_norm = TYPE_SCORE.get(cve_type, 0.3)

            score = (
                WEIGHT_CVSS * cvss_norm +
                WEIGHT_EXPLOITABILITY * exploit_norm +
                WEIGHT_IMPACT_RANGE * impact_norm +
                WEIGHT_TYPE_MATCH * type_norm
            )

            scored.append({
                "cve_id": cve_id,
                "score": round(score, 3),
                "cvss": cvss,
                "type": cve_type,
                "exploitability": exploit_str,
                "impact_ranges": range_count,
            })

        scored.sort(key=lambda x: x['score'], reverse=True)
        return scored[:top_n]

    def format_report(self, kernel_version: str, top_n: int = 10) -> str:
        """Human-readable priority report."""
        from .cve_map import CoverageMap

        coverage = CoverageMap(self._root)
        result = coverage.compute_coverage(kernel_version)
        ranked = self.rank_uncovered(kernel_version, top_n)

        lines = [
            f"=== CVE Development Priority ===",
            f"Kernel: {result['kernel_version']} | "
            f"Covered: {result['total_covered']}/{result['total_known']} "
            f"({result['coverage_pct']}%)",
            "",
        ]

        if not ranked:
            lines.append("All known CVEs are covered!")
            return "\n".join(lines)

        for i, entry in enumerate(ranked, 1):
            lines.append(
                f"#{i} {entry['cve_id']} [CVSS {entry['cvss']}] "
                f"{entry['type']} - exploit: {entry['exploitability']}, "
                f"ranges: {entry['impact_ranges']} (score: {entry['score']})"
            )

        return "\n".join(lines)
