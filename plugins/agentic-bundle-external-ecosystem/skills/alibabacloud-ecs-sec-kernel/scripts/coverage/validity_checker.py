"""
Detector Validity Checker — determines which detectors apply to the current kernel.

For each detector in kernel_cves.yaml:
- APPLICABLE: kernel version is in affected range → detector should run
- SKIPPED: kernel version is NOT in affected range → waste of time
- GAP: CVE affects this kernel but no detector exists yet
"""
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _parse_version(version_str: str) -> Tuple[int, ...]:
    match = re.match(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(int(x) for x in match.groups())
    return (0, 0, 0)


class ValidityResult:
    """Result of validity check for one CVE."""

    __slots__ = ('cve_id', 'status', 'reason')

    def __init__(self, cve_id: str, status: str, reason: str = ""):
        self.cve_id = cve_id
        self.status = status  # APPLICABLE, SKIPPED, GAP, UNKNOWN
        self.reason = reason

    def __repr__(self):
        return f"<ValidityResult {self.cve_id} {self.status}>"


class ValidityChecker:
    """Checks which detectors are valid for the current kernel version."""

    def __init__(self, project_root: Optional[Path] = None):
        from .cve_map import _resolve_project_root
        self._root = project_root or _resolve_project_root()

    def check_all(self, kernel_version: str) -> List[ValidityResult]:
        """Check validity of all detectors against the given kernel version.

        Returns a list of ValidityResult, one per CVE in kernel_cves.yaml.
        Also includes GAP entries for CVEs that affect this kernel but have
        no detector implemented.
        """
        from .cve_map import CoverageMap

        coverage = CoverageMap(self._root)
        implemented_cves = coverage._load_implemented_cves()
        known_cves = set(coverage.get_known_cves_for_version(kernel_version))

        results = []
        version_tuple = _parse_version(kernel_version)

        for cve_id in implemented_cves:
            if cve_id in known_cves:
                results.append(ValidityResult(
                    cve_id=cve_id,
                    status="APPLICABLE",
                    reason=f"Affects kernel {kernel_version}"
                ))
            else:
                results.append(ValidityResult(
                    cve_id=cve_id,
                    status="SKIPPED",
                    reason=f"Does not affect kernel {kernel_version}"
                ))

        # Find GAPs: CVEs in known set but not implemented
        implemented_set = set(implemented_cves)
        for cve_id in sorted(known_cves - implemented_set):
            results.append(ValidityResult(
                cve_id=cve_id,
                status="GAP",
                reason="Affects this kernel but no detector implemented"
            ))

        return results

    def get_applicable(self, kernel_version: str) -> List[str]:
        """Return CVE IDs of detectors that apply to this kernel."""
        return [r.cve_id for r in self.check_all(kernel_version)
                if r.status == "APPLICABLE"]

    def get_skipped(self, kernel_version: str) -> List[str]:
        """Return CVE IDs of detectors that don't apply to this kernel."""
        return [r.cve_id for r in self.check_all(kernel_version)
                if r.status == "SKIPPED"]

    def get_gaps(self, kernel_version: str) -> List[str]:
        """Return CVE IDs that affect this kernel but have no detector."""
        return [r.cve_id for r in self.check_all(kernel_version)
                if r.status == "GAP"]

    def format_report(self, kernel_version: str) -> str:
        """Human-readable validity report."""
        results = self.check_all(kernel_version)
        applicable = [r for r in results if r.status == "APPLICABLE"]
        skipped = [r for r in results if r.status == "SKIPPED"]
        gaps = [r for r in results if r.status == "GAP"]

        lines = [
            f"=== Detector Validity Report ===",
            f"Kernel: {kernel_version}",
            f"Applicable: {len(applicable)} | Skipped: {len(skipped)} | Gaps: {len(gaps)}",
            "",
        ]

        if applicable:
            lines.append("APPLICABLE (will run):")
            for r in applicable:
                lines.append(f"  {r.cve_id}")

        if skipped:
            lines.append(f"\nSKIPPED (not applicable to this kernel): {len(skipped)} detectors")

        if gaps:
            lines.append(f"\nGAPS (no detector yet):")
            for r in gaps:
                lines.append(f"  {r.cve_id} — {r.reason}")

        return "\n".join(lines)
