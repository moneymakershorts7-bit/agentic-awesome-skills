"""
CVE Coverage Map — computes coverage percentage for a given kernel version.

Compares implemented detectors (from kernel_cves.yaml) against known CVEs
for the target kernel version (from kernel_cve_database.json).
"""
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _resolve_project_root() -> Path:
    abs_file = Path(__file__).resolve()
    if '.pyz' in str(abs_file):
        pyz_path = str(abs_file).split('.pyz')[0] + '.pyz'
        return Path(pyz_path).parent.parent
    return abs_file.parent.parent.parent


def _parse_version(version_str: str) -> Tuple[int, ...]:
    match = re.match(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(int(x) for x in match.groups())
    match = re.match(r'(\d+)\.(\d+)', version_str)
    if match:
        return (int(match.group(1)), int(match.group(2)), 0)
    return (0, 0, 0)


def _version_in_range(version: Tuple[int, ...], range_min: Tuple[int, ...],
                      range_max: Tuple[int, ...]) -> bool:
    return range_min <= version <= range_max


class CoverageMap:
    """Computes CVE detection coverage for a given kernel version."""

    def __init__(self, project_root: Optional[Path] = None):
        self._root = project_root or _resolve_project_root()
        self._cve_db: Optional[Dict] = None
        self._implemented_cves: Optional[List[str]] = None

    def _load_cve_database(self) -> Dict:
        if self._cve_db is not None:
            return self._cve_db
        db_path = self._root / 'configs' / 'kernel_cve_database.json'
        if not db_path.exists():
            logger.warning(f"CVE database not found: {db_path}")
            self._cve_db = {"version_ranges": {}, "cve_metadata": {}}
            return self._cve_db
        with open(db_path, 'r', encoding='utf-8') as f:
            self._cve_db = json.load(f)
        return self._cve_db

    def _load_implemented_cves(self) -> List[str]:
        if self._implemented_cves is not None:
            return self._implemented_cves

        try:
            import yaml
        except ImportError:
            from ..thirdparties import yaml

        yaml_path = self._root / 'configs' / 'kernel_cves.yaml'
        if not yaml_path.exists():
            logger.warning(f"kernel_cves.yaml not found: {yaml_path}")
            self._implemented_cves = []
            return self._implemented_cves

        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}

        self._implemented_cves = [
            entry['cve_id']
            for entry in data.get('cves', [])
            if entry.get('enabled', True)
        ]
        return self._implemented_cves

    def get_known_cves_for_version(self, kernel_version: str) -> List[str]:
        """Return all known CVEs that affect the given kernel version."""
        db = self._load_cve_database()
        version_tuple = _parse_version(kernel_version)
        affected_cves = set()

        for range_key, cve_list in db.get('version_ranges', {}).items():
            parts = range_key.split('-', 1)
            if len(parts) != 2:
                continue
            range_min = _parse_version(parts[0])
            range_max = _parse_version(parts[1])
            if _version_in_range(version_tuple, range_min, range_max):
                affected_cves.update(cve_list)

        return sorted(affected_cves)

    def compute_coverage(self, kernel_version: str) -> Dict:
        """Compute coverage stats for a kernel version.

        Returns dict with:
          - kernel_version: str
          - total_known: int (CVEs known to affect this version)
          - total_covered: int (CVEs with implemented detectors)
          - coverage_pct: float
          - covered: list of CVE IDs
          - uncovered: list of CVE IDs (blind spots)
        """
        known = self.get_known_cves_for_version(kernel_version)
        implemented = set(self._load_implemented_cves())
        covered = sorted(set(known) & implemented)
        uncovered = sorted(set(known) - implemented)
        total = len(known)
        pct = (len(covered) / total * 100) if total > 0 else 0.0

        return {
            "kernel_version": kernel_version,
            "total_known": total,
            "total_covered": len(covered),
            "coverage_pct": round(pct, 1),
            "covered": covered,
            "uncovered": uncovered,
        }

    def get_cve_metadata(self, cve_id: str) -> Dict:
        """Get metadata for a specific CVE from the database."""
        db = self._load_cve_database()
        return db.get('cve_metadata', {}).get(cve_id, {})

    def format_report(self, kernel_version: str) -> str:
        """Generate human-readable coverage report."""
        result = self.compute_coverage(kernel_version)
        lines = [
            f"=== CVE Coverage Report ===",
            f"Kernel: {result['kernel_version']}",
            f"Coverage: {result['total_covered']}/{result['total_known']} "
            f"({result['coverage_pct']}%)",
            "",
        ]

        if result['uncovered']:
            lines.append(f"Blind spots ({len(result['uncovered'])} uncovered CVEs):")
            db = self._load_cve_database()
            metadata = db.get('cve_metadata', {})
            for cve_id in result['uncovered']:
                meta = metadata.get(cve_id, {})
                cvss = meta.get('cvss', '?')
                cve_type = meta.get('type', '?')
                exploit = meta.get('exploitability', '?')
                lines.append(f"  {cve_id} [CVSS {cvss}] {cve_type} - exploitability: {exploit}")
        else:
            lines.append("Full coverage — no blind spots!")

        return "\n".join(lines)
