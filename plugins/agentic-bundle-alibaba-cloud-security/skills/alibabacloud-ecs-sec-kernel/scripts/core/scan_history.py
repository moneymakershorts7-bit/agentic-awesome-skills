"""Scan history storage, diffing, and regression detection.

Saves a snapshot after each scan, compares against previous results,
and detects regressions (CVEs that were fixed but re-appeared).
"""
import json
import os
import platform
import time
from datetime import datetime
from typing import Dict, List, Optional, Any


_MAX_SNAPSHOTS = 30


class ScanSnapshot:
    """A single scan result snapshot."""

    def __init__(self, scan_time: str, kernel_version: str,
                 vulnerable: List[str], not_vulnerable: List[str],
                 poc_results: Dict[str, str]):
        self.scan_time = scan_time
        self.kernel_version = kernel_version
        self.vulnerable = vulnerable
        self.not_vulnerable = not_vulnerable
        self.poc_results = poc_results

    def to_dict(self) -> dict:
        return {
            "scan_time": self.scan_time,
            "kernel_version": self.kernel_version,
            "total_cves": len(self.vulnerable) + len(self.not_vulnerable),
            "vulnerable": sorted(self.vulnerable),
            "not_vulnerable": sorted(self.not_vulnerable),
            "poc_results": self.poc_results,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ScanSnapshot':
        return cls(
            scan_time=data.get("scan_time", ""),
            kernel_version=data.get("kernel_version", ""),
            vulnerable=data.get("vulnerable", []),
            not_vulnerable=data.get("not_vulnerable", []),
            poc_results=data.get("poc_results", {}),
        )

    @classmethod
    def from_results(cls, results: List[Any], kernel_version: str = None) -> 'ScanSnapshot':
        """Build snapshot from a list of DetectResult objects."""
        vulnerable = []
        not_vulnerable = []
        poc_results = {}

        for r in results:
            cve_id = r.cve_id
            if r.status == "VULNERABLE":
                vulnerable.append(cve_id)
            else:
                not_vulnerable.append(cve_id)
            if r.poc_result:
                poc_results[cve_id] = r.poc_result.status

        return cls(
            scan_time=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            kernel_version=kernel_version or platform.release(),
            vulnerable=vulnerable,
            not_vulnerable=not_vulnerable,
            poc_results=poc_results,
        )


class DiffResult:
    """Result of comparing two scan snapshots."""

    def __init__(self, new_vulnerabilities: List[str], fixed: List[str],
                 regressions: List[str], poc_changes: Dict[str, Dict[str, str]]):
        self.new_vulnerabilities = new_vulnerabilities
        self.fixed = fixed
        self.regressions = regressions
        self.poc_changes = poc_changes

    @property
    def has_changes(self) -> bool:
        return bool(self.new_vulnerabilities or self.fixed or
                    self.regressions or self.poc_changes)

    def format_report(self) -> str:
        lines = ["CVE Scan Diff Report", "=" * 60]

        if not self.has_changes:
            lines.append("No changes detected since last scan.")
            return "\n".join(lines)

        if self.regressions:
            lines.append("")
            lines.append("[CRITICAL] Regressions ({} CVEs re-appeared):".format(
                len(self.regressions)))
            for cve in sorted(self.regressions):
                lines.append("  ! {} — was fixed, now vulnerable again".format(cve))

        if self.new_vulnerabilities:
            lines.append("")
            lines.append("[NEW] Newly vulnerable ({} CVEs):".format(
                len(self.new_vulnerabilities)))
            for cve in sorted(self.new_vulnerabilities):
                lines.append("  + {}".format(cve))

        if self.fixed:
            lines.append("")
            lines.append("[FIXED] Resolved ({} CVEs):".format(len(self.fixed)))
            for cve in sorted(self.fixed):
                lines.append("  - {}".format(cve))

        if self.poc_changes:
            lines.append("")
            lines.append("[POC] PoC status changes:")
            for cve, change in sorted(self.poc_changes.items()):
                lines.append("  ~ {} : {} -> {}".format(
                    cve, change["old"], change["new"]))

        lines.append("")
        lines.append("-" * 60)
        lines.append("Summary: {} new, {} fixed, {} regressions".format(
            len(self.new_vulnerabilities), len(self.fixed), len(self.regressions)))

        return "\n".join(lines)


class ScanHistoryStore:
    """Manages scan history snapshots on disk."""

    def __init__(self, workspace_dir: str):
        self._history_dir = os.path.join(workspace_dir, "scan-history")
        os.makedirs(self._history_dir, exist_ok=True)

    def save(self, snapshot: ScanSnapshot) -> str:
        """Save a snapshot and update the latest symlink."""
        filename = "{}.json".format(snapshot.scan_time.replace(":", "-"))
        filepath = os.path.join(self._history_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(snapshot.to_dict(), f, indent=2, ensure_ascii=False)

        # Update latest symlink
        latest_link = os.path.join(self._history_dir, "latest.json")
        try:
            if os.path.islink(latest_link) or os.path.exists(latest_link):
                os.remove(latest_link)
            os.symlink(filename, latest_link)
        except OSError:
            pass

        self._cleanup()
        return filepath

    def load_latest(self) -> Optional[ScanSnapshot]:
        """Load the most recent snapshot."""
        latest_link = os.path.join(self._history_dir, "latest.json")
        if os.path.exists(latest_link):
            return self._load_file(latest_link)

        snapshots = self._list_snapshots()
        if snapshots:
            return self._load_file(snapshots[-1])
        return None

    def load_file(self, path: str) -> Optional[ScanSnapshot]:
        """Load a specific snapshot file."""
        return self._load_file(path)

    def list_snapshots(self) -> List[str]:
        """List all snapshot file paths, sorted oldest first."""
        return self._list_snapshots()

    def diff(self, current: ScanSnapshot, baseline: ScanSnapshot) -> DiffResult:
        """Compare two snapshots and detect changes."""
        current_vuln = set(current.vulnerable)
        baseline_vuln = set(baseline.vulnerable)
        baseline_not_vuln = set(baseline.not_vulnerable)

        new_vulnerabilities = sorted(current_vuln - baseline_vuln)
        fixed = sorted(baseline_vuln - current_vuln)

        # Regression: was not_vulnerable in baseline, now vulnerable
        # (simple regression — was explicitly safe, now exposed)
        regressions = sorted(current_vuln & baseline_not_vuln)

        # PoC status changes
        poc_changes = {}
        for cve in current_vuln | baseline_vuln:
            old_poc = baseline.poc_results.get(cve, "NO_POC")
            new_poc = current.poc_results.get(cve, "NO_POC")
            if old_poc != new_poc:
                poc_changes[cve] = {"old": old_poc, "new": new_poc}

        return DiffResult(
            new_vulnerabilities=new_vulnerabilities,
            fixed=fixed,
            regressions=regressions,
            poc_changes=poc_changes,
        )

    def detect_regressions(self, current: ScanSnapshot) -> List[str]:
        """Detect regressions by checking full history.

        A regression is a CVE that appeared in not_vulnerable at some point
        in history, then shows up as vulnerable in the current scan.
        """
        ever_fixed = set()
        for path in self._list_snapshots():
            snap = self._load_file(path)
            if snap:
                ever_fixed.update(snap.not_vulnerable)

        current_vuln = set(current.vulnerable)
        return sorted(current_vuln & ever_fixed)

    def _load_file(self, path: str) -> Optional[ScanSnapshot]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return ScanSnapshot.from_dict(data)
        except (json.JSONDecodeError, OSError, KeyError):
            return None

    def _list_snapshots(self) -> List[str]:
        if not os.path.isdir(self._history_dir):
            return []
        files = []
        for name in sorted(os.listdir(self._history_dir)):
            if name.endswith(".json") and name != "latest.json":
                files.append(os.path.join(self._history_dir, name))
        return files

    def _cleanup(self):
        """Remove oldest snapshots beyond the retention limit."""
        snapshots = self._list_snapshots()
        while len(snapshots) > _MAX_SNAPSHOTS:
            oldest = snapshots.pop(0)
            try:
                os.remove(oldest)
            except OSError:
                break
