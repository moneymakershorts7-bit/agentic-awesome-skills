"""Analyzer Health Dashboard — tracks per-analyzer runtime metrics across scans.

Stores metrics in workspace/analyzer_health.json and provides health
assessment (trigger rate, false positive rate, error rate, average duration,
staleness).
"""
import json
import os
import tempfile
import time
from typing import Dict, List, Any, Optional


_DEFAULT_WINDOW = 20


class AnalyzerHealthTracker:
    """Tracks analyzer health metrics across multiple scans."""

    def __init__(self, workspace_dir: str, window: int = _DEFAULT_WINDOW):
        self._path = os.path.join(workspace_dir, "analyzer_health.json")
        self._window = window
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        if os.path.isfile(self._path):
            try:
                with open(self._path, 'r', encoding='utf-8') as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def _save(self):
        dir_path = os.path.dirname(self._path)
        os.makedirs(dir_path, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix='.tmp')
        fd_consumed = False
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                fd_consumed = True
                json.dump(self._data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._path)
        except (OSError, TypeError, ValueError):
            if not fd_consumed:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def record(self, name: str, status: str, duration: float, findings: int,
               false_positives: int = 0):
        """Record a single analyzer execution result.

        Args:
            name: Analyzer name
            status: "success", "error", "skipped"
            duration: Execution time in seconds
            findings: Number of evidences produced
            false_positives: Number of false positives reported this run
        """
        entry = self._data.setdefault(name, {
            "runs": [],
            "total_runs": 0,
            "total_errors": 0,
            "total_findings": 0,
            "total_false_positives": 0,
            "last_triggered": None,
        })

        if "total_false_positives" not in entry:
            entry["total_false_positives"] = 0

        run = {
            "ts": int(time.time()),
            "status": status,
            "duration": round(duration, 3),
            "findings": findings,
            "fp": false_positives,
        }
        entry["runs"].append(run)
        if len(entry["runs"]) > self._window:
            entry["runs"] = entry["runs"][-self._window:]

        entry["total_runs"] += 1
        if status == "error":
            entry["total_errors"] += 1
        if findings > 0:
            entry["total_findings"] += findings
            entry["last_triggered"] = run["ts"]
        if false_positives > 0:
            entry["total_false_positives"] += false_positives

    def record_batch(self, module_stats: List[Dict[str, Any]]):
        """Record a batch of analyzer results from a scan.

        Args:
            module_stats: List of dicts with keys: name, status, duration, findings,
                          and optionally false_positives
        """
        for stat in module_stats:
            self.record(
                name=stat["name"],
                status=stat["status"],
                duration=stat.get("duration", 0.0),
                findings=stat.get("findings", 0),
                false_positives=stat.get("false_positives", 0),
            )
        self._save()

    def get_health(self, name: str) -> Dict[str, Any]:
        """Compute health metrics for a single analyzer."""
        entry = self._data.get(name)
        if not entry or not entry["runs"]:
            return {
                "name": name, "trigger_rate": 0.0, "error_rate": 0.0,
                "fp_rate": 0.0, "avg_duration": 0.0,
                "last_triggered_days": None,
                "status": "unknown", "total_runs": 0,
            }

        runs = entry["runs"]
        success_runs = [r for r in runs if r["status"] == "success"]
        triggered = sum(1 for r in success_runs if r["findings"] > 0)
        errors = sum(1 for r in runs if r["status"] == "error")
        total = len(runs)

        trigger_rate = triggered / max(len(success_runs), 1)
        error_rate = errors / total if total else 0.0
        avg_duration = (sum(r["duration"] for r in success_runs) /
                        max(len(success_runs), 1))

        total_findings = sum(r.get("findings", 0) for r in runs)
        total_fp = sum(r.get("fp", 0) for r in runs)
        fp_rate = total_fp / total_findings if total_findings > 0 else 0.0

        last_triggered_days = None
        if entry["last_triggered"]:
            elapsed = time.time() - entry["last_triggered"]
            last_triggered_days = int(elapsed / 86400)

        status = self._assess_status(trigger_rate, error_rate, fp_rate,
                                     last_triggered_days)

        return {
            "name": name,
            "trigger_rate": round(trigger_rate, 3),
            "error_rate": round(error_rate, 3),
            "fp_rate": round(fp_rate, 3),
            "avg_duration": round(avg_duration, 2),
            "last_triggered_days": last_triggered_days,
            "status": status,
            "total_runs": entry["total_runs"],
        }

    def get_all_health(self) -> List[Dict[str, Any]]:
        """Get health metrics for all tracked analyzers, sorted by status severity."""
        results = [self.get_health(name) for name in sorted(self._data.keys())]
        priority = {"unstable": 0, "needs_optimization": 1, "possibly_inactive": 2,
                    "overly_sensitive": 3, "healthy": 4, "unknown": 5}
        results.sort(key=lambda r: (priority.get(r["status"], 9), r["name"]))
        return results

    def format_report(self) -> str:
        """Format health dashboard as a text table."""
        health_list = self.get_all_health()
        if not health_list:
            return "No analyzer health data available. Run a scan first."

        lines = [
            "Analyzer Health Dashboard",
            "=" * 100,
            "{:<35} {:>8} {:>8} {:>6} {:>8} {:>7}  {}".format(
                "Analyzer", "Trigger%", "Error%", "FP%", "AvgTime", "LastDay", "Status"),
            "-" * 100,
        ]

        for h in health_list:
            last_day = str(h["last_triggered_days"]) if h["last_triggered_days"] is not None else "-"
            lines.append("{:<35} {:>7.0%} {:>7.0%} {:>5.0%} {:>7.2f}s {:>7}  {}".format(
                h["name"][:35],
                h["trigger_rate"],
                h["error_rate"],
                h["fp_rate"],
                h["avg_duration"],
                last_day,
                h["status"],
            ))

        lines.append("-" * 100)
        total = len(health_list)
        by_status = {}
        for h in health_list:
            by_status[h["status"]] = by_status.get(h["status"], 0) + 1
        summary_parts = ["{}: {}".format(k, v) for k, v in sorted(by_status.items())]
        lines.append("Total: {} analyzers | {}".format(total, ", ".join(summary_parts)))

        return "\n".join(lines)

    @staticmethod
    def _assess_status(trigger_rate: float, error_rate: float,
                       fp_rate: float = 0.0,
                       last_triggered_days: Optional[int] = None) -> str:
        if error_rate > 0:
            return "unstable"
        if fp_rate > 0.3:
            return "needs_optimization"
        if last_triggered_days is not None and last_triggered_days > 30:
            return "possibly_inactive"
        if trigger_rate > 0.8:
            return "overly_sensitive"
        if trigger_rate == 0.0:
            return "possibly_inactive"
        return "healthy"
