"""
Coverage Trend Tracker — records coverage snapshots over time.

Stores snapshots in workspace/coverage_history.jsonl (one JSON object per line).
Reports whether coverage is trending up, down, or flat.
"""
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class TrendTracker:
    """Tracks CVE coverage changes over time."""

    def __init__(self, project_root: Optional[Path] = None,
                 history_path: Optional[Path] = None):
        from .cve_map import _resolve_project_root
        self._root = project_root or _resolve_project_root()
        self._history_path = history_path or (self._root / 'workspace' / 'coverage_history.jsonl')

    def record_snapshot(self, kernel_version: str) -> Dict:
        """Compute current coverage and append to history.

        Returns the snapshot dict that was recorded.
        """
        from .cve_map import CoverageMap

        coverage = CoverageMap(self._root)
        result = coverage.compute_coverage(kernel_version)

        snapshot = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "kernel_version": kernel_version,
            "total_known": result['total_known'],
            "total_covered": result['total_covered'],
            "coverage_pct": result['coverage_pct'],
            "uncovered_count": len(result['uncovered']),
        }

        self._history_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._history_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(snapshot) + '\n')

        logger.info(f"Coverage snapshot recorded: {snapshot['coverage_pct']}%")
        return snapshot

    def get_history(self, last_n: int = 0) -> List[Dict]:
        """Read history entries. If last_n > 0, return only the last N entries."""
        if not self._history_path.exists():
            return []

        entries = []
        with open(self._history_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        if last_n > 0:
            return entries[-last_n:]
        return entries

    def get_trend(self, last_n: int = 5) -> str:
        """Determine coverage trend direction.

        Returns: "UP", "DOWN", "FLAT", or "INSUFFICIENT_DATA"
        """
        history = self.get_history(last_n=last_n)
        if len(history) < 2:
            return "INSUFFICIENT_DATA"

        first_pct = history[0]['coverage_pct']
        last_pct = history[-1]['coverage_pct']
        diff = last_pct - first_pct

        if diff > 1.0:
            return "UP"
        elif diff < -1.0:
            return "DOWN"
        return "FLAT"

    def format_report(self, kernel_version: str, last_n: int = 10) -> str:
        """Human-readable trend report."""
        history = self.get_history(last_n=last_n)
        trend = self.get_trend(last_n=last_n)

        trend_symbol = {"UP": "^", "DOWN": "v", "FLAT": "=",
                        "INSUFFICIENT_DATA": "?"}

        lines = [
            f"=== Coverage Trend ({trend_symbol.get(trend, '?')} {trend}) ===",
            f"Kernel: {kernel_version}",
            "",
        ]

        if not history:
            lines.append("No history recorded yet. Run --coverage to start tracking.")
            return "\n".join(lines)

        lines.append(f"Last {len(history)} snapshots:")
        for entry in history:
            lines.append(
                f"  {entry['timestamp']} | {entry['coverage_pct']}% "
                f"({entry['total_covered']}/{entry['total_known']})"
            )

        return "\n".join(lines)
