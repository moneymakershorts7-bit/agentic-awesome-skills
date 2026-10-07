"""Scan history persistent store — JSONL append-only with auto-rolling."""

import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from typing import Dict, List, Optional


MAX_HISTORY_RECORDS = 100


class ScanHistoryStore:
    """Persists scan results to JSONL for feedback loop consumption.

    Storage: workspace/feedback/scan_history.jsonl (append-only)
    Rolling: keeps last MAX_HISTORY_RECORDS entries; excess archived.
    """

    def __init__(self, workspace_dir: str):
        self._feedback_dir = os.path.join(workspace_dir, "feedback")
        self._history_path = os.path.join(self._feedback_dir, "scan_history.jsonl")
        self._archive_path = os.path.join(self._feedback_dir, "scan_history.archive.jsonl")

    def _ensure_dir(self):
        os.makedirs(self._feedback_dir, exist_ok=True)

    def record(self, module_stats: List[Dict], evidences: list,
               system_info: Optional[Dict] = None) -> Dict:
        """Record a scan result.

        Args:
            module_stats: List of per-analyzer stats dicts (name, status, duration, findings).
            evidences: List of Evidence objects from the scan.
            system_info: Optional system_info dict from profiling phase.

        Returns:
            The recorded entry dict.
        """
        self._ensure_dir()

        env_fingerprint = self._compute_env_fingerprint(system_info)

        analyzer_summaries = {}
        for stat in module_stats:
            name = stat.get("name", "unknown")
            analyzer_summaries[name] = {
                "status": stat.get("status", "unknown"),
                "duration": round(stat.get("duration", 0.0), 3),
                "hit_count": stat.get("findings", 0),
            }

        evidence_summaries = []
        for ev in evidences:
            ev_dict = ev.to_dict() if hasattr(ev, 'to_dict') else {}
            evidence_summaries.append({
                "module": getattr(ev, 'module', ev_dict.get('module', '')),
                "title": getattr(ev, 'title', ev_dict.get('title', '')),
                "severity": getattr(ev, 'severity', ev_dict.get('severity', '')),
                "confidence": getattr(ev, 'confidence', ev_dict.get('confidence', 0.0)),
                "attack_id": getattr(ev, 'attack_id', ev_dict.get('attack_id', '')),
                "verified_status": getattr(ev, 'verified_status', ev_dict.get('verified_status', '')),
            })
            # Normalize severity to string
            sev = evidence_summaries[-1]["severity"]
            if hasattr(sev, 'value'):
                evidence_summaries[-1]["severity"] = sev.value

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "env_fingerprint": env_fingerprint,
            "analyzers": analyzer_summaries,
            "evidences": evidence_summaries,
            "total_evidences": len(evidences),
            "total_analyzers": len(module_stats),
        }

        with open(self._history_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self._roll_if_needed()
        return entry

    def load_history(self, limit: Optional[int] = None) -> List[Dict]:
        """Load scan history records.

        Args:
            limit: Max records to return (most recent first). None = all.

        Returns:
            List of history entry dicts, most recent first.
        """
        if not os.path.exists(self._history_path):
            return []

        records = []
        try:
            with open(self._history_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []

        records.reverse()
        if limit is not None:
            records = records[:limit]
        return records

    def get_analyzer_hit_history(self, analyzer_name: str,
                                 limit: int = 20) -> List[Dict]:
        """Get hit history for a specific analyzer.

        Returns list of {timestamp, hit_count, evidence_titles} dicts.
        """
        history = self.load_history(limit=limit)
        result = []
        for entry in history:
            analyzer_data = entry.get("analyzers", {}).get(analyzer_name)
            if analyzer_data is None:
                continue
            titles = [
                ev["title"] for ev in entry.get("evidences", [])
                if ev.get("module") == analyzer_name
            ]
            result.append({
                "timestamp": entry["timestamp"],
                "hit_count": analyzer_data.get("hit_count", 0),
                "evidence_titles": titles,
            })
        return result

    def get_latest_env_fingerprint(self) -> Optional[str]:
        """Get the environment fingerprint from the most recent scan."""
        history = self.load_history(limit=1)
        if history:
            return history[0].get("env_fingerprint")
        return None

    def _compute_env_fingerprint(self, system_info: Optional[Dict]) -> str:
        """Compute a stable environment fingerprint.

        Combines OS version, kernel version, and hostname hash.
        """
        parts = []
        parts.append(platform.system())
        parts.append(platform.release())
        parts.append(platform.machine())

        if system_info:
            parts.append(system_info.get("os_version", ""))
            parts.append(system_info.get("kernel_version", ""))

        try:
            hostname = platform.node()
            parts.append(hostname)
        except OSError:
            pass

        raw = "|".join(str(p) for p in parts if p)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _roll_if_needed(self):
        """Archive excess records beyond MAX_HISTORY_RECORDS."""
        if not os.path.exists(self._history_path):
            return

        try:
            with open(self._history_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return

        if len(lines) <= MAX_HISTORY_RECORDS:
            return

        archive_lines = lines[:-MAX_HISTORY_RECORDS]
        keep_lines = lines[-MAX_HISTORY_RECORDS:]

        try:
            with open(self._archive_path, "a", encoding="utf-8") as f:
                f.writelines(archive_lines)
            with open(self._history_path, "w", encoding="utf-8") as f:
                f.writelines(keep_lines)
        except OSError:
            pass
