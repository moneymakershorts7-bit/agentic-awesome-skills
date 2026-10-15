"""Detection pattern learner — identifies co-occurrence and candidate IOCs.

Analyses scan history to extract:
- Co-occurring analyzer pairs (potential attack chains)
- Environment-specific detection profiles
- Candidate IOCs from high-confidence alerts
"""

import json
import os
from collections import defaultdict
from typing import Dict, List

from .scan_history import ScanHistoryStore


CORRELATION_THRESHOLD = 0.80
MIN_SAMPLES_FOR_CORRELATION = 5
IOC_PROMOTION_COUNT = 3


class PatternLearner:
    """Learns detection patterns from historical scan data."""

    def __init__(self, workspace_dir: str):
        self._workspace_dir = workspace_dir
        self._feedback_dir = os.path.join(workspace_dir, "feedback")
        self._candidate_ioc_path = os.path.join(
            self._feedback_dir, "candidate_iocs.jsonl"
        )
        self._history = ScanHistoryStore(workspace_dir)

    def analyze(self, min_history: int = 10) -> Dict:
        """Run full pattern analysis on scan history.

        Args:
            min_history: Minimum scan records required for meaningful analysis.

        Returns:
            Dict with keys: correlations, ineffective_analyzers, candidate_iocs
        """
        history = self._history.load_history()
        result = {
            "correlations": [],
            "ineffective_analyzers": [],
            "env_profile": {},
            "candidate_iocs": [],
        }

        if len(history) < min_history:
            return result

        result["correlations"] = self._find_correlations(history)
        result["ineffective_analyzers"] = self._find_ineffective(history)
        result["env_profile"] = self._build_env_profile(history)
        result["candidate_iocs"] = self._extract_candidate_iocs(history)

        return result

    def _find_correlations(self, history: List[Dict]) -> List[Dict]:
        """Find analyzer pairs that frequently co-occur in hits."""
        # Build per-scan hit presence matrix
        all_analyzers = set()
        hit_presence = []  # list of sets of analyzer names with hits per scan

        for entry in history:
            hit_set = set()
            for name, data in entry.get("analyzers", {}).items():
                all_analyzers.add(name)
                if data.get("hit_count", 0) > 0:
                    hit_set.add(name)
            hit_presence.append(hit_set)

        if len(hit_presence) < MIN_SAMPLES_FOR_CORRELATION:
            return []

        # Calculate co-occurrence ratio for each pair
        analyzers = sorted(all_analyzers)
        correlations = []

        for i in range(len(analyzers)):
            for j in range(i + 1, len(analyzers)):
                a, b = analyzers[i], analyzers[j]
                both_hit = sum(1 for s in hit_presence if a in s and b in s)
                either_hit = sum(1 for s in hit_presence if a in s or b in s)

                if either_hit < MIN_SAMPLES_FOR_CORRELATION:
                    continue

                ratio = both_hit / either_hit if either_hit > 0 else 0.0

                if ratio >= CORRELATION_THRESHOLD:
                    correlations.append({
                        "analyzer_a": a,
                        "analyzer_b": b,
                        "correlation": round(ratio, 3),
                        "co_occurrences": both_hit,
                        "total_either": either_hit,
                    })

        correlations.sort(key=lambda x: -x["correlation"])
        return correlations[:20]

    def _find_ineffective(self, history: List[Dict]) -> List[Dict]:
        """Find analyzers with sustained zero-hit streaks."""
        analyzer_total_scans = defaultdict(int)
        consecutive_zeros = {}

        for entry in history:
            for name, data in entry.get("analyzers", {}).items():
                analyzer_total_scans[name] += 1
                if name not in consecutive_zeros:
                    consecutive_zeros[name] = 0
                if consecutive_zeros[name] >= 0:
                    if data.get("hit_count", 0) == 0:
                        consecutive_zeros[name] += 1
                    else:
                        consecutive_zeros[name] = -1

        ineffective = []
        for name, streak in consecutive_zeros.items():
            if streak >= 20:
                ineffective.append({
                    "analyzer": name,
                    "zero_hit_streak": streak,
                    "total_scans": analyzer_total_scans[name],
                })

        ineffective.sort(key=lambda x: -x["zero_hit_streak"])
        return ineffective

    def _build_env_profile(self, history: List[Dict]) -> Dict:
        """Build environment-specific detection profile.

        Identifies which analyzers are most active for the current environment.
        """
        if not history:
            return {}

        # Get current fingerprint
        current_fp = history[0].get("env_fingerprint", "")
        if not current_fp:
            return {}

        # Filter to same-environment scans
        same_env = [e for e in history if e.get("env_fingerprint") == current_fp]
        if len(same_env) < 3:
            return {}

        # Calculate hit rate per analyzer in this environment
        hit_rates = defaultdict(lambda: {"hits": 0, "scans": 0})
        for entry in same_env:
            for name, data in entry.get("analyzers", {}).items():
                hit_rates[name]["scans"] += 1
                if data.get("hit_count", 0) > 0:
                    hit_rates[name]["hits"] += 1

        profile = {}
        for name, stats in hit_rates.items():
            rate = stats["hits"] / stats["scans"] if stats["scans"] > 0 else 0.0
            if rate > 0.0:
                profile[name] = round(rate, 3)

        return profile

    def _extract_candidate_iocs(self, history: List[Dict]) -> List[Dict]:
        """Extract candidate IOCs from high-confidence evidence.

        Looks for IPs, paths, and process names in evidence raw_data
        that appear consistently in high-confidence alerts.
        """
        # For now, track evidence titles that appear with high confidence
        title_occurrences = defaultdict(int)
        title_details = {}

        for entry in history:
            for ev in entry.get("evidences", []):
                conf = ev.get("confidence", 0.0)
                if conf >= 0.7:
                    title = ev.get("title", "")
                    if title:
                        title_occurrences[title] += 1
                        if title not in title_details:
                            title_details[title] = {
                                "module": ev.get("module", ""),
                                "severity": ev.get("severity", ""),
                                "attack_id": ev.get("attack_id", ""),
                                "first_seen": entry.get("timestamp", ""),
                            }

        candidates = []
        for title, count in title_occurrences.items():
            if count >= IOC_PROMOTION_COUNT:
                detail = title_details[title]
                candidates.append({
                    "title": title,
                    "occurrences": count,
                    "module": detail["module"],
                    "severity": detail["severity"],
                    "attack_id": detail["attack_id"],
                    "first_seen": detail["first_seen"],
                    "status": "promoted" if count >= IOC_PROMOTION_COUNT else "observing",
                })

        candidates.sort(key=lambda x: -x["occurrences"])
        return candidates[:50]

    def save_candidate_iocs(self, candidates: List[Dict]):
        """Persist candidate IOCs to JSONL file."""
        os.makedirs(self._feedback_dir, exist_ok=True)
        with open(self._candidate_ioc_path, "w", encoding="utf-8") as f:
            for ioc in candidates:
                f.write(json.dumps(ioc, ensure_ascii=False) + "\n")

    def load_candidate_iocs(self) -> List[Dict]:
        """Load candidate IOCs from disk."""
        if not os.path.exists(self._candidate_ioc_path):
            return []
        result = []
        try:
            with open(self._candidate_ioc_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            result.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
        return result
