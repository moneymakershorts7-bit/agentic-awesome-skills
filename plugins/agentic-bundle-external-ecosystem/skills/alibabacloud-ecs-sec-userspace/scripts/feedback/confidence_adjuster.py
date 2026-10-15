"""Confidence self-adaptation engine.

Adjusts analyzer confidence based on scan history patterns:
- Repeated same-item hits → lower confidence (likely FP)
- First-time new item → boost confidence
- Environment fingerprint change → reset to baseline
- Long zero-hit streaks → mark as ineffective
"""

import json
import os
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .scan_history import ScanHistoryStore


CONFIDENCE_FLOOR = 0.3
CONFIDENCE_CEILING = 1.0
DEFAULT_BASELINE = 0.8
REPEATED_HIT_THRESHOLD = 5
ZERO_HIT_THRESHOLD = 20
HMAC_KEY_ENV = "SEC_INSPECT_FEEDBACK_KEY"
_FALLBACK_HMAC_KEY = b"sec-userspace-feedback-integrity-v1"


class ConfidenceAdjuster:
    """Adjusts per-analyzer confidence based on historical scan patterns."""

    def __init__(self, workspace_dir: str):
        self._workspace_dir = workspace_dir
        self._feedback_dir = os.path.join(workspace_dir, "feedback")
        self._state_path = os.path.join(self._feedback_dir, "confidence_state.json")
        self._history = ScanHistoryStore(workspace_dir)
        self._state: Dict[str, Dict] = {}
        self._load_state()

    def _get_hmac_key(self) -> bytes:
        env_key = os.environ.get(HMAC_KEY_ENV, "")
        if env_key:
            return env_key.encode("utf-8")
        return _FALLBACK_HMAC_KEY

    def _compute_hmac(self, data: str) -> str:
        return hmac.HMAC(self._get_hmac_key(), data.encode("utf-8"),
                         hashlib.sha256).hexdigest()[:32]

    def _load_state(self):
        """Load confidence state from disk, verifying HMAC integrity."""
        if not os.path.exists(self._state_path):
            self._state = {}
            return

        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            self._state = {}
            return

        stored_hmac = raw.pop("_hmac", None)
        if stored_hmac is not None:
            data_str = json.dumps(raw, sort_keys=True, ensure_ascii=False)
            expected = self._compute_hmac(data_str)
            if not hmac.compare_digest(stored_hmac, expected):
                self._state = {}
                return

        self._state = raw

    def _save_state(self):
        """Save confidence state to disk with HMAC signature."""
        os.makedirs(self._feedback_dir, exist_ok=True)
        data_str = json.dumps(self._state, sort_keys=True, ensure_ascii=False)
        output = dict(self._state)
        output["_hmac"] = self._compute_hmac(data_str)
        with open(self._state_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

    def get_confidence(self, analyzer_name: str) -> float:
        """Get the adjusted confidence for an analyzer.

        Returns baseline if no history data available.
        """
        entry = self._state.get(analyzer_name)
        if entry is None:
            return DEFAULT_BASELINE
        return entry.get("adjusted_confidence", DEFAULT_BASELINE)

    def get_all_adjustments(self) -> Dict[str, Dict]:
        """Get all confidence adjustments (copy)."""
        return dict(self._state)

    def update(self, env_fingerprint: Optional[str] = None) -> List[Dict]:
        """Run confidence adjustment based on scan history.

        Args:
            env_fingerprint: Current environment fingerprint. If changed
                from previous scan, all confidences reset to baseline.

        Returns:
            List of adjustment actions taken (for reporting).
        """
        actions = []

        # Check environment change
        prev_fingerprint = self._history.get_latest_env_fingerprint()
        if (env_fingerprint and prev_fingerprint and
                env_fingerprint != prev_fingerprint):
            actions.append({
                "type": "env_reset",
                "reason": "Environment fingerprint changed",
                "previous": prev_fingerprint,
                "current": env_fingerprint,
            })
            self._state = {}
            self._save_state()
            return actions

        history = self._history.load_history(limit=ZERO_HIT_THRESHOLD)
        if not history:
            return actions

        # Collect all analyzer names seen
        all_analyzers = set()
        for entry in history:
            all_analyzers.update(entry.get("analyzers", {}).keys())

        for analyzer_name in all_analyzers:
            adjustment = self._evaluate_analyzer(analyzer_name, history)
            if adjustment:
                actions.append(adjustment)

        self._save_state()
        return actions

    def _evaluate_analyzer(self, analyzer_name: str, history: List[Dict]) -> Optional[Dict]:
        """Evaluate and adjust confidence for a single analyzer."""
        hit_counts = []
        evidence_titles_per_scan = []

        for entry in history:
            adata = entry.get("analyzers", {}).get(analyzer_name)
            if adata is None:
                continue
            hit_counts.append(adata.get("hit_count", 0))
            titles = [
                ev["title"] for ev in entry.get("evidences", [])
                if ev.get("module") == analyzer_name
            ]
            evidence_titles_per_scan.append(titles)

        if not hit_counts:
            return None

        current_state = self._state.get(analyzer_name, {
            "base_confidence": DEFAULT_BASELINE,
            "adjusted_confidence": DEFAULT_BASELINE,
            "reason": "",
            "last_updated": "",
        })
        base = current_state.get("base_confidence", DEFAULT_BASELINE)
        old_confidence = current_state.get("adjusted_confidence", base)
        new_confidence = base
        reason = ""

        # Rule 1: Consecutive zero hits → mark ineffective
        consecutive_zeros = 0
        for count in hit_counts:
            if count == 0:
                consecutive_zeros += 1
            else:
                break

        if consecutive_zeros >= ZERO_HIT_THRESHOLD:
            new_confidence = max(CONFIDENCE_FLOOR, base * 0.5)
            reason = f"zero_hit_streak:{consecutive_zeros}_scans"
        else:
            # Rule 2: Repeated same evidence title → likely FP
            repeated_title = self._find_repeated_title(evidence_titles_per_scan)
            if repeated_title:
                title, count = repeated_title
                decay = max(0.6, 1.0 - (count - REPEATED_HIT_THRESHOLD + 1) * 0.05)
                new_confidence = max(CONFIDENCE_FLOOR, base * decay)
                reason = f"repeated_hit:{title}:{count}_times"
            elif hit_counts[0] > 0 and all(c == 0 for c in hit_counts[1:min(4, len(hit_counts))]):
                # Rule 3: First-time hit after silence → boost
                new_confidence = min(CONFIDENCE_CEILING, base * 1.1)
                reason = "new_detection:first_hit_after_silence"

        if reason and new_confidence != old_confidence:
            self._state[analyzer_name] = {
                "base_confidence": base,
                "adjusted_confidence": round(new_confidence, 4),
                "reason": reason,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            return {
                "type": "confidence_adjust",
                "analyzer": analyzer_name,
                "old_confidence": round(old_confidence, 4),
                "new_confidence": round(new_confidence, 4),
                "reason": reason,
            }

        return None

    def _find_repeated_title(self, evidence_titles_per_scan: List[List[str]]
                             ) -> Optional[Tuple[str, int]]:
        """Find an evidence title repeated across consecutive scans."""
        if len(evidence_titles_per_scan) < REPEATED_HIT_THRESHOLD:
            return None

        # Count consecutive appearance of each title from most recent
        title_streak = {}
        for titles in evidence_titles_per_scan:
            title_set = set(titles)
            for t in title_set:
                if t not in title_streak:
                    title_streak[t] = 0
                title_streak[t] += 1
            # Only count consecutive from the beginning
            break_titles = set(title_streak.keys()) - title_set
            for bt in break_titles:
                if title_streak[bt] < REPEATED_HIT_THRESHOLD:
                    del title_streak[bt]

        # Find title with longest streak
        for title, count in sorted(title_streak.items(), key=lambda x: -x[1]):
            if count >= REPEATED_HIT_THRESHOLD:
                return (title, count)

        return None

    def reset_analyzer(self, analyzer_name: str):
        """Reset confidence for a specific analyzer back to baseline."""
        if analyzer_name in self._state:
            del self._state[analyzer_name]
            self._save_state()

    def reset_all(self):
        """Reset all confidence adjustments."""
        self._state = {}
        self._save_state()
