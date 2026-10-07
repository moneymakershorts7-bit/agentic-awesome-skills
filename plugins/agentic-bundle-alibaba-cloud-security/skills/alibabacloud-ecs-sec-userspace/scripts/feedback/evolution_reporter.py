"""Evolution reporter — generates self-evolution summary for scan reports."""

from typing import Dict, List


class EvolutionReporter:
    """Generates human-readable evolution summary from feedback loop data."""

    def __init__(self, confidence_actions: List[Dict] = None,
                 pattern_analysis: Dict = None):
        self._confidence_actions = confidence_actions or []
        self._pattern_analysis = pattern_analysis or {}

    def generate_summary(self) -> str:
        """Generate the evolution summary text block.

        Returns:
            Multi-line string suitable for appending to scan reports.
        """
        lines = []
        lines.append("=== Detection Engine Self-Evolution Summary ===")

        has_content = False

        # Confidence adjustments
        for action in self._confidence_actions:
            has_content = True
            if action.get("type") == "env_reset":
                lines.append(
                    "[RESET] Environment changed — all confidence scores reset to baseline"
                )
            elif action.get("type") == "confidence_adjust":
                analyzer = action.get("analyzer", "unknown")
                old = action.get("old_confidence", 0.0)
                new = action.get("new_confidence", 0.0)
                reason = action.get("reason", "")
                direction = "↓" if new < old else "↑"
                lines.append(
                    f"[ADJUST] {analyzer} confidence {old:.2f} → {new:.2f} {direction} ({reason})"
                )

        # Ineffective analyzers
        ineffective = self._pattern_analysis.get("ineffective_analyzers", [])
        for item in ineffective[:5]:
            has_content = True
            analyzer = item.get("analyzer", "unknown")
            streak = item.get("zero_hit_streak", 0)
            lines.append(
                f"[INEFFECTIVE] {analyzer} — {streak} consecutive zero-hit scans, review rule relevance"
            )

        # Correlations
        correlations = self._pattern_analysis.get("correlations", [])
        for corr in correlations[:3]:
            has_content = True
            a = corr.get("analyzer_a", "")
            b = corr.get("analyzer_b", "")
            r = corr.get("correlation", 0.0)
            lines.append(
                f"[CORRELATION] {a} + {b} co-occur (r={r:.2f}), possible attack chain"
            )

        # Candidate IOCs
        candidates = self._pattern_analysis.get("candidate_iocs", [])
        promoted = [c for c in candidates if c.get("status") == "promoted"]
        for ioc in promoted[:5]:
            has_content = True
            title = ioc.get("title", "")
            count = ioc.get("occurrences", 0)
            module = ioc.get("module", "")
            lines.append(
                f"[IOC] Promoted indicator: {title} (seen {count}x from {module})"
            )

        # Environment profile
        env_profile = self._pattern_analysis.get("env_profile", {})
        if env_profile:
            has_content = True
            top_active = sorted(env_profile.items(), key=lambda x: -x[1])[:3]
            active_str = ", ".join(f"{name}({rate:.0%})" for name, rate in top_active)
            lines.append(f"[PROFILE] Top active detectors for this environment: {active_str}")

        if not has_content:
            lines.append("[INFO] Insufficient history for self-evolution analysis (need 10+ scans)")

        return "\n".join(lines)

    def generate_dict(self) -> Dict:
        """Generate structured evolution data for JSON reports."""
        return {
            "confidence_adjustments": self._confidence_actions,
            "ineffective_analyzers": self._pattern_analysis.get("ineffective_analyzers", []),
            "correlations": self._pattern_analysis.get("correlations", []),
            "candidate_iocs": self._pattern_analysis.get("candidate_iocs", []),
            "env_profile": self._pattern_analysis.get("env_profile", {}),
        }
