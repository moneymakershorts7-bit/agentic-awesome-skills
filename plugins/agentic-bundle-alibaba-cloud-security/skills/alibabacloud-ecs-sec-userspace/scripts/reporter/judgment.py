"""JudgmentEngine: Comprehensive judgment for sec-userspace evidences."""
import math
from collections import defaultdict
from typing import List, Dict, Tuple


def _safe_weighted_score(e):
    """Return weighted_score, treating NaN/Inf as 0.0."""
    s = e.weighted_score
    if isinstance(s, float) and (math.isnan(s) or math.isinf(s)):
        return 0.0
    return s


class JudgmentEngine:
    """Comprehensive Judgment Engine"""

    MAX_SCORE = 100.0

    # Verification result weights - how much each verification status contributes
    VERIFICATION_WEIGHTS = {
        'confirmed_tp': 1.0,      # Confirmed true threat - full weight
        'likely_true': 0.7,       # Likely true - reduced but significant
        'pending': 0.5,           # Not yet verified - moderate weight
        'likely_fp': 0.1,         # Likely false positive - minimal weight
        'whitelisted': 0.0,       # Whitelisted - no weight
    }

    def calculate_score(self, evidences) -> float:
        """Calculate risk score with verification weights and capping

        Score calculation considers:
        1. Base severity score (CRITICAL=10, HIGH=8, MEDIUM=5, LOW=2, INFO=0)
        2. Confidence factor (0.0-1.0)
        3. Verification status weight (confirmed_tp=1.0, likely_true=0.7, etc.)
        4. Correlated alert deduplication (group correlated alerts, take max)

        Returns:
            Risk score capped at MAX_SCORE (0-100)
        """
        if not evidences:
            return 0.0

        # Step 1: Deduplicate correlated alerts to avoid double-counting
        unique_evidences = self._deduplicate_correlated_evidences(evidences)

        # Step 2: Calculate weighted scores with verification factors
        weighted_scores = []
        for e in unique_evidences:
            base_score = e.severity.score
            confidence_factor = e.confidence
            verification_factor = self.VERIFICATION_WEIGHTS.get(
                e.verified_status or 'pending', 0.5
            )

            weighted_score = base_score * confidence_factor * verification_factor
            weighted_scores.append(weighted_score)

        # Step 3: Sum and cap the score
        raw_score = sum(weighted_scores)
        return min(raw_score, self.MAX_SCORE)

    def _deduplicate_correlated_evidences(self, evidences: List) -> List:
        """Deduplicate correlated evidences to avoid double-counting

        Groups evidences by (module, attack_tactic, attack_id) and keeps only
        the highest weighted_score from each group. This prevents inflated scores
        from multiple related alerts detecting the same underlying issue.

        Args:
            evidences: List of Evidence objects

        Returns:
            Deduplicated list with highest-scoring evidence from each correlation group
        """
        if not evidences:
            return []

        # Group by correlation key (module + tactic + attack_id for more granular grouping)
        correlation_groups: Dict[Tuple[str, str, str], List] = defaultdict(list)
        for e in evidences:
            group_key = (e.module, e.attack_tactic, e.attack_id)
            correlation_groups[group_key].append(e)

        # Take highest weighted_score from each group
        deduplicated = []
        for group_key, group_evidences in correlation_groups.items():
            if len(group_evidences) == 1:
                deduplicated.append(group_evidences[0])
            else:
                # Take the evidence with highest weighted_score
                highest = max(group_evidences, key=_safe_weighted_score)
                deduplicated.append(highest)

        return deduplicated

    def determine_conclusion(self, evidences: List) -> dict:
        """
        Determine conclusion using new semantic-based grading system

        Args:
            evidences: List of Evidence objects

        New logic based on verified_status:
        - CRITICAL + confirmed_tp -> COMPROMISED
        - HIGH only (no CRITICAL confirmed) -> NEEDS_FIX
        - NOTICE/MEDIUM/LOW only -> RECOMMENDATIONS
        - Nothing -> SAFE
        """
        # Classify by verified_status
        confirmed_intrusions = []
        security_issues = []
        recommendations = []

        for e in evidences:
            status = e.verified_status or "pending"

            # Skip false positives
            if status in ["likely_fp", "whitelisted"]:
                continue

            # Classify based on severity and verification
            if e.severity.name == "CRITICAL" and status == "confirmed_tp":
                confirmed_intrusions.append(e)
            elif e.severity.name in ["CRITICAL", "HIGH"]:
                security_issues.append(e)
            else:
                recommendations.append(e)

        # Determine new semantic conclusion
        if confirmed_intrusions:
            conclusion_level = "COMPROMISED"
            conclusion_desc = "Evidence of active intrusion detected"
            result_code = "critical"
        elif security_issues:
            conclusion_level = "NEEDS_FIX"
            conclusion_desc = "Security issues require attention"
            result_code = "elevated"
        elif recommendations:
            conclusion_level = "RECOMMENDATIONS"
            conclusion_desc = "Security improvement suggestions"
            result_code = "moderate"
        else:
            conclusion_level = "SAFE"
            conclusion_desc = "No security issues detected"
            result_code = "normal"

        # Calculate total score with deduplication
        total_score = self.calculate_score(evidences)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for e in evidences:
            severity_counts[e.severity.name] += 1

        # Take top 5 by weighted_score in descending order
        top_evidences = [e.to_dict() for e in sorted(evidences, key=_safe_weighted_score, reverse=True)[:5]]

        return {
            "conclusion": conclusion_level,
            "conclusion_description": conclusion_desc,
            "result_code": result_code,
            "total_score": round(total_score, 2),
            "evidence_count": len(evidences),
            "severity_counts": severity_counts,
            "confirmed_intrusions": len(confirmed_intrusions),
            "security_issues": len(security_issues),
            "recommendations": len(recommendations),
            "top_evidences": top_evidences,
        }
