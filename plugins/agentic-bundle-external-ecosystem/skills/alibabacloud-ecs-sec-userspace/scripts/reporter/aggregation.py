"""Aggregation: Evidence aggregation for sec-userspace reports."""
import math
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Tuple


# Import at module level for aggregation types
@dataclass
class AggregatedGroup:
    """Aggregated security event group"""
    title: str
    module: str
    severity: 'Severity'
    attack_id: str
    attack_tactic: str
    confidence: float
    count: int
    source_paths: List[str]
    remediation: str
    representative: 'Evidence'

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "module": self.module,
            "severity": self.severity.value,
            "attack_id": self.attack_id,
            "attack_tactic": self.attack_tactic,
            "confidence": self.confidence,
            "count": self.count,
            "source_paths": self.source_paths,
            "remediation": self.remediation,
            "description": self.representative.description,
        }


def aggregate_evidences(evidences: List['Evidence'], limit: int = 0) -> List[AggregatedGroup]:
    """Aggregate security events into groups

    Grouping criteria: (module, title, attack_id)
    Take highest severity and confidence within group, aggregate all source paths.

    Args:
        evidences: List of evidence objects to aggregate
        limit: Maximum number of groups to return (0 = no limit)

    Returns:
        List of aggregated groups, sorted by severity and count
    """
    # P2-2026-04-13: Early return for empty evidences - avoids all overhead
    if not evidences:
        return []

    groups: Dict[Tuple[str, str, str], List] = defaultdict(list)
    for e in evidences:
        key = (e.module, e.title, e.attack_id)
        groups[key].append(e)

    result: List[AggregatedGroup] = []
    for (module, title, attack_id), members in groups.items():
        representative = max(members, key=lambda e: e.weighted_score if not (math.isnan(e.weighted_score) or math.isinf(e.weighted_score)) else 0.0)
        max_severity = max(members, key=lambda e: e.severity.score if not (math.isnan(e.severity.score) or math.isinf(e.severity.score)) else 0.0).severity
        valid_confidences = [e.confidence for e in members if not math.isnan(e.confidence)]
        max_confidence = max(valid_confidences) if valid_confidences else 0.0

        # Collect unique source paths
        seen_paths: set = set()
        unique_paths: List[str] = []
        for e in members:
            if e.source_path and e.source_path not in seen_paths:
                seen_paths.add(e.source_path)
                unique_paths.append(e.source_path)

        remediation = representative.remediation
        if not remediation:
            for e in members:
                if e.remediation:
                    remediation = e.remediation
                    break

        result.append(AggregatedGroup(
            title=title,
            module=module,
            severity=max_severity,
            attack_id=attack_id,
            attack_tactic=representative.attack_tactic,
            confidence=max_confidence,
            count=len(members),
            source_paths=unique_paths,
            remediation=remediation,
            representative=representative,
        ))

    result.sort(key=lambda g: (-(g.severity.score if not (math.isnan(g.severity.score) or math.isinf(g.severity.score)) else 0.0), -g.count))

    # Apply limit if specified
    if limit > 0 and len(result) > limit:
        result = result[:limit]

    return result
