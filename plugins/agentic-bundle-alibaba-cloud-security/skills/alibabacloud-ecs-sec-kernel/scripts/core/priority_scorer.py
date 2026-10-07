"""Vulnerability priority scoring engine.

Computes a composite priority score per CVE based on:
  Priority Score = CVSS_base * exploit_factor * exposure_factor

Produces a ranked list with P0/P1/P2 labels and fix recommendations.
"""

import sys
if sys.version_info < (3, 7):
    from ..thirdparties.dataclasses_backport import dataclass, field
else:
    from dataclasses import dataclass, field
from typing import List, Optional

from .result import DetectResult, Severity


SEVERITY_CVSS_MAP = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.0,
}

EXPLOIT_FACTOR_EXPLOITABLE = 1.5
EXPLOIT_FACTOR_DEFAULT = 1.0

EXPOSURE_FACTOR_NETWORK = 1.3
EXPOSURE_FACTOR_LOCAL = 1.0

NETWORK_VULN_TYPES = frozenset([
    "remote_code_exec",
    "remote_code_execution",
    "network",
])


@dataclass
class PriorityScoredResult:
    """A detection result augmented with priority scoring."""
    cve_id: str
    severity: str
    cvss_base: float
    exploit_factor: float
    exposure_factor: float
    priority_score: float
    priority_label: str
    reason: str
    fix_version: str = ""
    attack_vector: str = ""


def compute_cvss_base(result: DetectResult) -> float:
    """Derive CVSS base score from DetectResult.

    Uses the explicit cvss_score if available (>0), otherwise maps severity.
    """
    if result.cvss_score and result.cvss_score > 0:
        return result.cvss_score
    return SEVERITY_CVSS_MAP.get(result.severity, 5.5)


def compute_exploit_factor(result: DetectResult) -> float:
    """Determine exploit factor from PoC result."""
    if result.poc_result:
        status = result.poc_result.final_conclusion or result.poc_result.status
        if status in ("EXPLOITABLE", "USER_EXPLOITABLE"):
            return EXPLOIT_FACTOR_EXPLOITABLE
    return EXPLOIT_FACTOR_DEFAULT


def compute_exposure_factor(result: DetectResult, attack_vector: str = "") -> float:
    """Determine exposure factor from attack vector or vuln type."""
    if attack_vector and attack_vector.upper() in ("NETWORK", "ADJACENT"):
        return EXPOSURE_FACTOR_NETWORK
    if result.vuln_type and result.vuln_type.lower() in NETWORK_VULN_TYPES:
        return EXPOSURE_FACTOR_NETWORK
    return EXPOSURE_FACTOR_LOCAL


def classify_priority(score: float) -> str:
    """Map composite score to priority label."""
    if score >= 12.0:
        return "P0"
    elif score >= 8.0:
        return "P1"
    else:
        return "P2"


def build_reason(result: DetectResult, exploit_factor: float,
                 exposure_factor: float) -> str:
    """Build a human-readable reason string."""
    parts = [result.severity]
    if exploit_factor > 1.0:
        parts.append("PoC exploitable")
    if exposure_factor > 1.0:
        parts.append("network-reachable")
    if result.vuln_type:
        type_display = result.vuln_type.replace("_", " ")
        parts.append(type_display)
    return " + ".join(parts)


def score_results(results: List[DetectResult],
                  cve_metadata: dict = None) -> List[PriorityScoredResult]:
    """Score and rank a list of detection results.

    Args:
        results: DetectResult list (typically only VULNERABLE ones).
        cve_metadata: Optional dict mapping cve_id to metadata with
                      'attack_vector' and 'fix_version' fields.

    Returns:
        Sorted list of PriorityScoredResult (highest priority first).
    """
    if cve_metadata is None:
        cve_metadata = {}

    scored = []
    for r in results:
        if r.status not in ("VULNERABLE", "UNCERTAIN"):
            continue

        meta = cve_metadata.get(r.cve_id, {})
        attack_vector = meta.get("attack_vector", "")
        fix_version = meta.get("fix_version", "")

        cvss_base = compute_cvss_base(r)
        exploit_f = compute_exploit_factor(r)
        exposure_f = compute_exposure_factor(r, attack_vector)

        priority_score = round(cvss_base * exploit_f * exposure_f, 2)
        priority_label = classify_priority(priority_score)
        reason = build_reason(r, exploit_f, exposure_f)

        scored.append(PriorityScoredResult(
            cve_id=r.cve_id,
            severity=r.severity,
            cvss_base=cvss_base,
            exploit_factor=exploit_f,
            exposure_factor=exposure_f,
            priority_score=priority_score,
            priority_label=priority_label,
            reason=reason,
            fix_version=fix_version,
            attack_vector=attack_vector,
        ))

    scored.sort(key=lambda s: -s.priority_score)
    return scored


def format_priority_table(scored: List[PriorityScoredResult]) -> str:
    """Format scored results as a Markdown priority table."""
    if not scored:
        return ""

    lines = []
    lines.append("## Fix Priority Recommendations")
    lines.append("")
    lines.append("| Priority | CVE | Score | Reason |")
    lines.append("|----------|-----|-------|--------|")

    label_icons = {"P0": "\U0001f534", "P1": "\U0001f7e0", "P2": "\U0001f7e1"}

    for s in scored:
        icon = label_icons.get(s.priority_label, "")
        lines.append("| {icon} {label} | {cve} | {score:.2f} | {reason} |".format(
            icon=icon, label=s.priority_label, cve=s.cve_id,
            score=s.priority_score, reason=s.reason))

    lines.append("")

    # Fix version recommendations
    has_fix = [s for s in scored if s.fix_version]
    if has_fix:
        lines.append("### Recommended Fix Versions")
        lines.append("")
        for s in has_fix:
            lines.append("- **{cve}**: upgrade to kernel >= {ver}".format(
                cve=s.cve_id, ver=s.fix_version))
        lines.append("")

    # Action recommendations
    p0_list = [s for s in scored if s.priority_label == "P0"]
    p1_list = [s for s in scored if s.priority_label == "P1"]
    p2_list = [s for s in scored if s.priority_label == "P2"]

    lines.append("### Suggested Fix Order")
    lines.append("")
    if p0_list:
        lines.append("1. **Immediate** (P0): {cves}".format(
            cves=", ".join(s.cve_id for s in p0_list)))
    if p1_list:
        lines.append("{n}. **Next maintenance window** (P1): {cves}".format(
            n=2 if p0_list else 1,
            cves=", ".join(s.cve_id for s in p1_list)))
    if p2_list:
        idx = 1 + bool(p0_list) + bool(p1_list)
        lines.append("{n}. **Low risk / evaluate** (P2): {cves}".format(
            n=idx, cves=", ".join(s.cve_id for s in p2_list)))
    lines.append("")

    return "\n".join(lines)


def format_priority_json(scored: List[PriorityScoredResult]) -> list:
    """Format scored results as a JSON-serializable list."""
    return [
        {
            "cve_id": s.cve_id,
            "priority_label": s.priority_label,
            "priority_score": s.priority_score,
            "severity": s.severity,
            "cvss_base": s.cvss_base,
            "exploit_factor": s.exploit_factor,
            "exposure_factor": s.exposure_factor,
            "reason": s.reason,
            "fix_version": s.fix_version,
            "attack_vector": s.attack_vector,
        }
        for s in scored
    ]
