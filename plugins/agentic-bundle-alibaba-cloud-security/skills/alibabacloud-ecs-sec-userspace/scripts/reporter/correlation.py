"""Cross-Analyzer Correlation - Groups evidences by shared entities and upgrades severity."""
import math
import re
import uuid
from typing import List, Dict, Any, Tuple
from collections import defaultdict

from .evidence import Evidence
from .severity import Severity


# --- Entity Extraction ---

_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

_PATH_RE = re.compile(r'(/[a-zA-Z0-9._\-/]+)')


def _extract_entity_keys(evidence: Evidence) -> List[str]:
    """Extract entity keys from an evidence for correlation grouping.

    Looks for file paths, IP addresses, process names, and user names
    in source_path and raw_data.

    Returns a list of normalized entity key strings.
    """
    keys: List[str] = []
    raw = evidence.raw_data or {}

    # 1. File path from source_path
    src = getattr(evidence, 'source_path', '') or ''
    if src.startswith('/'):
        keys.append(f"path:{src}")
    else:
        # Try to extract a path from source_path even if it doesn't start with /
        m = _PATH_RE.search(src)
        if m:
            keys.append(f"path:{m.group(1)}")

    # 2. File path from raw_data
    for pk in ('file_path', 'path', 'source_path', 'target_path'):
        pv = raw.get(pk)
        if isinstance(pv, str) and pv.startswith('/'):
            key = f"path:{pv}"
            if key not in keys:
                keys.append(key)

    # 3. IP addresses from raw_data
    for ik in ('ip', 'remote_ip', 'local_ip', 'src_ip', 'dst_ip', 'attacker_ip'):
        iv = raw.get(ik)
        if isinstance(iv, str):
            for ip in _IP_RE.findall(iv):
                key = f"ip:{ip}"
                if key not in keys:
                    keys.append(key)

    # 4. Process names from raw_data
    for pk in ('process_name', 'comm', 'exe', 'executable', 'cmd'):
        pv = raw.get(pk)
        if isinstance(pv, str) and pv:
            key = f"process:{pv}"
            if key not in keys:
                keys.append(key)

    # 5. User names from raw_data
    for uk in ('user', 'username', 'uid', 'account', 'owner'):
        uv = raw.get(uk)
        if isinstance(uv, str) and uv:
            key = f"user:{uv}"
            if key not in keys:
                keys.append(key)

    return keys


# --- Severity Upgrade ---

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_SEVERITY_INDEX = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _upgrade_severity(severity: Severity) -> Severity:
    """Upgrade severity by one level, capped at CRITICAL."""
    idx = _SEVERITY_INDEX.get(severity, 0)
    new_idx = min(idx + 1, len(_SEVERITY_ORDER) - 1)
    return _SEVERITY_ORDER[new_idx]


# --- Main Correlation Function ---

def run_cross_correlation(
    evidences: List[Evidence],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Perform cross-analyzer correlation on security evidences.

    Groups evidences by shared entity keys and identifies cases where
    multiple different analyzers flag the same entity.  When 2+ distinct
    analyzers independently report HIGH or above on the same entity,
    the max severity is upgraded one level.

    Args:
        evidences: List of Evidence objects to correlate.

    Returns:
        A tuple of (cross_correlation_stats, correlation_summary):

        cross_correlation_stats:
            - correlated_groups: int, number of groups with 2+ analyzers
            - upgraded_count: int, how many groups had severity upgraded
            - correlation_rate: float, fraction of groups that are correlated

        correlation_summary:
            - total_groups: int
            - cross_analyzer_groups: int
            - correlated_groups: int
            - upgraded_count: int
            - isolated_count: int
            - correlation_rate: float
            - groups: list of group dicts
    """
    # --- Edge cases ---
    if not evidences:
        stats = {"correlated_groups": 0, "upgraded_count": 0, "correlation_rate": 0.0}
        summary = {
            "total_groups": 0,
            "cross_analyzer_groups": 0,
            "correlated_groups": 0,
            "upgraded_count": 0,
            "isolated_count": 0,
            "correlation_rate": 0.0,
            "groups": [],
        }
        return stats, summary

    # --- Group by entity key ---
    entity_map: Dict[str, Dict[str, Evidence]] = defaultdict(dict)
    for ev in evidences:
        keys = _extract_entity_keys(ev)
        if not keys:
            # Evidence has no extractable entity key; put it in its own isolated group
            keys = [f"id:{ev.id}"]
        for k in keys:
            entity_map[k][ev.id] = ev

    # --- Build correlation groups ---
    groups: List[Dict[str, Any]] = []
    upgraded_count = 0
    cross_analyzer_count = 0

    for entity_key, ev_dict in entity_map.items():
        ev_list = list(ev_dict.values())
        modules = list(dict.fromkeys(ev.module for ev in ev_list))  # preserve order, dedup
        attack_ids = list(dict.fromkeys(ev.attack_id for ev in ev_list if ev.attack_id))
        evidence_count = len(ev_list)

        # Max severity among the group
        max_sev = max((ev.severity for ev in ev_list), key=lambda s: _SEVERITY_INDEX.get(s, 0))
        original_severity_name = max_sev.name

        # Determine if this is a cross-analyzer group (2+ distinct analyzers)
        is_cross_analyzer = len(modules) >= 2

        # Correlation strength formula
        unique_analyzers = len(modules)
        correlation_strength = min(1.0, unique_analyzers * 0.25 + evidence_count * 0.1)

        # Severity upgrade logic
        upgraded = False
        final_severity_name = original_severity_name
        if is_cross_analyzer:
            cross_analyzer_count += 1
            # Upgrade if max severity is HIGH or above and 2+ analyzers
            if max_sev >= Severity.HIGH and max_sev < Severity.CRITICAL:
                new_sev = _upgrade_severity(max_sev)
                final_severity_name = new_sev.name
                upgraded = True
                upgraded_count += 1

        group_id = f"CG-{uuid.uuid4().hex[:8]}"
        groups.append({
            "group_id": group_id,
            "entity_key": entity_key,
            "analyzers": modules,
            "attack_ids": attack_ids,
            "evidence_count": evidence_count,
            "max_severity": final_severity_name,
            "original_severity": original_severity_name,
            "correlation_strength": round(correlation_strength, 2),
            "upgraded": upgraded,
        })

    groups.sort(
        key=lambda g: g["correlation_strength"] if not math.isnan(g["correlation_strength"]) else 0.0,
        reverse=True,
    )

    # --- Compute stats ---
    total_groups = len(groups)
    correlated_groups = cross_analyzer_count
    isolated_count = total_groups - correlated_groups
    correlation_rate = correlated_groups / total_groups if total_groups > 0 else 0.0

    cross_correlation_stats = {
        "correlated_groups": correlated_groups,
        "upgraded_count": upgraded_count,
        "correlation_rate": round(correlation_rate, 4),
    }

    correlation_summary = {
        "total_groups": total_groups,
        "cross_analyzer_groups": cross_analyzer_count,
        "correlated_groups": correlated_groups,
        "upgraded_count": upgraded_count,
        "isolated_count": isolated_count,
        "correlation_rate": round(correlation_rate, 4),
        "groups": groups,
    }

    return cross_correlation_stats, correlation_summary
