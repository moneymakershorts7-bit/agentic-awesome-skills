"""Pipeline: data flow utilities for collect → analyze → report."""
import logging
import threading
from collections import defaultdict
from typing import Dict, Any

# ── Constants (duplicated from main.py for pipeline independence) ─────

DEV_ENV_PATHS = frozenset([
    '.qoder_cli', '.cursor', '.vscode', '.idea', '.claude',
    '.git/hooks', '__pycache__', '.cache',
    'node_modules', '.npm', '.bun', '.yarn', '.cargo',
    '.venv', 'venv', 'virtualenv',
    'dev', 'staging', 'example', 'demo', 'sample',
    'template', 'fixture', 'mock', 'test', 'tests',
    'testing', 'sandbox', 'playground',
    'build', 'dist', 'out', 'target', 'bin', 'obj',
    'docs', 'documentation', 'examples', 'tutorials',
])

AI_TOOL_DIRS = ['.qoder', '.cursor', '.claude', '.vscode', '.idea']
TEST_KEYWORDS = ['test', 'example', 'sample', 'demo', 'fixture', 'mock']


# ── Partial results ──────────────────────────────────────────────────

_partial_results: Dict[str, Any] = {
    "collected_data": {},
    "evidences": [],
    "module_stats": [],
    "system_info": {},
}
_partial_results_lock = threading.Lock()


def get_partial_results() -> Dict[str, Any]:
    """Get shared partial results dict (for timeout handler use)."""
    with _partial_results_lock:
        return dict(_partial_results)


def reset_partial_results():
    """Reset partial results (for testing)."""
    global _partial_results
    with _partial_results_lock:
        _partial_results = {
            "collected_data": {},
            "evidences": [],
            "module_stats": [],
            "system_info": {},
        }


# ── FP detection ─────────────────────────────────────────────────────

def apply_auto_fp_detection(evidences: list) -> list:
    """Apply auto-FP detection to all evidences as post-processing."""
    for evidence in evidences:
        if evidence.verified_status != "pending":
            continue

        source_lower = evidence.source_path.lower() if evidence.source_path else ""
        title_lower = evidence.title.lower() if evidence.title else ""

        fp_reason = ""

        for dev_path in DEV_ENV_PATHS:
            if dev_path.lower() in source_lower:
                fp_reason = f"Located in development environment directory: {dev_path}"
                break

        if not fp_reason:
            for ai_dir in AI_TOOL_DIRS:
                if ai_dir in source_lower:
                    fp_reason = f"Located in AI tool configuration directory: {ai_dir}"
                    break

        if not fp_reason:
            for keyword in TEST_KEYWORDS:
                if keyword in source_lower or keyword in title_lower:
                    fp_reason = f"Contains test/example keyword: {keyword}"
                    break

        if fp_reason:
            evidence.verified_status = "likely_fp"
            if not evidence.raw_data:
                evidence.raw_data = {}
            evidence.raw_data["fp_reason"] = fp_reason

    return evidences


def compute_fp_statistics(evidences: list) -> dict:
    """Compute FP statistics per module for report dashboard."""
    module_stats = defaultdict(lambda: {"total": 0, "pending": 0, "likely_fp": 0,
                                         "confirmed_tp": 0, "whitelisted": 0})
    for e in evidences:
        stats = module_stats[e.module]
        stats["total"] += 1
        status = e.verified_status or "pending"
        if status in stats:
            stats[status] += 1

    result = {}
    for module, stats in module_stats.items():
        fp_rate = stats["likely_fp"] / stats["total"] if stats["total"] > 0 else 0.0
        result[module] = {
            "total": stats["total"],
            "pending": stats["pending"],
            "likely_fp": stats["likely_fp"],
            "confirmed_tp": stats["confirmed_tp"],
            "whitelisted": stats["whitelisted"],
            "fp_rate": round(fp_rate, 4),
        }

    return result


def generate_whitelist_templates(evidences: list) -> list:
    """Generate whitelist entry templates for likely_fp evidences."""
    templates = []
    seen = set()

    for e in evidences:
        if e.verified_status != "likely_fp":
            continue

        pattern = e.source_path if e.source_path else e.title
        dedup_key = (e.module, pattern)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        fp_reason = ""
        if isinstance(e.raw_data, dict):
            fp_reason = e.raw_data.get("fp_reason", "")

        templates.append({
            "module": e.module,
            "pattern": pattern,
            "reason": fp_reason or f"Auto-detected likely FP: {e.title}",
            "added_by": "auto_suggestion",
            "evidence_title": e.title,
            "severity": e.severity.value,
        })

    return templates


# ── Correlation helpers ──────────────────────────────────────────────

def build_correlation_whitelist(args) -> dict:
    """Build whitelist entities for correlation filtering."""
    whitelist_entities = {"pid": set(), "ip": set(), "path": set()}

    try:
        from ..utils.whitelist import get_whitelist_manager, detect_environment

        workspace_dir = getattr(args, 'output_dir', '/data/sec-userspace/workspace')
        env = detect_environment()
        wl_manager = get_whitelist_manager(workspace_dir, env)

        for entry in wl_manager.entries:
            if not entry.enabled or entry.is_expired():
                continue
            if entry.module in ("process_analyzer", "malware_analyzer"):
                whitelist_entities["path"].add(entry.pattern)
            elif entry.module in ("network_analyzer",):
                whitelist_entities["ip"].add(entry.pattern)

        whitelist_entities["pid"].update({"1", "2"})

    except (ImportError, AttributeError, KeyError, TypeError) as e:
        logging.getLogger(__name__).debug(f"Failed to build correlation whitelist: {e}")

    return whitelist_entities


def build_correlation_summary(correlator, stats: dict) -> dict:
    """Build correlation summary for reports from cross-analyzer correlator."""
    groups = correlator.get_correlated_groups()
    group_summaries = []

    for grp in groups:
        group_summaries.append({
            "group_id": grp.group_id,
            "entity_key": grp.entity_key,
            "entity_type": grp.entity_type,
            "analyzers": sorted(list(grp.analyzers)),
            "attack_ids": sorted(list(grp.attack_ids)),
            "max_severity": grp.max_severity.value,
            "correlation_strength": round(grp.correlation_strength, 2),
            "evidence_ids": [ev.id for ev in grp.evidences],
            "evidence_count": grp.evidence_count,
        })

    return {
        "total_groups": stats.get("total_groups", 0),
        "cross_analyzer_groups": stats.get("cross_analyzer_groups", 0),
        "correlated_groups": stats.get("correlated_groups", 0),
        "upgraded_count": stats.get("upgraded_count", 0),
        "isolated_count": stats.get("isolated_count", 0),
        "correlation_rate": stats.get("correlation_rate", 0.0),
        "groups": group_summaries,
    }


# ── Exports ──────────────────────────────────────────────────────────

__all__ = [
    'get_partial_results',
    'reset_partial_results',
    'apply_auto_fp_detection',
    'compute_fp_statistics',
    'generate_whitelist_templates',
    'build_correlation_whitelist',
    'build_correlation_summary',
]
