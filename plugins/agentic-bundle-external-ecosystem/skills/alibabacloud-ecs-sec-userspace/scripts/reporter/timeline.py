"""Timeline builder for chronological evidence ordering."""
from datetime import datetime, timezone
import logging
from typing import List, Optional

from .evidence import Evidence
from .severity import Severity
from ..utils.datetime_compat import fromisoformat

logger = logging.getLogger(__name__)


def _parse_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse a timestamp string into a datetime object.

    Handles ISO 8601 format and common variants. Returns None for
    invalid or missing timestamps.

    Args:
        ts: Timestamp string in ISO format or similar, or None.

    Returns:
        Parsed datetime object, or None if parsing fails.
    """
    if not ts:
        return None

    try:
        # Python 3.7+ fromisoformat handles most ISO 8601 variants
        dt = fromisoformat(ts)
        # If naive (no timezone), assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError) as exc:
        logger.debug("Failed to parse timestamp '%s': %s", ts, exc)
        return None


def _severity_name(severity: Severity) -> str:
    """Extract the severity name string from a Severity enum.

    Args:
        severity: Severity enum instance.

    Returns:
        The severity name as a string (e.g., 'CRITICAL', 'HIGH').
    """
    if severity is None:
        return "UNKNOWN"
    if isinstance(severity, Severity):
        return severity.value
    # Fallback: try to get .name or .value attribute
    return str(severity)


def build_timeline(
    evidences: List[Evidence],
    module_stats: Optional[List[dict]] = None,
) -> dict:
    """Build a chronological timeline from evidence objects.

    Sorts all evidences by timestamp (stable sort), placing entries
    with missing or invalid timestamps at the end. Returns a structured
    timeline dict suitable for inclusion in reports.

    Args:
        evidences: List of Evidence objects to include in the timeline.
        module_stats: Optional list of module statistics dicts (each with
            keys like 'name', 'status', 'findings', 'duration'). Included
            in the returned dict for context but not part of the timeline
            entries themselves.

    Returns:
        A dict with keys:
            - 'entries': List of timeline entry dicts sorted chronologically,
              each with keys: timestamp, severity, module, title, attack_id,
              description, confidence, source_path.
            - 'total_entries': Total number of timeline entries.
            - 'module_stats': The module_stats passed in (or empty list).
            - 'time_range': Dict with 'earliest' and 'latest' ISO timestamp
              strings, or None values if no valid timestamps exist.

    Edge cases handled:
        - Empty evidences list → returns empty timeline.
        - None timestamps → sorted to the end.
        - Invalid timestamp formats → treated as None, sorted to end.
        - Missing evidence fields → filled with empty/None defaults.
    """
    if not evidences:
        return {
            "entries": [],
            "total_entries": 0,
            "module_stats": module_stats or [],
            "time_range": {"earliest": None, "latest": None},
        }

    # Build sortable tuples: (datetime_or_none, original_index, evidence)
    # Using original_index as tiebreaker ensures stable sort for equal timestamps.
    parsed: List[tuple] = []
    for idx, ev in enumerate(evidences):
        dt = _parse_timestamp(getattr(ev, "timestamp", None))
        parsed.append((dt, idx, ev))

    # Sort: None timestamps go last (None < datetime is False, so we use a key)
    # Items with valid timestamps sort first by datetime, then by original index.
    # Items with None timestamps sort after all valid ones, by original index.
    def sort_key(item: tuple) -> tuple:
        dt, idx, _ev = item
        # (has_valid_ts, dt_or_zero, idx)
        # False (0) < True (1), so we invert: has_valid=False → 1 (goes last)
        has_valid = dt is not None
        return (not has_valid, dt or datetime.min.replace(tzinfo=timezone.utc), idx)

    parsed.sort(key=sort_key)

    # Build timeline entries
    entries: List[dict] = []
    earliest_dt: Optional[datetime] = None
    latest_dt: Optional[datetime] = None

    for dt, _idx, ev in parsed:
        entry = {
            "timestamp": getattr(ev, "timestamp", None),
            "severity": _severity_name(getattr(ev, "severity", None)),
            "module": getattr(ev, "module", ""),
            "title": getattr(ev, "title", ""),
            "attack_id": getattr(ev, "attack_id", ""),
            "description": getattr(ev, "description", ""),
            "confidence": getattr(ev, "confidence", 0.0),
            "source_path": getattr(ev, "source_path", ""),
        }
        entries.append(entry)

        # Track time range from valid timestamps only
        if dt is not None:
            if earliest_dt is None or dt < earliest_dt:
                earliest_dt = dt
            if latest_dt is None or dt > latest_dt:
                latest_dt = dt

    time_range = {
        "earliest": earliest_dt.isoformat() if earliest_dt else None,
        "latest": latest_dt.isoformat() if latest_dt else None,
    }

    return {
        "entries": entries,
        "total_entries": len(entries),
        "module_stats": module_stats or [],
        "time_range": time_range,
    }
