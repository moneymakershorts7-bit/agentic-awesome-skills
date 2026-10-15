"""Python 3.6 compatible datetime.fromisoformat replacement."""
from datetime import datetime


def fromisoformat(ts):
    """Parse ISO 8601 timestamp, compatible with Python 3.6+.

    Handles:
    - '2024-01-01T12:00:00' (no timezone)
    - '2024-01-01T12:00:00+00:00' (with timezone)
    - '2024-01-01T12:00:00Z' (Z suffix)
    """
    if hasattr(datetime, 'fromisoformat'):
        # Python 3.7+: use native, but handle 'Z' suffix
        if isinstance(ts, str) and ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
        return datetime.fromisoformat(ts)
    # Python 3.6 fallback: manual parsing
    if isinstance(ts, str) and ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    for fmt in (
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
    ):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError("Cannot parse ISO timestamp: {}".format(ts))


def date_fromisoformat(ts):
    """Python 3.6 compatible date.fromisoformat."""
    from datetime import date
    if hasattr(date, 'fromisoformat'):
        return date.fromisoformat(ts)
    return datetime.strptime(ts, '%Y-%m-%d').date()
