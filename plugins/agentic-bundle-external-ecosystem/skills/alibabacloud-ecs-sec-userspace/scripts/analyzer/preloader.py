"""Analyzer dependency preloader (removed - sequential execution only).

Preloading has been removed as part of the architecture simplification.
All functions are no-ops to maintain import compatibility with tests.
"""


def preload_analyzer_dependencies(mode='full', **kwargs):
    """No-op: preloading removed."""
    return {}


def is_analyzer_preloaded(name):
    """No-op: always returns False."""
    return False


def validate_preload_completion(analyzer_names):
    """No-op: always returns success."""
    return {"warning": False, "completion_rate": 1.0, "missing": [], "loaded": list(analyzer_names)}


def get_preload_stats():
    """Return empty stats."""
    return {
        "total_preload_time": 0.0,
        "analyzers_preloaded": 0,
        "preload_failed": 0,
        "preload_skipped": True,
        "import_times": {},
        "slow_analyzers": [],
        "preload_started": False,
        "preload_completed": True,
        "preloaded_analyzers": [],
    }


def reset_preload_state():
    """No-op: nothing to reset."""


def get_preload_completion_status():
    """Return completed status."""
    return {
        "status": "skipped",
        "timeout_reason": None,
        "preload_started": False,
        "preload_completed": True,
        "preload_skipped": True,
        "preloaded_analyzers": [],
        "total_preload_time": 0.0,
        "analyzers_preloaded": 0,
        "preload_failed": 0,
    }


def is_preload_completed():
    """Always True."""
    return True


def get_module_import_cache_stats():
    """Return empty stats."""
    return {"loaded_modules": 0, "sec_inspect_modules": 0, "sec_module_names": []}
