"""
Shared cache management for analyzers.

Module-level: shared result cache and compiled pattern cache functions.
"""
import threading
from typing import Dict, List, Optional


# This allows cross-scan caching when analyzer instances are recreated
_shared_analyzer_cache: Dict = {}
_shared_cache_lock = threading.Lock()

_lazy_init_lock = threading.Lock()

_config_loader = None
def _get_config_loader():
    """Lazy load config_loader to avoid import at module level."""
    global _config_loader
    if _config_loader is None:
        with _lazy_init_lock:
            if _config_loader is None:
                from .. import config_loader
                _config_loader = config_loader
    return _config_loader


def _get_shared_cache_max_size():
    """Get shared cache max size from config or fallback."""
    try:
        loader = _get_config_loader()
        return loader.get_global_cache_config().get("shared_cache_max_size", 256)
    except (ImportError, OSError, ValueError, KeyError, AttributeError):
        return 256


_shared_cache_max_size = _get_shared_cache_max_size()  # Maximum entries in shared cache


_shared_pattern_cache: Dict = {}
_shared_pattern_cache_lock = threading.Lock()


def _get_pattern_cache_max_size():
    """Get pattern cache max size from config or fallback."""
    try:
        loader = _get_config_loader()
        return loader.get_global_cache_config().get("pattern_cache_max_size", 100)
    except (ImportError, OSError, ValueError, KeyError, AttributeError):
        return 100


_pattern_cache_max_size = _get_pattern_cache_max_size()


def get_shared_cache() -> Dict:
    """Get the module-level shared analyzer cache."""
    with _shared_cache_lock:
        return dict(_shared_analyzer_cache)


def clear_shared_cache():
    """Clear the module-level shared cache."""
    with _shared_cache_lock:
        _shared_analyzer_cache.clear()


def set_shared_cache_max_size(size: int):
    """Set the maximum size of the shared cache."""
    global _shared_cache_max_size
    with _shared_cache_lock:
        _shared_cache_max_size = size


def get_shared_cache_max_size() -> int:
    """Get the current maximum size of the shared cache."""
    with _shared_cache_lock:
        return _shared_cache_max_size


def get_shared_pattern_cache() -> Dict:
    """Get the shared compiled pattern cache."""
    with _shared_pattern_cache_lock:
        return dict(_shared_pattern_cache)


def cache_compiled_patterns(pattern_name: str, patterns: List) -> List:
    """Cache compiled regex patterns to avoid recompilation."""
    with _shared_pattern_cache_lock:
        if len(_shared_pattern_cache) >= _pattern_cache_max_size:
            oldest_key = next(iter(_shared_pattern_cache))
            del _shared_pattern_cache[oldest_key]
        _shared_pattern_cache[pattern_name] = patterns
    return patterns


def get_cached_patterns(pattern_name: str) -> Optional[List]:
    """Get cached compiled patterns by name."""
    with _shared_pattern_cache_lock:
        return _shared_pattern_cache.get(pattern_name)


