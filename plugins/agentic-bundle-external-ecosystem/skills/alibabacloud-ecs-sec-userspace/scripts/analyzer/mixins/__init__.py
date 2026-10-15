"""
Analyzer mixins package - provides reusable functionality for BaseAnalyzer.

All mixins are exported here for backward compatibility.
The original mixins.py imports from this package.
"""

from .data_extraction import DataExtractionMixin
from .evidence import EvidenceMixin
from .throttling import ThrottleMixin
from .environment import EnvAwareMixin
from .validation import ValidationMixin
from .streaming import StreamingMixin
from .config import ConfigMixin

# Re-export shared cache management functions from caching module
from .caching import (
    get_shared_cache,
    clear_shared_cache,
    set_shared_cache_max_size,
    get_shared_cache_max_size,
    get_shared_pattern_cache,
    cache_compiled_patterns,
    get_cached_patterns,
    # Internal symbols needed by base.py
    _shared_analyzer_cache,
    _shared_cache_lock,
    _shared_cache_max_size,
    _shared_pattern_cache,
)

# Re-export environment management functions
from .environment import (
    set_skip_expensive_flag,
    get_skip_expensive_flag,
    EXPENSIVE_ANALYZER_THRESHOLD,
    DEV_ENV_PATH_PATTERNS,
    DEV_ENV_HOSTNAME_PATTERNS,
    # Internal symbols needed by base.py
    _skip_expensive_flag,
)

__all__ = [
    # Mixins
    'DataExtractionMixin',
    'EvidenceMixin',
    'ThrottleMixin',
    'EnvAwareMixin',
    'ValidationMixin',
    'StreamingMixin',
    'ConfigMixin',
    # Shared cache functions
    'get_shared_cache',
    'clear_shared_cache',
    'set_shared_cache_max_size',
    'get_shared_cache_max_size',
    'get_shared_pattern_cache',
    'cache_compiled_patterns',
    'get_cached_patterns',
    # Internal cache variables (for backward compatibility)
    '_shared_analyzer_cache',
    '_shared_cache_lock',
    '_shared_cache_max_size',
    '_shared_pattern_cache',
    # Environment functions
    'set_skip_expensive_flag',
    'get_skip_expensive_flag',
    'EXPENSIVE_ANALYZER_THRESHOLD',
    'DEV_ENV_PATH_PATTERNS',
    'DEV_ENV_HOSTNAME_PATTERNS',
    # Internal environment variable (for backward compatibility)
    '_skip_expensive_flag',
]
