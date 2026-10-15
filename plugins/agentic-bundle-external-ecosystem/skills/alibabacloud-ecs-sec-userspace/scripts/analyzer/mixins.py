"""
Analyzer mixins for reusable functionality - Backward Compatibility Layer

This file re-exports all mixins from the mixins/ package.
All imports from `.mixins` will continue to work without changes.

New code should import directly from the mixins/ subpackage:
    from .mixins.evidence import EvidenceMixin
    from .mixins.caching import CacheMixin
    etc.
"""

# Re-export everything from the mixins package
from .mixins import (
    # Mixins
    DataExtractionMixin,
    EvidenceMixin,
    ThrottleMixin,
    EnvAwareMixin,
    ValidationMixin,
    StreamingMixin,
    ConfigMixin,
    # Shared cache functions
    get_shared_cache,
    clear_shared_cache,
    set_shared_cache_max_size,
    get_shared_cache_max_size,
    get_shared_pattern_cache,
    cache_compiled_patterns,
    get_cached_patterns,
    # Environment functions
    set_skip_expensive_flag,
    get_skip_expensive_flag,
    EXPENSIVE_ANALYZER_THRESHOLD,
    DEV_ENV_PATH_PATTERNS,
    DEV_ENV_HOSTNAME_PATTERNS,
    # Internal symbols needed by base.py
    _shared_analyzer_cache,
    _shared_cache_lock,
    _shared_cache_max_size,
    _shared_pattern_cache,
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
    # Environment functions
    'set_skip_expensive_flag',
    'get_skip_expensive_flag',
    'EXPENSIVE_ANALYZER_THRESHOLD',
    'DEV_ENV_PATH_PATTERNS',
    'DEV_ENV_HOSTNAME_PATTERNS',
]
