"""Core modules for sec-userspace scan pipeline.

This package extracts functionality from the monolithic main.py into
focused submodules:

- constants: Global constants and configuration defaults
- cli: Command-line argument parsing
- lifecycle: Signal handling, resource limits, timeout management
- engine: Scan orchestration (collect -> analyze -> report)
- pipeline: Data flow utilities
"""

from .constants import (
    COLLECTOR_PREFERRED_ORDER,
    DEV_ENV_PATHS,
    AI_TOOL_DIRS,
    TEST_KEYWORDS,
    DEFAULT_SCAN_TIMEOUT,
    DEFAULT_CPU_LIMIT,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_RETENTION_DAYS,
)
from .cli import parse_args
from .lifecycle import (
    _get_cpu_limit,
    _get_scan_timeout,
    _calculate_throttle_target,
    setup_resource_limits,
    global_timeout_handler,
    get_global_timeout_flag,
    reset_global_timeout_flag,
)
from .engine import (
    COLLECTORS,
    _get_analyzers,
    run_collectors,
    run_analyzers,
    run_environment_profiling,
)
from .pipeline import (
    get_partial_results,
    reset_partial_results,
    apply_auto_fp_detection,
    compute_fp_statistics,
    generate_whitelist_templates,
    build_correlation_whitelist,
    build_correlation_summary,
)

__all__ = [
    # Constants
    'COLLECTOR_PREFERRED_ORDER',
    'DEV_ENV_PATHS',
    'AI_TOOL_DIRS',
    'TEST_KEYWORDS',
    'DEFAULT_SCAN_TIMEOUT',
    'DEFAULT_CPU_LIMIT',
    'DEFAULT_OUTPUT_DIR',
    'DEFAULT_RETENTION_DAYS',
    # CLI
    'parse_args',
    # Lifecycle
    '_get_cpu_limit',
    '_get_scan_timeout',
    '_calculate_throttle_target',
    'setup_resource_limits',
    'global_timeout_handler',
    'get_global_timeout_flag',
    'reset_global_timeout_flag',
    # Engine
    'COLLECTORS',
    '_get_analyzers',
    'run_collectors',
    'run_analyzers',
    'run_environment_profiling',
    # Pipeline
    'get_partial_results',
    'reset_partial_results',
    'apply_auto_fp_detection',
    'compute_fp_statistics',
    'generate_whitelist_templates',
    'build_correlation_whitelist',
    'build_correlation_summary',
]
