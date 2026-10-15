"""Analyzer Registry - Dynamic discovery and lazy loading.

This module provides automatic discovery of security analyzers by scanning
the analyzer directory, enabling lazy loading to reduce memory usage.

Usage:
    from .analyzer.analyzer_registry import ANALYZER_REGISTRY, load_analyzer

    # Load specific analyzer on demand
    analyzer_class = load_analyzer("process_analyzer")
    analyzer = analyzer_class()

Dynamic Discovery:
    - Scans all .py and .pyc files in the analyzer directory
    - Supports both source mode (.py) and compiled/zipapp mode (.pyc)
    - Uses pkgutil for zipapp compatibility (zipimport paths)
    - Automatically finds classes inheriting from BaseAnalyzer
    - Files moved to disabled_*/ or backup/ are auto-excluded
    - New analyzer files are auto-registered
"""
from importlib import import_module
from pathlib import Path
from typing import Dict, Tuple, Type, List, Optional
import pkgutil
import sys
import time
import inspect
import threading

_logger = None
_logger_lock = threading.Lock()


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


# ============================================================
# Dynamic Analyzer Discovery
# ============================================================

# Files/patterns to skip during auto-discovery
SKIP_PATTERNS = frozenset([
    '__init__',
    'base',
    'mixins',
    'analyzer_registry',
    'preloader',
    'config_loader',
    # Utility/helper modules, not analyzers
    'crypto_utils',
    'cloud_service_whitelist',
    'cicd_detector',
    'container_environment_detector',
    # Network analyzer sub-package (implementation split into modules)
    'network',
    # Lateral movement analyzer sub-package (implementation split into modules)
    'lateral_movement',
    # Cilium runtime security analyzer sub-package (implementation split into modules)
    'cilium',
    # Memory forensics analyzer sub-package (implementation split into modules)
    'memory',
])


def _should_skip_file(filename: str) -> bool:
    """Check if file should be skipped from auto-registration.
    
    Args:
        filename: Python module filename without .py extension
        
    Returns:
        True if file should be skipped
    """
    # Skip known special files
    if filename in SKIP_PATTERNS:
        return True
    
    # Skip disabled/backup directories or files
    if filename.startswith('disabled') or 'backup' in filename:
        return True
    
    # Skip test files
    if filename.endswith('_test') or filename.startswith('test_'):
        return True
    
    return False


def scan_analyzer_directory() -> Dict[str, Tuple[str, str]]:
    """Scan analyzer directory and build registry dynamically.

    Discovers analyzer modules using pkgutil.iter_modules, which works
    with both filesystem paths and zipimport (zipapp) paths.

    Supports both source (.py) and compiled (.pyc) deployments:
    - Source mode: discovers analyzers via filesystem .py files
    - Compiled mode (zipapp/compileall): discovers analyzers via pkgutil

    Returns:
        Dict mapping analyzer_name -> (module_path, class_name)
    """
    from .base import BaseAnalyzer

    registry = {}

    # Use pkgutil to discover submodules - works with both filesystem and zipimport
    # pkgutil.iter_modules correctly handles zipapp archives
    try:
        pkg_path = getattr(sys.modules.get(__package__), '__path__', None)
        if pkg_path is None:
            pkg_path = [str(Path(__file__).parent)]

        module_names = set()
        for importer, modname, ispkg in pkgutil.iter_modules(pkg_path):
            if not _should_skip_file(modname):
                module_names.add(modname)
    except ImportError:
        # Fallback: filesystem scan for .py and .pyc files
        analyzer_dir = Path(__file__).parent
        module_names = set()
        for f in analyzer_dir.glob('*.py'):
            if not _should_skip_file(f.stem):
                module_names.add(f.stem)
        for f in analyzer_dir.glob('*.pyc'):
            if not _should_skip_file(f.stem):
                module_names.add(f.stem)

    for filename in sorted(module_names):
        module_name = f"scripts.analyzer.{filename}"

        try:
            # Import module (works for both .py and .pyc via zipimport)
            module = import_module(module_name)

            # Find BaseAnalyzer subclasses
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Must be subclass of BaseAnalyzer
                if not issubclass(obj, BaseAnalyzer):
                    continue

                # Must be defined in this module (not imported)
                if obj.__module__ != module_name:
                    continue

                # Skip the BaseAnalyzer class itself
                if name == 'BaseAnalyzer':
                    continue

                # Found the analyzer class
                registry[filename] = (module_name, name)
                break  # One analyzer class per file (take the first match)

        except (ImportError, OSError, ValueError, AttributeError, TypeError) as e:
            _get_logger().warning(f"Failed to scan analyzer {module_name}: {e}")

    _get_logger().info(f"Dynamic analyzer discovery: found {len(registry)} analyzers")
    return registry


# ============================================================
# Registry Cache and Public API
# ============================================================

# Cache for the dynamically built registry
_registry_cache: Optional[Dict[str, Tuple[str, str]]] = None
_registry_lock = threading.Lock()

# Import timing metrics storage
_import_times: Dict[str, float] = {}

# Cache for loaded analyzer classes
_loaded_analyzers: Dict[str, Type] = {}


def _get_registry() -> Dict[str, Tuple[str, str]]:
    """Get analyzer registry, building it if needed.

    Uses double-check locking for thread safety.

    Returns:
        Dict mapping analyzer_name -> (module_path, class_name)
    """
    global _registry_cache
    if _registry_cache is None:
        with _registry_lock:
            if _registry_cache is None:
                _registry_cache = scan_analyzer_directory()
    return _registry_cache


def rebuild_registry() -> Dict[str, Tuple[str, str]]:
    """Force rebuild the registry (for testing or hot-reload).

    Returns:
        Dict mapping analyzer_name -> (module_path, class_name)
    """
    global _registry_cache, _loaded_analyzers
    with _registry_lock:
        _registry_cache = scan_analyzer_directory()
        _loaded_analyzers.clear()
    return _registry_cache


# Backward-compatible public API: ANALYZER_REGISTRY
# This is lazily evaluated on first access via property-like pattern
# For direct dict access compatibility, we build it once at module load
# but defer the heavy scanning until actually needed.
class _RegistryProxy:
    """Proxy object that builds registry on first access."""

    def __init__(self):
        self._data = None
        self._lock = threading.Lock()

    def _ensure_loaded(self):
        if self._data is None:
            with self._lock:
                if self._data is None:
                    self._data = _get_registry()

    def __getitem__(self, key):
        self._ensure_loaded()
        return self._data[key]

    def __setitem__(self, key, value):
        self._ensure_loaded()
        self._data[key] = value

    def __delitem__(self, key):
        self._ensure_loaded()
        del self._data[key]

    def __contains__(self, key):
        self._ensure_loaded()
        return key in self._data

    def __iter__(self):
        self._ensure_loaded()
        return iter(self._data)

    def __len__(self):
        self._ensure_loaded()
        return len(self._data)

    def __repr__(self):
        self._ensure_loaded()
        return repr(self._data)

    def keys(self):
        self._ensure_loaded()
        return self._data.keys()

    def values(self):
        self._ensure_loaded()
        return self._data.values()

    def items(self):
        self._ensure_loaded()
        return self._data.items()

    def get(self, key, default=None):
        self._ensure_loaded()
        return self._data.get(key, default)


# Public registry object (backward compatible)
ANALYZER_REGISTRY = _RegistryProxy()


def load_analyzer(name: str) -> Type:
    """Lazy load an analyzer class by name.

    Args:
        name: Analyzer name (e.g., "process_analyzer")

    Returns:
        Analyzer class

    Raises:
        KeyError: If analyzer name not found in registry
        ImportError: If module cannot be imported
        AttributeError: If class not found in module
    """
    with _registry_lock:
        if name in _loaded_analyzers:
            return _loaded_analyzers[name]

        if name not in ANALYZER_REGISTRY:
            raise KeyError(f"Analyzer '{name}' not found in registry. Available: {list(ANALYZER_REGISTRY.keys())}")

        module_path, class_name = ANALYZER_REGISTRY[name]

    try:
        start_time = time.monotonic()
        module = import_module(module_path)
        analyzer_class = getattr(module, class_name)
        elapsed = time.monotonic() - start_time

        with _registry_lock:
            _loaded_analyzers[name] = analyzer_class
            _import_times[name] = elapsed

        _get_logger().debug(f"Loaded analyzer: {name} from {module_path}.{class_name} ({elapsed:.3f}s)")
        return analyzer_class
    except ImportError as e:
        _get_logger().error(f"Failed to import module {module_path} for analyzer {name}: {e}")
        raise
    except AttributeError as e:
        _get_logger().error(f"Class {class_name} not found in module {module_path}: {e}")
        raise


def load_analyzers(names: list) -> list:
    """Lazy load multiple analyzer classes.

    Args:
        names: List of analyzer names

    Returns:
        List of (name, class) tuples
    """
    result = []
    for name in names:
        try:
            cls = load_analyzer(name)
            result.append((name, cls))
        except (ImportError, AttributeError, KeyError) as e:
            _get_logger().warning(f"Skipping analyzer {name}: {e}")
    return result


def get_available_analyzers() -> list:
    """Get list of all available analyzer names.

    Returns:
        List of analyzer names
    """
    return list(ANALYZER_REGISTRY.keys())


def get_import_timing() -> Dict[str, float]:
    """Get import timing metrics for loaded analyzers.

    Returns:
        Dict mapping analyzer name to import time in seconds
    """
    with _registry_lock:
        return dict(_import_times)


def get_slow_analyzers(threshold: float = 1.0) -> List[Tuple[str, float]]:
    """Get analyzers that exceeded import time threshold.

    Args:
        threshold: Time threshold in seconds

    Returns:
        List of (analyzer_name, import_time) tuples sorted by time descending
    """
    with _registry_lock:
        snapshot = dict(_import_times)
    slow = [(name, t) for name, t in snapshot.items() if t > threshold]
    return sorted(slow, key=lambda x: x[1], reverse=True)


def preload_analyzers(analyzer_names: List[str]) -> Dict[str, float]:
    """Pre-import all analyzers sequentially.

    Args:
        analyzer_names: List of analyzer names to preload

    Returns:
        Dict mapping analyzer name to import time in seconds (-1.0 for failures)
    """
    load_times = {}

    for name in analyzer_names:
        if name not in ANALYZER_REGISTRY:
            _get_logger().warning("Analyzer {} not found in registry, skipping".format(name))
            load_times[name] = -1.0
            continue

        with _registry_lock:
            already_loaded = name in _loaded_analyzers
        if already_loaded:
            load_times[name] = 0.0
            continue

        try:
            elapsed = _preload_single_analyzer(name)
            load_times[name] = elapsed
            _get_logger().debug("Preloaded analyzer: {} ({:.3f}s)".format(name, elapsed))
        except (ImportError, OSError, ValueError, AttributeError, TypeError) as e:
            _get_logger().error("Failed to preload analyzer {}: {}".format(name, e))
            load_times[name] = -1.0

    total_time = sum(t for t in load_times.values() if t > 0)
    _get_logger().info(
        "Preloaded {}/{} analyzers in {:.3f}s".format(
            len([t for t in load_times.values() if t > 0]),
            len(analyzer_names),
            total_time
        )
    )

    return load_times


def _preload_single_analyzer(name: str) -> float:
    """Preload a single analyzer and return load time.

    Args:
        name: Analyzer name

    Returns:
        Load time in seconds
    """
    start_time = time.monotonic()
    load_analyzer(name)
    elapsed = time.monotonic() - start_time
    return elapsed


def build_analyzer_list_from_registry() -> list:
    """Build complete analyzer list from registry.

    Returns:
        List of (name, class) tuples for all registered analyzers
    """
    return load_analyzers(list(ANALYZER_REGISTRY.keys()))


# Analyzer priority order for execution
ANALYZER_PRIORITY_ORDER = [
    "process_analyzer",
    "network_analyzer",
    "auth_analyzer",
    "file_analyzer",
    "rootkit_analyzer",
]


def reset_registry_state():
    """Reset all registry global state. For testing only."""
    global _import_times, _loaded_analyzers, _registry_cache
    with _registry_lock:
        _import_times.clear()
        _loaded_analyzers.clear()
        _registry_cache = None
