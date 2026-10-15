"""Collector Registry - Dynamic discovery and lazy loading for collectors.

This module dynamically discovers all collector modules in the collector directory
using pkgutil.iter_modules(), replacing the previous hardcoded registry.

Usage:
    from .collector.collector_registry import COLLECTOR_REGISTRY, load_collector

    # Load specific collector on demand
    collector_class = load_collector("process")
    collector = collector_class()
"""
import os
import pkgutil
import logging
import threading
from importlib import import_module
from typing import Dict, Tuple, Type

logger = logging.getLogger("sec-userspace")

# Modules that are NOT collectors (utility/infrastructure modules)
_SKIP_MODULES = frozenset({
    'base',
    'collector_registry',
    'data_validator',
})


def _discover_collectors() -> Dict[str, Tuple[str, str]]:
    """Dynamically discover all collector modules and their classes.

    Scans the collector directory for .py files, imports each module,
    and finds classes that inherit from BaseCollector.

    Returns:
        Dict mapping collector name -> (module_path, class_name)
    """
    registry = {}
    package_dir = os.path.dirname(__file__)
    package_name = __name__.rsplit('.', 1)[0]  # scripts.collector

    for importer, modname, ispkg in pkgutil.iter_modules([package_dir]):
        # Skip packages (directories)
        if ispkg:
            continue
        # Skip private/internal modules
        if modname.startswith('_'):
            continue
        # Skip disabled modules
        if modname.startswith('disabled'):
            continue
        # Skip known non-collector modules
        if modname in _SKIP_MODULES:
            continue

        full_module_path = f"{package_name}.{modname}"

        try:
            module = import_module(full_module_path)
        except (ImportError, SyntaxError, AttributeError) as e:
            logger.warning(f"[collector_registry] Failed to import {full_module_path}: {e}")
            continue

        # Find BaseCollector subclasses in the module
        try:
            # Lazy import to avoid circular dependency
            from .base import BaseCollector

            for attr_name in dir(module):
                if attr_name.startswith('_'):
                    continue
                try:
                    attr = getattr(module, attr_name, None)
                    if (attr is not None
                            and isinstance(attr, type)
                            and issubclass(attr, BaseCollector)
                            and attr is not BaseCollector
                            and attr.__module__ == module.__name__):
                        # Derive a short name from the module name
                        # e.g. "process" from "process.py", "package_history_collector" -> "package_history"
                        short_name = modname
                        if short_name.endswith('_collector'):
                            short_name = short_name[:-10]  # Remove _collector suffix

                        registry[short_name] = (full_module_path, attr_name)
                        logger.debug(f"[collector_registry] Discovered collector: {short_name} -> {full_module_path}.{attr_name}")
                        break  # One collector per module
                except (TypeError, AttributeError) as e:
                    logger.debug(f"[collector_registry] Skipping attr {attr_name} in {modname}: {e}")
                    continue
        except ImportError:
            logger.warning(f"[collector_registry] Cannot import BaseCollector for inspection, skipping {modname}")
            continue

    return registry


# Build registry on first access via module-level discovery
COLLECTOR_REGISTRY: Dict[str, Tuple[str, str]] = _discover_collectors()

# Cache for loaded collector classes
_loaded_collectors: Dict[str, Type] = {}
_collector_load_lock = threading.Lock()


def load_collector(name: str) -> Type:
    """Lazy load a collector class by name.

    Args:
        name: Collector name (e.g., "process")

    Returns:
        Collector class

    Raises:
        KeyError: If collector name not found in registry
        ImportError: If module cannot be imported
        AttributeError: If class not found in module
    """
    if name in _loaded_collectors:
        return _loaded_collectors[name]

    with _collector_load_lock:
        if name in _loaded_collectors:
            return _loaded_collectors[name]

        if name not in COLLECTOR_REGISTRY:
            raise KeyError(f"Collector '{name}' not found in registry. Available: {list(COLLECTOR_REGISTRY.keys())}")

        module_path, class_name = COLLECTOR_REGISTRY[name]

        try:
            module = import_module(module_path)
            collector_class = getattr(module, class_name)
            _loaded_collectors[name] = collector_class
            logger.debug(f"Loaded collector: {name} from {module_path}.{class_name}")
            return collector_class
        except ImportError as e:
            logger.error(f"Failed to import module {module_path} for collector {name}: {e}")
            raise
        except AttributeError as e:
            logger.error(f"Class {class_name} not found in module {module_path}: {e}")
            raise


def load_collectors(names: list) -> list:
    """Lazy load multiple collector classes.

    Args:
        names: List of collector names

    Returns:
        List of (name, class) tuples
    """
    result = []
    for name in names:
        try:
            cls = load_collector(name)
            result.append((name, cls))
        except (ImportError, AttributeError, KeyError) as e:
            logger.warning(f"Skipping collector {name}: {e}")
    return result


def get_available_collectors() -> list:
    """Get list of all available collector names.

    Returns:
        List of collector names
    """
    return list(COLLECTOR_REGISTRY.keys())
