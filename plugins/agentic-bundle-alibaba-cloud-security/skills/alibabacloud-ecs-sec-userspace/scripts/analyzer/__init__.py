"""Analyzer module for sec-userspace.

Lazy loading implementation to avoid importing all 185 heavy analyzers
at module load time. Analyzers are imported on-demand when accessed.

P3 Task 5 (2026-04-22): Extended to use analyzer registry for complete lazy loading.
"""


def __getattr__(name):
    """Lazy load analyzers on demand using the analyzer registry.
    
    This supports two patterns:
    1. Direct class access: ProcessAnalyzer, NetworkAnalyzer, etc.
    2. Registry-based access: Any analyzer in ANALYZER_REGISTRY
    
    P3 Task 5: Now uses registry to avoid hardcoding 185 analyzer mappings.
    """
    # Direct sub-module imports (not analyzers)
    if name in ('config_loader',):
        from importlib import import_module
        return import_module(f'.{name}', __package__)

    # First, try the legacy mapping for backward compatibility
    legacy_mappings = {
        'AnalyzeResult': ('.base', 'AnalyzeResult'),
    }
    
    if name in legacy_mappings:
        module_name, class_name = legacy_mappings[name]
        from importlib import import_module
        module = import_module(module_name, __package__)
        return getattr(module, class_name)
    
    # Try to find in the analyzer registry
    try:
        from .analyzer_registry import ANALYZER_REGISTRY, load_analyzer
        
        # Search for the analyzer name in registry values
        for registry_name, (module_path, class_name) in ANALYZER_REGISTRY.items():
            if class_name == name:
                # Found it, use the registry's lazy loader
                return load_analyzer(registry_name)
        
        # Not found in registry
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    except ImportError:
        # Registry not available, fall through to error
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    """List all available analyzer names for IDE autocompletion.
    
    P3 Task 5: Now dynamically generates list from analyzer registry.
    """
    # Legacy names for backward compatibility
    legacy_names = ['AnalyzeResult']
    
    try:
        from .analyzer_registry import ANALYZER_REGISTRY
        
        # Extract class names from registry
        registry_classes = [class_name for _, (module_path, class_name) in ANALYZER_REGISTRY.items()]
        return legacy_names + registry_classes
    except ImportError:
        return legacy_names


# Build __all__ lazily to avoid circular import on Python 3.6
# On Python 3.7+, __all__ is evaluated lazily by most tools
# On Python 3.6, we provide a static fallback list
try:
    from .analyzer_registry import ANALYZER_REGISTRY
    _legacy_names = ['AnalyzeResult']
    __all__ = _legacy_names  # Will be extended by __dir__ for autocomplete
except ImportError:
    __all__ = ['AnalyzeResult']
