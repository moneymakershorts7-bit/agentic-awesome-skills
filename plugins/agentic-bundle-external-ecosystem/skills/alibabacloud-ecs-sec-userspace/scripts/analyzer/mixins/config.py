"""
ConfigMixin: Configuration loading and access for analyzers.

Extracted from BaseAnalyzer to modularize configuration functionality.
Methods: _load_analyzer_config, _get_config, _get_global_config
"""
import threading

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

_logger = None
def _get_logger():
    """Lazy logger initialization."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


class ConfigMixin:
    """Mixin providing configuration loading and access for analyzers."""

    def _load_analyzer_config(self) -> dict:
        """Load configuration for this analyzer from analyzer.yaml.

        Returns:
            Merged config dict (analyzer-specific > defaults > code defaults)
        """
        try:
            loader = _get_config_loader()
            return loader.get_analyzer_config(self.name)
        except (ImportError, OSError, ValueError, KeyError) as e:
            # Config loading failure should not break analysis
            if _logger:
                _get_logger().debug(f"[{self.name}] Config load failed: {e}")
            return {}

    def _get_config(self, key: str, default=None):
        """Get a configuration value for this analyzer.

        Falls back to the provided default if the key is not in the config.
        Subclasses use this to replace hardcoded values.

        Args:
            key: Configuration key (e.g., 'timeout', 'thresholds.max_package_checks')
            default: Default value if key not found

        Returns:
            Config value or default
        """
        if not self._config:
            return default

        # Support dotted key paths like 'thresholds.max_package_checks'
        if '.' in key:
            parts = key.split('.')
            value = self._config
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return default
            return value

        return self._config.get(key, default)

    def _get_global_config(self, key: str, default=None):
        """Get a global configuration value from analyzer.yaml.

        These are values from the top-level sections (cache, memory, load_adaptive, paths)
        that apply to all analyzers.

        Args:
            key: Configuration key with section prefix (e.g., 'cache.shared_cache_max_size')
            default: Default value if key not found

        Returns:
            Config value or default
        """
        try:
            loader = _get_config_loader()
            parts = key.split('.', 1)
            if len(parts) == 2:
                section, subkey = parts
                if section == 'cache':
                    cfg = loader.get_global_cache_config()
                elif section == 'memory':
                    cfg = loader.get_global_memory_config()
                elif section == 'load_adaptive':
                    cfg = loader.get_load_adaptive_config()
                elif section == 'paths':
                    cfg = loader.get_global_paths_config()
                else:
                    return default

                # Support nested dotted paths within section
                if '.' in subkey:
                    subparts = subkey.split('.')
                    value = cfg
                    for subpart in subparts:
                        if isinstance(value, dict) and subpart in value:
                            value = value[subpart]
                        else:
                            return default
                    return value
                return cfg.get(subkey, default)
            return default
        except (ImportError, OSError, ValueError, KeyError, AttributeError) as e:
            if _logger:
                _get_logger().debug(f"[{self.name}] Global config load failed: {e}")
            return default
