"""
ConfigMixin: Collector configuration loading and access.

Provides methods to load collector-specific configuration from YAML
and retrieve config values with dotted key path support.
"""


class ConfigMixin:
    """Mixin for collector configuration management."""

    def _load_collector_config(self) -> dict:
        """Load configuration for this collector from collector.yaml.

        Returns:
            Merged config dict (collector-specific > defaults > code defaults)
        """
        try:
            loader = _get_config_loader()
            return loader.get_collector_config(self.name)
        except (ImportError, OSError, ValueError, KeyError) as e:
            if _logger:
                _get_logger().debug(f"[{self.name}] Config load failed: {e}")
            return {}

    def _get_config(self, key: str, default=None):
        """Get a configuration value for this collector.

        Falls back to the provided default if the key is not in the config.
        Subclasses use this to replace hardcoded values.

        Args:
            key: Configuration key (e.g., 'timeout', 'max_lines', 'paths.auth_log')
            default: Default value if key not found

        Returns:
            Config value or default
        """
        if not self._config:
            return default

        # Support dotted key paths like 'paths.auth_log'
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


import threading

_lazy_init_lock = threading.Lock()

_logger = None
_config_loader = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


def _get_config_loader():
    """Lazy load config_loader to avoid import at module level."""
    global _config_loader
    if _config_loader is None:
        with _lazy_init_lock:
            if _config_loader is None:
                from .. import config_loader
                _config_loader = config_loader
    return _config_loader
