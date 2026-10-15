"""Whitelist Configuration Loader

Loads and manages whitelist configuration from YAML file.
Provides module-level whitelist control and audit logging settings.
"""
import copy
import os
import logging
import threading
from pathlib import Path
from typing import Dict, Optional, Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logging.getLogger(__name__).warning("PyYAML not available, using default config")

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "whitelist": {
        "enabled": True,
        "modules": {},  # Empty means all modules enabled by default
        "global_bypass": False
    },
    "auto_cleanup": {
        "enabled": True,
        "log_actions": True
    },
    "audit": {
        "enabled": True,
        "log_file": "/var/log/sec-userspace/whitelist-audit.log",
        "max_size_mb": 10,
        "backup_count": 5
    }
}


class WhitelistConfig:
    """Whitelist configuration manager"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize whitelist config

        Args:
            config_path: Path to whitelist_config.yaml (optional)
        """
        self.config_path = config_path or self._find_config_file()
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self._load_config()

    @staticmethod
    def _get_skill_root() -> str:
        """Get skill root directory using path_resolver (works in zipapp and plain mode)."""
        from ..path_resolver import get_skill_root
        return get_skill_root()

    def _find_config_file(self) -> Optional[str]:
        """Find whitelist config file in standard locations

        Returns:
            str: Path to config file or None
        """
        # Check common locations
        possible_paths = [
            # Relative to skill root's configs/ directory (works in both zipapp and plain mode)
            str(Path(self._get_skill_root()) / "configs" / "whitelist_config.yaml"),
            # System-wide
            "/etc/sec-userspace/whitelist_config.yaml",
            # Workspace
            "/data/sec-userspace/workspace/whitelist_config.yaml",
        ]

        for path in possible_paths:
            if os.path.exists(path):
                logger.debug(f"Found whitelist config at: {path}")
                return path

        logger.debug("No whitelist config file found, using defaults")
        return None

    def _load_config(self) -> None:
        """Load configuration from YAML file"""
        if not self.config_path or not os.path.exists(self.config_path):
            logger.info("Using default whitelist configuration")
            return

        if not YAML_AVAILABLE:
            logger.warning("PyYAML not installed, cannot load config file")
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                loaded_config = yaml.safe_load(f)

            if loaded_config:
                # Merge with defaults
                self._merge_config(self.config, loaded_config)
                logger.info(f"Loaded whitelist config from: {self.config_path}")
        except (OSError, ValueError, KeyError) as e:
            logger.error(f"Failed to load whitelist config: {e}")
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in whitelist config: {e}")

    def _merge_config(self, base: Dict, override: Dict) -> None:
        """Recursively merge override into base config

        Args:
            base: Base configuration dict
            override: Override configuration dict
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def is_whitelist_enabled(self) -> bool:
        """Check if whitelist is globally enabled

        Returns:
            bool: True if enabled
        """
        return self.config.get("whitelist", {}).get("enabled", True)

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if whitelist is enabled for specific module

        Args:
            module_name: Analyzer module name

        Returns:
            bool: True if module whitelist is enabled
        """
        if not self.is_whitelist_enabled():
            return False

        modules_config = self.config.get("whitelist", {}).get("modules", {})

        # If no module-specific config, default to enabled
        if not modules_config:
            return True

        # Check module-specific setting
        module_config = modules_config.get(module_name, {})
        if isinstance(module_config, dict):
            return module_config.get("enabled", True)

        return True

    def is_global_bypass(self) -> bool:
        """Check if global bypass is enabled (emergency override)

        Returns:
            bool: True if global bypass is enabled
        """
        return self.config.get("whitelist", {}).get("global_bypass", False)

    def should_auto_cleanup(self) -> bool:
        """Check if automatic cleanup on startup is enabled

        Returns:
            bool: True if auto-cleanup is enabled
        """
        return self.config.get("auto_cleanup", {}).get("enabled", True)

    def should_log_cleanup(self) -> bool:
        """Check if cleanup actions should be logged

        Returns:
            bool: True if cleanup logging is enabled
        """
        return self.config.get("auto_cleanup", {}).get("log_actions", True)

    def is_audit_enabled(self) -> bool:
        """Check if audit logging is enabled

        Returns:
            bool: True if audit logging is enabled
        """
        return self.config.get("audit", {}).get("enabled", True)

    def get_audit_log_path(self) -> str:
        """Get audit log file path

        Returns:
            str: Path to audit log file
        """
        return self.config.get("audit", {}).get("log_file", "/var/log/sec-userspace/whitelist-audit.log")

    def get_config(self) -> Dict[str, Any]:
        """Get full configuration

        Returns:
            dict: Full configuration dictionary
        """
        return self.config.copy()


# Global singleton
_config_instance: Optional[WhitelistConfig] = None
_whitelist_config_lock = threading.Lock()


def get_whitelist_config(config_path: Optional[str] = None) -> WhitelistConfig:
    """Get whitelist config singleton

    Args:
        config_path: Optional path to config file

    Returns:
        WhitelistConfig: Configuration instance
    """
    global _config_instance

    if _config_instance is None:
        with _whitelist_config_lock:
            if _config_instance is None:
                _config_instance = WhitelistConfig(config_path)

    return _config_instance


def reset_config() -> None:
    """Reset config singleton (for testing)"""
    global _config_instance
    with _whitelist_config_lock:
        _config_instance = None
