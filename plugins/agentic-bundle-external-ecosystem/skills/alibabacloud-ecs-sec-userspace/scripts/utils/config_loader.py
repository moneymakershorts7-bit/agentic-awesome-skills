"""Unified config loader — YAML only

Loads sec-userspace configuration from configs/sec-userspace.yaml.
Provides convenient accessors for server, IoC, scan, and logging settings.

Priority chain: CLI args > config file > built-in defaults
"""

import copy
import logging
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger("sec-userspace")

# Built-in defaults (mirror configs/sec-userspace.yaml)
_DEFAULT_CONFIG: Dict[str, Any] = {
    "server": {
        "endpoint": "",
        "api_version": "v1",
        "timeout": 30,
        "retry": 3,
    },
    "ioc": {
        "local_db": "assets/ioc",
        "auto_update": False,
        "update_interval": 3600,
    },
    "scan": {
        "output_dir": "/tmp/sec-userspace",
        "format": "both",
        "skip_expensive": False,
    },
    "logging": {
        "level": "INFO",
        "quiet": False,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*. Returns merged dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _find_config_file() -> Optional[Path]:
    """Locate sec-userspace.yaml relative to this module's package root."""
    from .path_resolver import get_skill_root, get_scripts_dir
    skill_root = Path(get_skill_root())
    candidate = skill_root / "configs" / "sec-userspace.yaml"
    if candidate.exists():
        return candidate
    # Fallback: relative to scripts dir itself
    scripts_dir = Path(get_scripts_dir())
    candidate = scripts_dir / "configs" / "sec-userspace.yaml"
    if candidate.exists():
        return candidate
    return None


def load_config(config_path: Optional[str] = None) -> dict:
    """Load sec-userspace main config file.

    Lookup order:
    1. *config_path* if explicitly provided
    2. configs/sec-userspace.yaml (relative to skill root)
    3. Built-in defaults

    Returns:
        Merged configuration dictionary
    """
    defaults = copy.deepcopy(_DEFAULT_CONFIG)

    target = None
    if config_path:
        target = Path(config_path)
        if not target.exists():
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return defaults
    else:
        found = _find_config_file()
        if found:
            target = found
        else:
            logger.debug("No config file found, using defaults")
            return defaults

    if not _YAML_AVAILABLE:
        logger.warning("PyYAML not available, using defaults")
        return defaults

    try:
        with open(target, "r", encoding="utf-8") as fh:
            file_data = yaml.safe_load(fh)
        if not file_data or not isinstance(file_data, dict):
            logger.debug("Config file empty or invalid, using defaults")
            return defaults
        merged = _deep_merge(defaults, file_data)
        if isinstance(file_data, dict) and "version" in file_data:
            logger.info("[Config] sec-userspace.yaml v%s from %s", file_data['version'], target)
            try:
                from .path_resolver import verify_config_version
                verify_config_version(file_data['version'], "sec-userspace.yaml")
            except (ImportError, ValueError, TypeError):
                pass
        return merged
    except yaml.YAMLError as exc:
        logger.warning(f"Config file has invalid YAML at {target}: {exc}, using defaults")
        return defaults
    except OSError as exc:
        logger.warning(f"Failed to read config file {target}: {exc}, using defaults")
        return defaults


# ------------------------------------------------------------------
# Convenience accessors
# ------------------------------------------------------------------

def get_server_config(config: Optional[dict] = None) -> dict:
    """Return server section of config."""
    cfg = config if config is not None else load_config()
    return cfg.get("server") or copy.deepcopy(_DEFAULT_CONFIG["server"])


def get_ioc_config(config: Optional[dict] = None) -> dict:
    """Return IoC section of config."""
    cfg = config if config is not None else load_config()
    return cfg.get("ioc") or copy.deepcopy(_DEFAULT_CONFIG["ioc"])


def get_scan_config(config: Optional[dict] = None) -> dict:
    """Return scan section of config."""
    cfg = config if config is not None else load_config()
    return cfg.get("scan") or copy.deepcopy(_DEFAULT_CONFIG["scan"])


def get_logging_config(config: Optional[dict] = None) -> dict:
    """Return logging section of config."""
    cfg = config if config is not None else load_config()
    return cfg.get("logging") or copy.deepcopy(_DEFAULT_CONFIG["logging"])
