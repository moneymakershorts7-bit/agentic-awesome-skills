"""
Collector Configuration Loader

Loads and merges collector configuration from configs/collector.yaml.
Provides fallback to code-level defaults when config file is missing.

Design principles:
- Zero external dependencies (uses scripts/thirdparties/yaml)
- Backward compatible: missing file = all collectors use code defaults
- Deep merge: collector-specific config > defaults > code-level defaults
"""
import os
import copy
import logging
import threading

_logger = None
_logger_lock = threading.Lock()

# Code-level default values for each collector (used when config file is missing)
_COLLECTOR_DEFAULTS = {
    "system": {
        "timeout": 10,
    },
    "process": {
        "timeout": 120,
        "max_processes": 500,
        "thread_count": 20,
    },
    "network": {
        "timeout": 180,
        "tcp_timeout": 10,
        "udp_timeout": 15,
    },
    "filesystem": {
        "timeout": 180,
        "max_files_per_dir": 100,
    },
    "cron": {
        "timeout": 30,
        "soft_timeout_ratio": 0.85,
        "max_cron_d_files": 100,
        "max_periodic_files": 100,
        "max_user_crontabs": 50,
        "max_cron_script_size": 1048576,
    },
    "log": {
        "timeout": 90,
        "max_lines": 1000,
    },
    "user": {
        "timeout": 30,
        "max_sudoers": 100,
        "max_auth_keys_file_size": 1048576,
        "max_sshd_config_size": 1048576,
        "max_shadow_size": 1048576,
    },
    "service": {
        "timeout": 60,
        "soft_timeout_ratio": 0.85,
        "max_services": 500,
    },
    "dns": {
        "timeout": 60,
        "max_reverse_lookups": 50,
        "reverse_dns_timeout": 2,
    },
    "package_history": {
        "timeout": 120,
        "batch_gc_interval": 10,
    },
    "package-history": {  # Alias for backward compatibility
        "timeout": 120,
        "batch_gc_interval": 10,
    },
}

# Global defaults
_GLOBAL_DEFAULTS = {
    "timeout": 60,
    "retry": 0,
    "retry_delay": 1,
    "enabled": True,
}

# Executor defaults
_EXECUTOR_DEFAULTS = {
    "phase_timeout": 55,
    "intra_group_check_interval": 5,
    "max_workers": 4,
    "global_timeout": 600,
}


def _get_logger():
    """Lazy logger initialization."""
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                _logger = logging.getLogger("sec-userspace")
    return _logger


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dicts. Override values take precedence.

    - Dict fields are merged recursively
    - List fields are replaced entirely (not merged)
    - Scalar fields are replaced

    Args:
        base: Base dictionary
        override: Override dictionary

    Returns:
        Merged dictionary (new dict, not modifying inputs)
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _find_config_path() -> str:
    """Auto-discover collector.yaml path.

    Supports two modes:
    1. Plain mode: configs/collector.yaml relative to scripts/ directory
    2. Zipapp mode: uses path_resolver to resolve external configs/ directory

    Returns:
        Path to collector.yaml, or empty string if not found
    """
    # Try relative to current file (scripts/collector/config_loader.py)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # scripts/collector/ -> scripts/ -> configs/
    scripts_dir = os.path.dirname(current_dir)
    base_dir = os.path.dirname(scripts_dir)

    candidates = [
        os.path.join(base_dir, "configs", "collector.yaml"),
        os.path.join(scripts_dir, "..", "configs", "collector.yaml"),
        # Zipapp mode: look for configs/ in common locations
        "/etc/sec-userspace/configs/collector.yaml",
    ]

    for path in candidates:
        path = os.path.normpath(path)
        if os.path.isfile(path):
            return path

    # Fallback: resolve configs/ via path_resolver (works in zipapp mode)
    try:
        from ..utils.path_resolver import get_skill_root
        path = os.path.normpath(os.path.join(get_skill_root(), "configs", "collector.yaml"))
        if os.path.isfile(path):
            return path
    except ImportError:
        pass

    return ""


def _load_yaml_file(filepath: str) -> dict:
    """Load YAML file using built-in thirdparties/yaml.

    Args:
        filepath: Path to YAML file

    Returns:
        Parsed YAML dict, or empty dict on failure
    """
    try:
        from ..thirdparties import yaml
    except ImportError:
        _get_logger().error("[config_loader] PyYAML not available in thirdparties")
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            _get_logger().warning(f"[config_loader] YAML file parsed as non-dict: {type(data).__name__}")
            return {}
        return data
    except (OSError, ValueError, TypeError, yaml.YAMLError) as e:
        _get_logger().warning(f"[config_loader] Failed to parse YAML: {e}")
        return {}


# Module-level cache
_cached_config = None
_cached_config_path = None
_config_cache_lock = threading.Lock()


def load_collector_config(config_path: str = None) -> dict:
    """Load collector configuration from YAML file.

    Auto-discovers configs/collector.yaml if path not specified.
    File not found or parse error returns empty dict (all collectors use code defaults).

    Args:
        config_path: Optional explicit path to collector.yaml

    Returns:
        Dict with 'defaults', 'collectors', 'executor' keys (may be empty)
    """
    global _cached_config, _cached_config_path

    if config_path is None and _cached_config is not None:
        return _cached_config

    with _config_cache_lock:
        if config_path is None and _cached_config is not None:
            return _cached_config

        if config_path is None:
            config_path = _find_config_path()

        if not config_path or not os.path.isfile(config_path):
            _get_logger().debug("[config_loader] Config file not found, using code defaults")
            _cached_config = {}
            _cached_config_path = config_path
            return _cached_config

        _get_logger().info(f"[config_loader] Loading config from: {config_path}")
        data = _load_yaml_file(config_path)

        if data and "version" in data:
            _get_logger().info("[config_loader] Config version %s loaded from %s", data["version"], config_path)
            try:
                from ..utils.path_resolver import verify_config_version
                verify_config_version(data['version'], "collector.yaml")
            except ImportError:
                pass

        if not data:
            _get_logger().warning("[config_loader] Config file empty or invalid, using code defaults")

        _cached_config = data
        _cached_config_path = config_path
        return data


def get_collector_config(collector_name: str) -> dict:
    """Get merged configuration for a specific collector.

    Merge order: collector-specific config > defaults > code-level defaults

    Args:
        collector_name: Collector name (e.g., 'system', 'process')

    Returns:
        Merged configuration dict
    """
    config = load_collector_config()

    if not config:
        # No config file, return code-level defaults
        return copy.deepcopy(_COLLECTOR_DEFAULTS.get(collector_name, {}))

    global_defaults = config.get("defaults", _GLOBAL_DEFAULTS)
    collectors_config = config.get("collectors", {})

    # Start with global defaults
    merged = copy.deepcopy(global_defaults)

    # Merge code-level defaults for this collector
    code_defaults = _COLLECTOR_DEFAULTS.get(collector_name, {})
    merged = _deep_merge(merged, code_defaults)

    # Merge collector-specific config (highest priority)
    collector_cfg = collectors_config.get(collector_name, {})
    merged = _deep_merge(merged, collector_cfg)

    return merged


def get_collector_timeout(collector_name: str) -> int:
    """Get timeout for a collector.

    Args:
        collector_name: Collector name

    Returns:
        Timeout in seconds
    """
    cfg = get_collector_config(collector_name)
    return cfg.get("timeout", 60)


def get_executor_config() -> dict:
    """Get executor configuration.

    Returns:
        Merged executor config dict
    """
    config = load_collector_config()

    if not config:
        return copy.deepcopy(_EXECUTOR_DEFAULTS)

    executor_cfg = config.get("executor", {})
    return _deep_merge(_EXECUTOR_DEFAULTS, executor_cfg)


def reload_config():
    """Force reload configuration from disk (clears cache)."""
    global _cached_config, _cached_config_path
    with _config_cache_lock:
        _cached_config = None
        _cached_config_path = None
