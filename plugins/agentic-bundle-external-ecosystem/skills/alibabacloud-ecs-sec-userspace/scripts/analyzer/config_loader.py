"""
Analyzer Configuration Loader

Loads and merges analyzer configuration from configs/analyzer.yaml.
Provides fallback to code-level defaults when config file is missing.

Design principles:
- Zero external dependencies (uses scripts/thirdparties/yaml)
- Backward compatible: missing file = all analyzers use code defaults
- Deep merge: analyzer-specific config > defaults > code-level defaults
"""
import os
import copy
import logging
import threading

_logger = None
_logger_lock = threading.Lock()

# Code-level default values for each analyzer (used when config file is missing)
_ANALYZER_DEFAULTS = {
    "process_analyzer": {
        "timeout": 30,
        "thresholds": {
            "max_package_checks": 5,
            "package_check_timeout": 1.0,
            "hidden_proc_check_limit": 20,
            "max_command_length": 500,
        },
        "paths": {
            "proc_dir": "/proc",
        },
        "risky_paths": ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/"],
        "suspicious_download_paths": ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/", "/.hidden"],
        "ai_tool_temp_paths": [
            "/tmp/.claude-code-", "/tmp/.qoder-", "/tmp/.cursor-",
            "/tmp/qoder-", "/tmp/claude-", "/tmp/cursor-",
            "/tmp/npx-cache-", "/tmp/npm-cache-", "/tmp/yarn--",
        ],
    },
    "file_analyzer": {
        "timeout": 30,
        "thresholds": {
            "max_file_list_size": 1000,
        },
        "paths": {
            "low_confidence_paths": ["/tmp", "/var/tmp", "/dev/shm"],
            "hidden_file_exempt_paths": ["/tmp", "/var/tmp", "/dev/shm"],
        },
    },
    "malware_analyzer": {
        "timeout": 60,
        "thresholds": {
            "max_script_size": 1048576,
            "elf_header_size": 4096,
            "static_link_check_size": 65536,
        },
        "scan_paths": {
            "suspicious_dirs": ["/tmp", "/var/tmp", "/dev/shm", "/root"],
            "extended_scan_dirs": ["/opt", "/home"],
            "home_dir": "/home",
        },
        "subdir_scan": {
            "max_depth": 1,
        },
    },
    "rootkit_analyzer": {
        "timeout": 45,
        "thresholds": {
            "quick_mode_budget": 0.8,
            "hidden_process_threshold": 5,
            "ephemeral_port_threshold": 32768,
        },
        "paths": {
            "service_dirs": [
                "/etc/systemd/system",
                "/usr/lib/systemd/system",
                "/run/systemd/system",
            ],
        },
    },
    "mining_analyzer": {
        "timeout": 30,
        "thresholds": {
            "high_cpu_threshold": 80.0,
            "min_runtime_seconds": 300,
            "wallet_min_cmdline_len": 30,
        },
    },
    "webshell_analyzer": {
        "timeout": 60,
        "web_directories": ["/var/www", "/usr/share/nginx", "/opt/nginx"],
        "entropy": {
            "php": {"normal_max": 5.5, "suspicious": 6.0, "critical": 7.0},
        },
        "char_freq": {
            "printable_ratio_min": 0.6,
            "special_char_ratio_max": 0.3,
            "null_byte_ratio_max": 0.05,
        },
        "base64": {
            "ratio_threshold": 0.5,
            "min_length": 100,
            "min_occurrences": 3,
        },
    },
    "network_analyzer": {
        "timeout": 30,
        "thresholds": {
            "port_scan_window": 10,
            "syn_flood_threshold": 100,
        },
    },
    "persistence_analyzer": {
        "timeout": 30,
        "thresholds": {
            "max_startup_entries": 500,
        },
    },
    "auth_analyzer": {
        "timeout": 30,
        "thresholds": {
            "brute_force_window": 300,
            "brute_force_max_attempts": 10,
        },
    },
    "lateral_movement_analyzer": {
        "timeout": 30,
    },
    "memory_forensics_analyzer": {
        "timeout": 120,
    },
    "threat_intel_analyzer": {
        "timeout": 60,
    },
}

# Global defaults
_GLOBAL_DEFAULTS = {
    "timeout": 60,
    "enabled": True,
    "cache_enabled": True,
}

# Cache defaults
_CACHE_DEFAULTS = {
    "shared_cache_max_size": 256,
    "pattern_cache_max_size": 100,
}

# Memory defaults
_MEMORY_DEFAULTS = {
    "default_budget_mb": 200,
    "chunk_size": 10000,
}

# Load adaptive defaults
_LOAD_ADAPTIVE_DEFAULTS = {
    "extreme_load_timeout_threshold": 30.0,
    "extreme_load_analyzer_timeout": 3.0,
    "high_load_timeout_threshold": 15.0,
    "high_load_analyzer_timeout": 5.0,
    "expensive_analyzer_threshold": 10.0,
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
    """Auto-discover analyzer.yaml path.

    Supports two modes:
    1. Plain mode: configs/analyzer.yaml relative to scripts/ directory
    2. Zipapp mode: uses path_resolver to resolve external configs/ directory

    Returns:
        Path to analyzer.yaml, or empty string if not found
    """
    # Try relative to current file (scripts/analyzer/config_loader.py)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # scripts/analyzer/ -> scripts/ -> project root -> configs/
    scripts_dir = os.path.dirname(current_dir)
    base_dir = os.path.dirname(scripts_dir)

    candidates = [
        os.path.join(base_dir, "configs", "analyzer.yaml"),
        os.path.join(scripts_dir, "..", "configs", "analyzer.yaml"),
        # Zipapp mode: look for configs/ in common locations
        "/etc/sec-userspace/configs/analyzer.yaml",
    ]

    for path in candidates:
        path = os.path.normpath(path)
        if os.path.isfile(path):
            return path

    # Fallback: resolve configs/ via path_resolver (works in zipapp mode)
    try:
        from ..utils.path_resolver import get_skill_root
        sr = get_skill_root()
        path = os.path.normpath(os.path.join(sr, "configs", "analyzer.yaml"))
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
        _get_logger().error("[analyzer_config_loader] PyYAML not available in thirdparties")
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            _get_logger().warning(f"[analyzer_config_loader] YAML file parsed as non-dict: {type(data).__name__}")
            return {}
        return data
    except (OSError, ValueError, KeyError) as e:
        _get_logger().warning(f"[analyzer_config_loader] Failed to parse YAML: {e}")
        return {}
    except yaml.YAMLError as e:
        _get_logger().warning(f"[analyzer_config_loader] YAML parse error: {e}")
        return {}


# Module-level cache
_cached_config = None
_cached_config_path = None
_config_cache_lock = threading.Lock()


def load_analyzer_config(config_path: str = None) -> dict:
    """Load analyzer configuration from YAML file.

    Auto-discovers configs/analyzer.yaml if path not specified.
    File not found or parse error returns empty dict (all analyzers use code defaults).

    Args:
        config_path: Optional explicit path to analyzer.yaml

    Returns:
        Dict with 'defaults', 'analyzers', 'cache', 'memory', 'load_adaptive', 'paths' keys (may be empty)
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
            _get_logger().debug("[analyzer_config_loader] Config file not found, using code defaults")
            _cached_config = {}
            _cached_config_path = config_path
            return _cached_config

        _get_logger().info(f"[analyzer_config_loader] Loading config from: {config_path}")
        data = _load_yaml_file(config_path)

        if data and "version" in data:
            _get_logger().info("[analyzer_config_loader] Config version %s loaded from %s", data["version"], config_path)
            try:
                from ..utils.path_resolver import verify_config_version
                verify_config_version(data['version'], "analyzer.yaml")
            except ImportError:
                pass

        if not data:
            _get_logger().warning("[analyzer_config_loader] Config file empty or invalid, using code defaults")

        _cached_config = data
        _cached_config_path = config_path
        return data


def get_analyzer_config(analyzer_name: str) -> dict:
    """Get merged configuration for a specific analyzer.

    Merge order: analyzer-specific config > defaults > code-level defaults

    Args:
        analyzer_name: Analyzer name (e.g., 'process_analyzer', 'mining_analyzer')

    Returns:
        Merged configuration dict
    """
    config = load_analyzer_config()

    if not config:
        # No config file, return code-level defaults
        return copy.deepcopy(_ANALYZER_DEFAULTS.get(analyzer_name, {}))

    yaml_defaults = config.get("defaults", {})
    analyzers_config = config.get("analyzers", {})

    # Start with code-level defaults for this analyzer (lowest priority)
    merged = copy.deepcopy(_ANALYZER_DEFAULTS.get(analyzer_name, {}))

    # Merge YAML global defaults (medium priority)
    if yaml_defaults:
        merged = _deep_merge(merged, yaml_defaults)

    # Merge analyzer-specific config from YAML (highest priority)
    analyzer_cfg = analyzers_config.get(analyzer_name, {})
    if analyzer_cfg:
        merged = _deep_merge(merged, analyzer_cfg)

    return merged


def get_analyzer_timeout(analyzer_name: str) -> int:
    """Get timeout for an analyzer.

    Args:
        analyzer_name: Analyzer name

    Returns:
        Timeout in seconds
    """
    cfg = get_analyzer_config(analyzer_name)
    return cfg.get("timeout", 60)


def get_global_cache_config() -> dict:
    """Get global cache configuration.

    Returns:
        Merged cache config dict
    """
    config = load_analyzer_config()

    if not config:
        return copy.deepcopy(_CACHE_DEFAULTS)

    cache_cfg = config.get("cache", {})
    return _deep_merge(_CACHE_DEFAULTS, cache_cfg)


def get_global_memory_config() -> dict:
    """Get global memory configuration.

    Returns:
        Merged memory config dict
    """
    config = load_analyzer_config()

    if not config:
        return copy.deepcopy(_MEMORY_DEFAULTS)

    memory_cfg = config.get("memory", {})
    return _deep_merge(_MEMORY_DEFAULTS, memory_cfg)


def get_load_adaptive_config() -> dict:
    """Get load adaptive configuration.

    Returns:
        Merged load adaptive config dict
    """
    config = load_analyzer_config()

    if not config:
        return copy.deepcopy(_LOAD_ADAPTIVE_DEFAULTS)

    load_cfg = config.get("load_adaptive", {})
    return _deep_merge(_LOAD_ADAPTIVE_DEFAULTS, load_cfg)


def get_global_paths_config() -> dict:
    """Get global paths configuration.

    Returns:
        Merged paths config dict
    """
    config = load_analyzer_config()

    if not config:
        return {}

    return copy.deepcopy(config.get("paths", {}))


def reload_config():
    """Force reload configuration from disk (clears cache)."""
    global _cached_config, _cached_config_path
    with _config_cache_lock:
        _cached_config = None
        _cached_config_path = None
