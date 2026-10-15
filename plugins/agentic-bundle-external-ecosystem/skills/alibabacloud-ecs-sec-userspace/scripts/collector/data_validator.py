"""Collector Data Validation Utilities

P1-2026-04-15: Data validation utilities to ensure collectors return valid
data structures even when collection fails or returns incomplete results.

This module provides:
- Data schema validation for each collector type
- Default value injection for missing fields
- Data quality scoring and logging
- CollectorValidator with degradation strategies (FULL/PARTIAL/EMPTY)
"""
from typing import Dict, Any, List, Tuple
import threading

_lazy_init_lock = threading.Lock()

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


# Collector data schemas - expected structure for each collector
# This ensures analyzers receive valid data even when collectors fail
COLLECTOR_DATA_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "system": {
        "required_keys": ["hostname", "os_release", "kernel_version"],
        "defaults": {
            "hostname": "unknown",
            "os_release": "Unknown",
            "kernel_version": "Unknown",
            "kernel_release": "Unknown",
            "arch": "unknown",
            "uptime_seconds": 0.0,
            "boot_time": "",
            "cpu_count": 1,
            "memory_total_mb": 0,
            "memory_available_mb": 0,
            "load_avg": {"load1": 0.0, "load5": 0.0, "load15": 0.0},
            "kernel_capabilities": "Unknown",
        }
    },
    "process": {
        "required_keys": ["processes"],
        "defaults": {
            "processes": [],
            "total_count": 0,
            "statistics": {},
        }
    },
    "network": {
        "required_keys": ["tcp_connections", "udp_connections", "listening_ports"],
        "defaults": {
            "tcp_connections": [],
            "tcp6_connections": [],
            "udp_connections": [],
            "udp6_connections": [],
            "listening_ports": [],
            "ssl_connections": [],
        }
    },
    "filesystem": {
        "required_keys": ["files"],
        "defaults": {
            "files": [],
            "suspicious_paths": [],
            "statistics": {},
        }
    },
    "log": {
        "required_keys": ["logs"],
        "defaults": {
            "logs": [],
            "suspicious_entries": [],
            "statistics": {},
        }
    },
    "user": {
        "required_keys": ["users"],
        "defaults": {
            "users": [],
            "sudoers": [],
            "ssh_keys": [],
        }
    },
    "cron": {
        "required_keys": ["system_crontab"],
        "defaults": {
            "system_crontab": [],
            "cron_d_entries": [],
            "cron_periodic": [],
            "user_crontabs": [],
            "systemd_timers": [],
            "suspicious_jobs": [],
        }
    },
    "service": {
        "required_keys": ["systemd_services"],
        "defaults": {
            "systemd_services": [],
            "systemd_timers": [],
            "dbus_services": [],
            "initd_scripts": [],
            "rc_local": {},
            "profile_d_scripts": [],
            "ld_so_preload": {},
            "modules_load_d": [],
            "modprobe_d": [],
            "enabled_services": [],
        }
    },
    # Extended collector schemas for full coverage
    "dns": {
        "required_keys": ["resolv_conf", "hosts_entries"],
        "defaults": {
            "resolv_conf": {"nameservers": [], "search_domains": [], "raw_path": "/etc/resolv.conf"},
            "hosts_entries": [],
            "reverse_dns": {},
        }
    },
    "ebpf": {
        "required_keys": ["programs", "maps"],
        "defaults": {
            "programs": [],
            "maps": [],
            "kprobes": [],
            "tracepoints": [],
            "bpf_fs_entries": [],
            "suspicious_programs": [],
            "statistics": {},
        }
    },
    "container_runtime": {
        "required_keys": ["running_containers"],
        "defaults": {
            "running_containers": [],
            "container_namespaces": [],
            "ebpf_programs": [],
            "mount_points": [],
            "cgroup_hierarchy": {},
            "syscall_traces": [],
            "escape_indicators": [],
            "side_channel_indicators": [],
            "shared_memory_usage": [],
            "sysctl_modifications": [],
        }
    },
    "k8s_workload": {
        "required_keys": ["service_accounts"],
        "defaults": {
            "service_accounts": [],
            "pod_identity": None,
            "rbac_bindings": [],
            "cloud_federation": {},
            "is_k8s_environment": False,
        }
    },
    "conversation": {
        "required_keys": ["conversations"],
        "defaults": {
            "conversations": [],
            "vector_db_entries": [],
            "memory_snapshots": [],
            "statistics": {},
            "sources_checked": [],
            "files_scanned": 0,
            "parse_errors": [],
        }
    },
    "ai_dev": {
        "required_keys": ["ai_tools"],
        "defaults": {
            "ai_tools": [],
            "ai_dependencies": [],
            "ai_configs": [],
            "ai_logs": [],
            "statistics": {},
        }
    },
    "agent_memory": {
        "required_keys": ["memory_entries"],
        "defaults": {
            "memory_entries": [],
            "vector_stores": [],
            "embeddings": [],
            "statistics": {},
        }
    },
    "agent_tools": {
        "required_keys": ["tools"],
        "defaults": {
            "tools": [],
            "tool_configs": [],
            "tool_logs": [],
            "suspicious_tools": [],
            "statistics": {},
        }
    },
    "agent_dependency": {
        "required_keys": ["dependencies"],
        "defaults": {
            "dependencies": [],
            "suspicious_packages": [],
            "supply_chain_risks": [],
            "statistics": {},
        }
    },
    "agent_logs": {
        "required_keys": ["logs"],
        "defaults": {
            "logs": [],
            "suspicious_entries": [],
            "statistics": {},
        }
    },
    "mcp": {
        "required_keys": ["mcp_servers"],
        "defaults": {
            "mcp_servers": [],
            "mcp_tools": [],
            "mcp_resources": [],
            "suspicious_servers": [],
            "statistics": {},
        }
    },
    "mcp_config": {
        "required_keys": ["mcp_configs"],
        "defaults": {
            "mcp_configs": [],
            "mcp_endpoints": [],
            "mcp_auth_configs": [],
            "statistics": {},
        }
    },
    "cloud_lambda": {
        "required_keys": ["lambda_functions"],
        "defaults": {
            "lambda_functions": [],
            "trigger_configs": [],
            "permission_policies": [],
            "suspicious_functions": [],
            "statistics": {},
        }
    },
    "container_config": {
        "required_keys": ["container_configs"],
        "defaults": {
            "container_configs": [],
            "docker_compose_files": [],
            "kubernetes_manifests": [],
            "suspicious_configs": [],
            "statistics": {},
        }
    },
    "openclaw": {
        "required_keys": ["openclaw_configs"],
        "defaults": {
            "openclaw_configs": [],
            "openclaw_logs": [],
            "openclaw_plugins": [],
            "suspicious_entries": [],
            "statistics": {},
        }
    },
    "mesh_telemetry": {
        "required_keys": ["mesh_configs"],
        "defaults": {
            "mesh_configs": [],
            "telemetry_data": [],
            "service_mesh_policies": [],
            "suspicious_entries": [],
            "statistics": {},
        }
    },
    "rag_kb": {
        "required_keys": ["knowledge_bases"],
        "defaults": {
            "knowledge_bases": [],
            "rag_configs": [],
            "embedding_models": [],
            "suspicious_entries": [],
            "statistics": {},
        }
    },
    "vector_db": {
        "required_keys": ["vector_stores"],
        "defaults": {
            "vector_stores": [],
            "collections": [],
            "indexes": [],
            "suspicious_entries": [],
            "statistics": {},
        }
    },
    "package_history": {
        "required_keys": ["packages"],
        "defaults": {
            "packages": [],
            "install_history": [],
            "suspicious_packages": [],
            "statistics": {},
        }
    },
}


def validate_collector_data(collector_name: str, data: Any) -> Tuple[Dict[str, Any], List[str], float]:
    """Validate collected data structure and apply defaults for missing fields
    
    P1-2026-04-15: Ensures analyzers receive valid data even when collectors
    return incomplete or empty results.
    
    Args:
        collector_name: Name of the collector
        data: Raw collected data
        
    Returns:
        Tuple of (validated_data, validation_warnings, quality_score)
        - validated_data: Data with defaults applied for missing fields
        - validation_warnings: List of warnings about data issues
        - quality_score: Data quality score between 0.0 and 1.0
    """
    warnings = []
    
    # Handle non-dict data
    if not isinstance(data, dict):
        _get_logger().warning(
            f"[{collector_name}] Collector returned non-dict data type: {type(data).__name__}"
        )
        warnings.append("invalid_data_type")
        
        # Return schema defaults if available
        if collector_name in COLLECTOR_DATA_SCHEMAS:
            defaults = dict(COLLECTOR_DATA_SCHEMAS[collector_name]["defaults"])
            return defaults, warnings, 0.3  # Low quality since data was invalid
        return {}, warnings, 0.0
    
    schema = COLLECTOR_DATA_SCHEMAS.get(collector_name, {})
    required_keys = schema.get("required_keys", [])
    defaults = schema.get("defaults", {})
    
    # Check for missing required keys and apply defaults
    missing_keys = []
    for key in required_keys:
        if key not in data:
            missing_keys.append(key)
            warnings.append(f"missing_required_key:{key}")
            if key in defaults:
                import copy
                data[key] = copy.deepcopy(defaults[key])
            else:
                data[key] = []  # Safe default
    
    if missing_keys:
        _get_logger().warning(
            f"[{collector_name}] Missing required keys: {', '.join(missing_keys)}, "
            f"applying defaults"
        )
    
    # Validate key types - ensure list fields are actually lists
    type_warnings = []
    for key, value in data.items():
        if key.startswith('_'):  # Skip metadata keys
            continue
        expected_type = defaults.get(key)
        if expected_type is not None:
            if isinstance(expected_type, list) and not isinstance(value, list):
                type_warnings.append(key)
                warnings.append(f"invalid_type:{key}")
                _get_logger().warning(
                    f"[{collector_name}] Key '{key}' has invalid type {type(value).__name__}, "
                    f"expected list"
                )
                data[key] = []
            elif isinstance(expected_type, dict) and not isinstance(value, dict):
                type_warnings.append(key)
                warnings.append(f"invalid_type:{key}")
                _get_logger().warning(
                    f"[{collector_name}] Key '{key}' has invalid type {type(value).__name__}, "
                    f"expected dict"
                )
                data[key] = dict(expected_type)
    
    # Calculate quality score
    quality_score = calculate_quality_score(data, required_keys, missing_keys, type_warnings)
    
    return data, warnings, quality_score


def calculate_quality_score(
    data: Dict[str, Any],
    required_keys: List[str],
    missing_keys: List[str],
    type_warnings: List[str]
) -> float:
    """Calculate data quality score between 0.0 and 1.0
    
    Args:
        data: Validated data
        required_keys: List of required keys
        missing_keys: List of keys that were missing (now have defaults)
        type_warnings: List of keys with invalid types (now fixed)
        
    Returns:
        Quality score between 0.0 (worst) and 1.0 (best)
    """
    if not required_keys:
        return 1.0  # No schema, assume good
    
    # Start with perfect score
    score = 1.0
    
    # Penalize for missing required keys (each missing key reduces score)
    if required_keys:
        missing_ratio = len(missing_keys) / len(required_keys)
        score -= missing_ratio * 0.5  # Up to 0.5 penalty for missing keys
    
    # Penalize for type errors
    total_keys = len([k for k in data.keys() if not k.startswith('_')])
    if total_keys > 0:
        type_error_ratio = len(type_warnings) / total_keys
        score -= type_error_ratio * 0.3  # Up to 0.3 penalty for type errors
    
    # Penalize for empty required lists
    empty_penalty = 0.0
    empty_count = 0
    for key in required_keys:
        if key in data and isinstance(data[key], list) and len(data[key]) == 0:
            empty_count += 1
    if required_keys:
        empty_ratio = empty_count / len(required_keys)
        empty_penalty = empty_ratio * 0.2  # Up to 0.2 penalty for empty lists
    
    score -= empty_penalty
    
    return max(0.0, min(1.0, score))  # Clamp between 0.0 and 1.0


# ── Collector-Analyzer dependency map ───────────────────────────────

COLLECTOR_ANALYZER_MAP: Dict[str, List[str]] = {
    "process": [
        "process", "mining", "rootkit", "backdoor", "webshell",
        "reverse_shell", "privilege_escalation",
    ],
    "network": [
        "network", "c2", "lateral_movement", "dns_tunnel",
        "reverse_shell", "port_scan",
    ],
    "filesystem": [
        "filesystem", "webshell", "rootkit", "persistence",
        "suspicious_file",
    ],
    "user": [
        "user", "privilege_escalation", "persistence", "ssh",
    ],
    "cron": [
        "cron", "persistence", "scheduled_task",
    ],
    "log": [
        "log", "audit", "tampering",
    ],
    "service": [
        "service", "persistence", "systemd",
    ],
    "dns": [
        "dns", "dns_tunnel",
    ],
    "system": [],
}


class ValidationResult:
    """Result from collector data validation with degradation info."""

    __slots__ = ('is_valid', 'quality', 'degradation', 'warnings',
                 'degraded_analyzers', 'collector_name')

    FULL = "FULL"
    PARTIAL = "PARTIAL"
    EMPTY = "EMPTY"

    def __init__(self, collector_name, is_valid, quality, degradation,
                 warnings, degraded_analyzers):
        self.collector_name = collector_name
        self.is_valid = is_valid
        self.quality = quality
        self.degradation = degradation
        self.warnings = warnings
        self.degraded_analyzers = degraded_analyzers

    def __repr__(self):
        return ("<ValidationResult {name} quality={q:.2f} "
                "degradation={d}>".format(
                    name=self.collector_name, q=self.quality,
                    d=self.degradation))


class CollectorValidator:
    """Validates collector output and determines degradation strategy.

    Integrates between collectors and analyzers to prevent crashes
    from incomplete/empty data.
    """

    def __init__(self, quality_threshold_partial=0.5, quality_threshold_empty=0.2):
        self._threshold_partial = quality_threshold_partial
        self._threshold_empty = quality_threshold_empty

    def validate(self, collector_name: str, data: Any) -> ValidationResult:
        """Validate collector output and determine degradation level."""
        validated_data, warnings, quality = validate_collector_data(
            collector_name, data
        )

        if quality >= self._threshold_partial:
            degradation = ValidationResult.FULL
            degraded_analyzers = []
        elif quality >= self._threshold_empty:
            degradation = ValidationResult.PARTIAL
            degraded_analyzers = self._get_dependent_analyzers(collector_name)
        else:
            degradation = ValidationResult.EMPTY
            degraded_analyzers = self._get_dependent_analyzers(collector_name)

        is_valid = degradation != ValidationResult.EMPTY

        return ValidationResult(
            collector_name=collector_name,
            is_valid=is_valid,
            quality=quality,
            degradation=degradation,
            warnings=warnings,
            degraded_analyzers=degraded_analyzers,
        )

    def validate_all(self, collector_results: Dict[str, Any]) -> Dict[str, ValidationResult]:
        """Validate all collector results.

        Args:
            collector_results: Dict mapping collector name to raw data.

        Returns:
            Dict mapping collector name to ValidationResult.
        """
        results = {}
        for name, data in collector_results.items():
            results[name] = self.validate(name, data)
        return results

    def validate_collect_results(self, collected_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate CollectResult objects from the pipeline.

        Args:
            collected_results: Dict of collector_name -> CollectResult objects.

        Returns:
            Dict with keys: results, skip_analyzers (set), summary.
        """
        results: Dict[str, ValidationResult] = {}
        skip_analyzers: set = set()
        level_counts = {"FULL": 0, "PARTIAL": 0, "EMPTY": 0}

        for name, collect_result in collected_results.items():
            if name.startswith("_"):
                continue
            if collect_result.status != "success":
                vr = ValidationResult(
                    collector_name=name, is_valid=False, quality=0.0,
                    degradation=ValidationResult.EMPTY,
                    warnings=["collector_failed"],
                    degraded_analyzers=self._get_dependent_analyzers(name),
                )
            else:
                vr = self.validate(name, collect_result.data)
            results[name] = vr
            level_counts[vr.degradation] += 1
            skip_analyzers.update(vr.degraded_analyzers)

        return {
            "results": results,
            "skip_analyzers": skip_analyzers,
            "summary": level_counts,
        }

    def get_skip_list(self, validation_results: Dict[str, ValidationResult]) -> List[str]:
        """Get analyzer prefixes to skip due to empty data."""
        skip = set()
        for vr in validation_results.values():
            if vr.degradation == ValidationResult.EMPTY:
                skip.update(vr.degraded_analyzers)
        return sorted(skip)

    def format_quality_summary(self, validation_results: Dict[str, ValidationResult]) -> str:
        """Format data quality summary for report inclusion."""
        lines = ["[Data Quality Summary]"]
        for name, vr in sorted(validation_results.items()):
            icon = {"FULL": "+", "PARTIAL": "~", "EMPTY": "!"}[vr.degradation]
            lines.append("  [{icon}] {name}: quality={q:.0%} ({d})".format(
                icon=icon, name=name, q=vr.quality, d=vr.degradation))
            if vr.warnings:
                for w in vr.warnings[:3]:
                    lines.append("      - {w}".format(w=w))
        return "\n".join(lines)

    def _get_dependent_analyzers(self, collector_name: str) -> List[str]:
        """Get analyzer prefixes that depend on a given collector."""
        return list(COLLECTOR_ANALYZER_MAP.get(collector_name, []))
