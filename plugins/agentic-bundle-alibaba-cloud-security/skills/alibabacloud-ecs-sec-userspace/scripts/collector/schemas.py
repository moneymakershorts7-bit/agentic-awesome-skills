"""
Collector data schemas - expected structure for each collector type.

This ensures analyzers receive valid data even when collectors fail.
Schemas define required_keys and default values for each collector module.
"""

COLLECTOR_DATA_SCHEMAS = {
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
            "rc_local": [],
            "profile_d_scripts": [],
            "ld_so_preload": [],
            "modules_load_d": [],
            "modprobe_d": [],
            "enabled_services": [],
        }
    },
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
