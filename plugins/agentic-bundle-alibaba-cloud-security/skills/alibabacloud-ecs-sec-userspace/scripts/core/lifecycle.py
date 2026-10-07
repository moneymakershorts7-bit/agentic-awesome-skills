"""Lifecycle management: signals, resource limits, timeouts."""
import logging
import os


def _get_cpu_limit() -> int:
    """Get CPU limit percentage from config (1-100, default 40)."""
    from ..utils.config_loader import load_config, get_scan_config
    try:
        file_config = load_config()
        scan_cfg = get_scan_config(file_config)
        config_limit = scan_cfg.get('cpu_limit', 40)
        return max(1, min(100, int(config_limit)))
    except (OSError, ValueError, KeyError):
        return 40


def _get_scan_timeout() -> int:
    """Get scan timeout in seconds from config (default 300, 0 = unlimited)."""
    from ..utils.config_loader import load_config, get_scan_config
    try:
        file_config = load_config()
        scan_cfg = get_scan_config(file_config)
        timeout = int(scan_cfg.get('scan_timeout', 300))
        return timeout if timeout > 0 else 0
    except (OSError, ValueError, KeyError):
        return 300


def _apply_cgroup_cpu_limit(cpu_limit: int) -> bool:
    """Apply CPU limit using cgroups v2.
    
    Args:
        cpu_limit: CPU limit percentage (1-100)
    
    Returns:
        True if limit was successfully applied
    """
    try:
        cgroup_path = '/sys/fs/cgroup/sec-userspace'
        
        if not os.path.exists('/sys/fs/cgroup/cgroup.controllers'):
            return False
        
        os.makedirs(cgroup_path, exist_ok=True)
        
        quota = cpu_limit * 1000
        period = 100000
        
        cpu_max_file = os.path.join(cgroup_path, 'cpu.max')
        with open(cpu_max_file, 'w', encoding='utf-8') as f:
            f.write(f"{quota} {period}")
        
        cgroup_procs_file = os.path.join(cgroup_path, 'cgroup.procs')
        with open(cgroup_procs_file, 'w', encoding='utf-8') as f:
            f.write(str(os.getpid()))
        
        logging.getLogger("sec-userspace").info(
            f"cgroups CPU limit applied: {cpu_limit}% (cpu.max: {quota} {period})"
        )
        return True
    except OSError as e:
        logging.getLogger("sec-userspace").debug(f"cgroups CPU limit failed: {e}")
        return False


def _calculate_throttle_target(cpu_limit: int) -> float:
    """Calculate throttle target percentage based on CPU limit.
    
    Args:
        cpu_limit: CPU limit percentage (1-100)
    
    Returns:
        Throttle target percentage
    """
    if cpu_limit >= 80:
        return 5.0
    elif cpu_limit >= 40:
        return 2.5
    elif cpu_limit >= 20:
        return 1.0
    else:
        return 0.5


def setup_resource_limits():
    """Set resource limits (nice priority, CPU limits)."""
    # Set nice priority (lowest)
    try:
        os.nice(19)
    except OSError:
        pass
    
    # CPU limits (from config)
    cpu_limit = _get_cpu_limit()
    if cpu_limit < 100:
        if not _apply_cgroup_cpu_limit(cpu_limit):
            logging.getLogger("sec-userspace").warning(
                "cgroups not available, using worker count + throttle control"
            )


# Global timeout flag
_global_timeout_flag = False


def global_timeout_handler(signum, frame):
    """Global timeout signal handler - only sets flag, no I/O in signal context."""
    global _global_timeout_flag
    _global_timeout_flag = True


def get_global_timeout_flag() -> bool:
    """Check if global timeout has been triggered."""
    return _global_timeout_flag


def reset_global_timeout_flag():
    """Reset global timeout flag (for testing)."""
    global _global_timeout_flag
    _global_timeout_flag = False
