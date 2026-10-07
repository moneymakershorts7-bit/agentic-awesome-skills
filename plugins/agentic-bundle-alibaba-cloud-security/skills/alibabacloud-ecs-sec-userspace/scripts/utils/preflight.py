"""Pre-boot system load check and root permission detection utility"""
import os
import sys
import logging
from pathlib import Path
from typing import Tuple, List, Dict

from .proc import get_loadavg, get_meminfo, get_cpu_count
from .timeout_scaler import TimeoutScaler

logger = logging.getLogger("sec-userspace")

# Memory threshold for CPU load override (MB)
# If available memory exceeds this, allow higher CPU load
MEMORY_OVERRIDE_THRESHOLD_MB = 16000  # 16GB

# Very high memory threshold for extreme load environments (MB)
VERY_HIGH_MEMORY_THRESHOLD_MB = 20000  # 20GB

# Environment-specific CPU load thresholds (load_ratio = load5 / cpu_count)
# Development: 90% - IDE, compilation, containers cause high baseline
# CI/CD: 85% - Build processes, test runners consume CPU
# Production: 70% - Should be relatively idle, high load is suspicious
# Unknown: 75% - Conservative default
ENV_CPU_THRESHOLDS = {
    'development': 0.90,
    'ci_cd': 0.85,
    'production': 0.70,
    'unknown': 0.75,
}

# Extended thresholds when memory is abundant (>16GB available)
# Rationale: High memory availability means scan won't cause OOM or swapping
ENV_CPU_THRESHOLDS_HIGH_MEMORY = {
    'development': 1.50,   # Allow 150% on dev machines with abundant memory
    'ci_cd': 1.20,         # Allow 120% on CI/CD with abundant memory
    'production': 1.00,    # Allow 100% on production with abundant memory
    'unknown': 1.10,       # Allow 110% unknown with abundant memory
}

# Extreme thresholds when memory is very abundant (>20GB available)
# Rationale: Very high memory means system can handle extreme CPU load
ENV_CPU_THRESHOLDS_VERY_HIGH_MEMORY = {
    'development': 15.0,   # Allow extreme load on dev machines with very abundant memory
    'ci_cd': 10.0,         # Allow high load on CI/CD with very abundant memory
    'production': 5.0,     # Allow moderate load on production with very abundant memory
    'unknown': 8.0,        # Allow high load unknown with very abundant memory
}


def detect_environment() -> str:
    """Detect the current environment type.

    Returns:
        'development', 'ci_cd', 'production', or 'unknown'
    """
    indicators = {
        'development': 0,
        'ci_cd': 0,
        'production': 0,
    }

    # Development indicators
    if Path("/data/work").exists():
        indicators['development'] += 2
    if Path(".git").exists():
        indicators['development'] += 1
    if Path("node_modules").exists():
        indicators['development'] += 1
    if os.environ.get("DEV_ENV", "0") == "1":
        indicators['development'] += 3
    if any(Path(p).exists() for p in ["/home", "/Users"]):
        indicators['development'] += 1

    # CI/CD indicators
    if os.environ.get("CI"):
        indicators['ci_cd'] += 3
    if os.environ.get("GITHUB_ACTIONS"):
        indicators['ci_cd'] += 2
    if os.environ.get("GITLAB_CI"):
        indicators['ci_cd'] += 2
    if os.environ.get("JENKINS_URL"):
        indicators['ci_cd'] += 2
    if os.environ.get("CIRCLECI"):
        indicators['ci_cd'] += 2

    # Production indicators
    if Path("/etc/kubernetes").exists():
        indicators['production'] += 3
    if Path("/var/lib/kubelet").exists():
        indicators['production'] += 2
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        indicators['production'] += 3
    if Path("/etc/ecs").exists():  # Alibaba Cloud ECS
        indicators['production'] += 2

    # Return highest scoring environment
    env = max(indicators, key=indicators.get)
    
    # If all scores are 0, return unknown
    if indicators[env] == 0:
        return 'unknown'
    
    return env


# Backward compatibility: default threshold for unknown environment
CPU_LOAD_THRESHOLD = ENV_CPU_THRESHOLDS['unknown']


def _is_memory_abundant() -> Tuple[str, int]:
    """Check available memory level.

    Returns:
        tuple: (memory_level, available_memory_mb)
            memory_level: 'very_high', 'high', or 'normal'
    """
    try:
        meminfo = get_meminfo()
        available_kb = meminfo.get("MemAvailable", 0)
        available_mb = available_kb // 1024

        if available_mb >= VERY_HIGH_MEMORY_THRESHOLD_MB:
            return ('very_high', available_mb)
        elif available_mb >= MEMORY_OVERRIDE_THRESHOLD_MB:
            return ('high', available_mb)
        else:
            return ('normal', available_mb)
    except (OSError, ValueError, KeyError):
        return ('normal', 0)


def get_cpu_threshold() -> Tuple[float, str]:
    """Get CPU load threshold based on detected environment and memory.

    Returns:
        tuple: (threshold_ratio, environment_type)
    """
    env = detect_environment()

    # Check memory level
    memory_level, avail_mb = _is_memory_abundant()

    if memory_level == 'very_high':
        threshold = ENV_CPU_THRESHOLDS_VERY_HIGH_MEMORY.get(env, ENV_CPU_THRESHOLDS_VERY_HIGH_MEMORY['unknown'])
        logger.debug(
            f"Memory very high ({avail_mb}MB), using very-high-memory threshold: "
            f"{threshold:.0%} for {env}"
        )
    elif memory_level == 'high':
        threshold = ENV_CPU_THRESHOLDS_HIGH_MEMORY.get(env, ENV_CPU_THRESHOLDS_HIGH_MEMORY['unknown'])
        logger.debug(
            f"Memory abundant ({avail_mb}MB), using high-memory threshold: "
            f"{threshold:.0%} for {env}"
        )
    else:
        threshold = ENV_CPU_THRESHOLDS.get(env, ENV_CPU_THRESHOLDS['unknown'])
        logger.debug(f"Using standard threshold: {threshold:.0%} for {env}")

    return threshold, env


def check_root() -> bool:
    """Check for root permission
    
    Returns:
        bool: True indicates root permission, False indicates non-root permission
    """
    if os.geteuid() == 0:
        return True
    
    # Output error message when not root
    error_msg = "[ERROR] sec-userspace requires root permission to run, please use: sudo python -m scripts.main"
    sys.stderr.write(error_msg + "\n")
    sys.stderr.flush()
    logger.error("Non-root permission detected, execution denied")
    
    return False


def check_cpu_load(force: bool = False) -> Tuple[bool, str]:
    """Check CPU load with environment-aware thresholds.

    Args:
        force: Whether to force execution (ignore load check)

    Returns:
        tuple[bool, str]: (whether check passed, message)
    """
    try:
        # Get load information
        loadavg = get_loadavg()
        load5 = loadavg.get("load5", 0.0)

        # Get CPU core count
        cpu_count = get_cpu_count()
        if cpu_count == 0:
            cpu_count = 1

        # Calculate load ratio
        load_ratio = load5 / cpu_count

        # Get environment-specific threshold
        threshold, env = get_cpu_threshold()

        if load_ratio > threshold:
            if force:
                msg = f"CPU load too high but --force forced execution: {load_ratio:.1%} (threshold {threshold:.0%} for {env})"
                logger.warning(msg)
                return (True, msg)
            else:
                msg = f"CPU load too high: {load_ratio:.1%} (threshold {threshold:.0%} for {env} environment)"
                logger.warning(msg)
                return (False, msg)
        else:
            memory_level, avail_mb = _is_memory_abundant()
            memory_note = ""
            if memory_level == 'very_high':
                memory_note = f", memory very high: {avail_mb}MB"
            elif memory_level == 'high':
                memory_note = f", memory abundant: {avail_mb}MB"
            msg = f"CPU load normal: {load_ratio:.1%}{memory_note}"
            logger.debug(f"Environment: {env}, threshold: {threshold:.0%}")
            logger.info(msg)
            return (True, msg)

    except (OSError, ValueError, KeyError, TypeError) as e:
        msg = f"CPU load check failed: {str(e)}"
        logger.error(msg, exc_info=True)
        if force:
            return (True, f"{msg} (force continue)")
        return (False, msg)


def check_memory_available(force: bool = False) -> Tuple[bool, str]:
    """Check available memory
    
    Args:
        force: Whether to force execution (ignore memory check)
        
    Returns:
        tuple[bool, str]: (whether check passed, message)
    """
    try:
        # Get memory information
        meminfo = get_meminfo()
        available_kb = meminfo.get("MemAvailable", 0)
        available_mb = available_kb // 1024
        
        if available_mb < 500:
            if force:
                msg = f"Insufficient available memory but --force forced execution: {available_mb}MB (threshold 500MB)"
                logger.warning(msg)
                return (True, msg)
            else:
                msg = f"Insufficient available memory: {available_mb}MB (threshold 500MB)"
                logger.warning(msg)
                return (False, msg)
        else:
            msg = f"Available memory sufficient: {available_mb}MB"
            logger.info(msg)
            return (True, msg)
            
    except (OSError, ValueError, KeyError, TypeError) as e:
        msg = f"Memory check failed: {str(e)}"
        logger.error(msg, exc_info=True)
        if force:
            return (True, f"{msg} (force continue)")
        return (False, msg)


def preflight_check(force: bool = False) -> Tuple[bool, List[str]]:
    """Execute all pre-boot checks
    
    Args:
        force: Whether to force execution (ignore check failures)
                
    Returns:
        tuple[bool, List[str]]: (whether all passed, message list)
    """
    messages = []
    all_pass = True
    
    # Check CPU load
    cpu_pass, cpu_msg = check_cpu_load(force=force)
    messages.append(cpu_msg)
    if not cpu_pass:
        all_pass = False
    
    # Check memory
    mem_pass, mem_msg = check_memory_available(force=force)
    messages.append(mem_msg)
    if not mem_pass:
        all_pass = False
    
    # If force=True, force pass
    if force and not all_pass:
        all_pass = True
        messages.append("--force used, ignoring check failures")
        logger.warning("--force used, ignoring load check failures")
    
    return (all_pass, messages)


def get_preflight_load_info() -> Dict:
    """Get load information from preflight for timeout scaling.
    
    Returns:
        Dict with load_ratio, cpu_count, load5, and timeout_scaler instance.
    """
    try:
        loadavg = get_loadavg()
        load5 = loadavg.get("load5", 0.0)
        cpu_count = get_cpu_count() or 1
        load_ratio = load5 / cpu_count
        
        timeout_scaler = TimeoutScaler(load_ratio=load_ratio)
        
        return {
            "load5": load5,
            "cpu_count": cpu_count,
            "load_ratio": load_ratio,
            "timeout_scaler": timeout_scaler,
        }
    except (OSError, ValueError, KeyError, TypeError) as e:
        logger.debug(f"Failed to get preflight load info: {e}")
        return {
            "load5": 0.0,
            "cpu_count": 1,
            "load_ratio": 1.0,
            "timeout_scaler": TimeoutScaler(load_ratio=1.0),
        }
