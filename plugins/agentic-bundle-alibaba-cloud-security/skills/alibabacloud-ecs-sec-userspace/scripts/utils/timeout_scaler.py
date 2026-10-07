"""Adaptive Timeout Scaler - Dynamically adjusts timeouts based on system load.

This module provides functions to calculate scaled timeouts based on current
CPU load ratio, preventing premature timeouts under high-load conditions
while still enforcing reasonable limits.

Usage:
    from scripts.utils.timeout_scaler import (
        calculate_adaptive_timeout,
        get_load_ratio,
        TimeoutScaler
    )

    # Simple function usage
    scaled_timeout = calculate_adaptive_timeout(base_timeout=30.0, load_ratio=2.5)

    # Using the scaler class for consistent load tracking
    scaler = TimeoutScaler()
    timeouts = scaler.get_scaled_collector_timeouts()
"""
import os
import logging
from typing import Dict, Optional

logger = logging.getLogger("sec-userspace")

# Timeout scaling configuration
TIMEOUT_SCALER_CONFIG = {
    # Minimum multiplier (never go below base timeout)
    "min_multiplier": 1.0,
    # Under extreme load (16x), this caps at 2.0x instead of 3.0x
    "max_multiplier": 2.0,  # Reduced from 3.0
    # Load ratio threshold where scaling begins (load5 / cpu_count)
    "scaling_threshold": 1.0,
    # Linear scaling factor (multiplier increases linearly above threshold)
    "scaling_factor": 1.0,
}

# Collector base timeouts (seconds)
# These are the base timeouts under normal load conditions
COLLECTOR_BASE_TIMEOUTS = {
    "network": 10,
    "process": 30,
    "system": 10,
    "user": 10,
    "cron": 10,
    "filesystem": 25,
    "log": 15,
}

# Overall scan timeout configuration
SCAN_TIMEOUT_CONFIG = {
    "base": 600,      # 10 minutes base
    "max": 900,       # 15 minutes max (reduced from 20 minutes)
}


def get_load_ratio() -> float:
    """Get current system load ratio (load5 / cpu_count).

    Returns:
        Load ratio value. Returns 1.0 if unable to determine.
    """
    try:
        load_avg = os.getloadavg()[1]  # 5-minute load average
        cpu_count = os.cpu_count() or 1
        return load_avg / cpu_count
    except (OSError, AttributeError):
        logger.debug("Failed to get load ratio, defaulting to 1.0")
        return 1.0


def calculate_adaptive_timeout(
    base_timeout: float,
    load_ratio: Optional[float] = None,
    config: Optional[Dict] = None
) -> float:
    """Calculate timeout scaled by current CPU load.

    Args:
        base_timeout: Base timeout under normal load (seconds).
        load_ratio: Current load ratio (load5 / cpu_count).
                   If None, calculated automatically.
        config: Optional configuration override.

    Returns:
        Scaled timeout value in seconds.

    Example:
        >>> calculate_adaptive_timeout(30.0, load_ratio=2.5)
        75.0  # 30 * 2.5 = 75, capped at 30 * 3.0 = 90
    """
    if load_ratio is None:
        load_ratio = get_load_ratio()

    cfg = config or TIMEOUT_SCALER_CONFIG
    min_mult = cfg.get("min_multiplier", 1.0)
    max_mult = cfg.get("max_multiplier", 2.0)
    threshold = cfg.get("scaling_threshold", 1.0)
    factor = cfg.get("scaling_factor", 1.0)

    # No scaling needed under normal load
    if load_ratio <= threshold:
        return base_timeout

    # Calculate scaling multiplier
    # Linear scaling: multiplier = 1.0 + (load_ratio - threshold) * factor
    multiplier = 1.0 + (load_ratio - threshold) * factor

    # Clamp to min/max bounds
    multiplier = max(min_mult, min(multiplier, max_mult))

    scaled_timeout = base_timeout * multiplier

    logger.debug(
        f"Timeout scaled: {base_timeout:.0f}s -> {scaled_timeout:.0f}s "
        f"(load_ratio={load_ratio:.1f}, multiplier={multiplier:.1f}x)"
    )

    return scaled_timeout


class TimeoutScaler:
    """Manages adaptive timeout scaling for the entire scan.

    Tracks load ratio at startup and provides scaled timeouts for
    collectors and overall scan duration.

    Attributes:
        load_ratio: System load ratio captured at initialization.
        cpu_count: Number of CPU cores.
        load5: 5-minute load average.
    """

    def __init__(self, load_ratio: Optional[float] = None):
        """Initialize timeout scaler with current system load.

        Args:
            load_ratio: Optional load ratio override (for testing).
                       If None, calculated from current system state.
        """
        self.cpu_count = os.cpu_count() or 1

        if load_ratio is not None:
            self.load_ratio = load_ratio
            self.load5 = load_ratio * self.cpu_count
        else:
            try:
                self.load5 = os.getloadavg()[1]
                self.load_ratio = self.load5 / self.cpu_count
            except (OSError, AttributeError):
                self.load5 = 0.0
                self.load_ratio = 1.0

        logger.info(
            f"Timeout scaler initialized: load={self.load5:.1f}, "
            f"cpus={self.cpu_count}, ratio={self.load_ratio:.1f}x"
        )

    def get_scaled_collector_timeouts(self) -> Dict[str, float]:
        """Get scaled timeouts for all collectors based on current load.

        Returns:
            Dict mapping collector name to scaled timeout in seconds.
        """
        scaled_timeouts = {}
        for name, base_timeout in COLLECTOR_BASE_TIMEOUTS.items():
            scaled_timeouts[name] = calculate_adaptive_timeout(
                base_timeout, self.load_ratio
            )

        return scaled_timeouts

    def get_scaled_scan_timeout(self) -> float:
        """Get scaled overall scan timeout based on current load.

        Returns:
            Scaled scan timeout in seconds.
        """
        base_timeout = SCAN_TIMEOUT_CONFIG['base']
        max_timeout = SCAN_TIMEOUT_CONFIG['max']

        # Scale based on load ratio, capped at max
        scaled_timeout = calculate_adaptive_timeout(base_timeout, self.load_ratio)
        final_timeout = min(scaled_timeout, max_timeout)

        logger.info(
            f"Scan timeout scaled: "
            f"{base_timeout}s -> {final_timeout:.0f}s "
            f"(load_ratio={self.load_ratio:.1f}x)"
        )

        return final_timeout

    def is_high_load(self, threshold: float = 2.0) -> bool:
        """Check if system is under high load.

        Args:
            threshold: Load ratio threshold (default 2.0 = 200% of CPU count).

        Returns:
            True if load ratio exceeds threshold.
        """
        return self.load_ratio > threshold

    def get_scaling_summary(self) -> Dict:
        """Get human-readable summary of timeout scaling.

        Returns:
            Dict with scaling information for logging/display.
        """
        return {
            "load5": round(self.load5, 2),
            "cpu_count": self.cpu_count,
            "load_ratio": round(self.load_ratio, 2),
            "is_high_load": self.is_high_load(),
            "collector_timeouts": self.get_scaled_collector_timeouts(),
        }
