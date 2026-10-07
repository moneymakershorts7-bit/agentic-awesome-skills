"""System Information Collector"""
import socket
import re
import os
from datetime import datetime, timedelta

from .base import BaseCollector
from ..utils import proc
from ..utils.kernel_detector import get_kernel_summary
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


class SystemCollector(BaseCollector):
    """System Information Collector"""
    name = "system"

    def __init__(self):
        """Initialize system collector with config-driven timeouts"""
        super().__init__()
        self.timeout = self._get_config("timeout", 10)

        self._paths = self._get_config("paths", {})

    def collect(self) -> dict:
        """Collect system information with hard deadline checks for survival mode"""
        result = {}

        # 1.1 hostname
        hostname = socket.gethostname()

        # 1.2 os_release
        os_release = self._get_os_release()

        # 1.3 kernel_version - check deadline before expensive operation
        if self._check_hard_deadline("kernel version collection"):
            _get_logger().warning(
                f"[system] Hard deadline reached before kernel version, "
                f"returning partial result"
            )
            return self._build_partial_result(result, "Hard deadline before kernel version")

        kernel_version = self._get_kernel_version()

        # 1.4 kernel_release
        kernel_release = os.uname().release

        # 1.5 arch
        arch = os.uname().machine

        # 1.6 uptime - check deadline before /proc read
        if self._check_hard_deadline("uptime collection"):
            _get_logger().warning(
                f"[system] Hard deadline reached before uptime, "
                f"returning partial result"
            )
            return self._build_partial_result(result, "Hard deadline before uptime")

        uptime_seconds = self._get_uptime()

        # 1.7 boot_time
        boot_time = (datetime.now() - timedelta(seconds=uptime_seconds)).isoformat()

        # 1.8 cpu_count
        cpu_count = os.cpu_count() or 1

        # 1.9 memory - check deadline before /proc/meminfo read
        if self._check_hard_deadline("memory info collection"):
            _get_logger().warning(
                f"[system] Hard deadline reached before memory info, "
                f"returning partial result"
            )
            return self._build_partial_result(result, "Hard deadline before memory info")

        meminfo = proc.get_meminfo()
        memory_total_mb = meminfo.get("MemTotal", 0) // 1024
        memory_available_mb = meminfo.get("MemAvailable", 0) // 1024

        # 1.10 load_avg - check deadline before /proc/loadavg read
        if self._check_hard_deadline("load average collection"):
            _get_logger().warning(
                f"[system] Hard deadline reached before load average, "
                f"returning partial result"
            )
            return self._build_partial_result(result, "Hard deadline before load average")

        loadavg = proc.get_loadavg()
        load_avg = {
            "load1": loadavg.get("load1", 0.0),
            "load5": loadavg.get("load5", 0.0),
            "load15": loadavg.get("load15", 0.0),
        }

        # Kernel capabilities - check deadline
        if self._check_hard_deadline("kernel capabilities collection"):
            _get_logger().warning(
                f"[system] Hard deadline reached before kernel capabilities, "
                f"returning partial result"
            )
            return self._build_partial_result(result, "Hard deadline before kernel capabilities")

        kernel_capabilities = get_kernel_summary()

        return {
            "hostname": hostname,
            "os_release": os_release,
            "kernel_version": kernel_version,
            "kernel_release": kernel_release,
            "arch": arch,
            "uptime_seconds": uptime_seconds,
            "boot_time": boot_time,
            "cpu_count": cpu_count,
            "memory_total_mb": memory_total_mb,
            "memory_available_mb": memory_available_mb,
            "load_avg": load_avg,
            "kernel_capabilities": kernel_capabilities,
        }

    def _build_partial_result(self, result: dict, reason: str) -> dict:
        """Build partial result with collected data so far

        Args:
            result: Partially collected data
            reason: Reason for partial result

        Returns:
            Partial result dict with metadata
        """
        result["_partial"] = True
        result["_partial_note"] = reason
        result.setdefault("hostname", socket.gethostname())
        result.setdefault("os_release", "Unknown")
        result.setdefault("kernel_version", "Unknown")
        result.setdefault("kernel_release", "Unknown")
        result.setdefault("arch", "Unknown")
        result.setdefault("uptime_seconds", 0.0)
        result.setdefault("boot_time", "")
        result.setdefault("cpu_count", 1)
        result.setdefault("memory_total_mb", 0)
        result.setdefault("memory_available_mb", 0)
        result.setdefault("load_avg", {"load1": 0.0, "load5": 0.0, "load15": 0.0})
        result.setdefault("kernel_capabilities", "Unknown")
        return result

    def _get_os_release(self) -> str:
        """Read PRETTY_NAME from /etc/os-release"""
        path = self._paths.get("os_release", "/etc/os-release")
        try:
            with open(path, "r", errors='replace', encoding='utf-8') as f:
                for line in f:
                    match = re.match(r'PRETTY_NAME="(.+)"', line.strip())
                    if match:
                        return match.group(1)
        except (FileNotFoundError, PermissionError):
            pass
        return "Unknown"

    def _get_kernel_version(self) -> str:
        """Read first line of /proc/version"""
        path = self._paths.get("kernel_version", "/proc/version")
        try:
            with open(path, "r", errors='replace', encoding='utf-8') as f:
                return f.readline().strip()
        except (FileNotFoundError, PermissionError):
            return "Unknown"

    def _get_uptime(self) -> float:
        """Read first field from /proc/uptime"""
        path = self._paths.get("uptime", "/proc/uptime")
        try:
            with open(path, "r", errors='replace', encoding='utf-8') as f:
                return float(f.read(256).split()[0])  # /proc/uptime is tiny
        except (FileNotFoundError, PermissionError, ValueError):
            return 0.0
