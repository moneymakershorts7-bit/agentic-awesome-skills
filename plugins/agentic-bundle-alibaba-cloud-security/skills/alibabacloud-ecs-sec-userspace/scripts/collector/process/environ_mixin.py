"""Mixin for environment variable reading and namespace operations."""
import logging
import os
import threading
from typing import Dict, List
from ...utils import proc
from .constants import _CRITICAL_ENV_VARS, _STANDARD_LIB_PREFIXES

_logger = None
_lazy_init_lock = threading.Lock()


def _get_logger():
    """Lazy logger initialization."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                _logger = logging.getLogger("sec-userspace")
    return _logger


class EnvironMixin:
    """Mixin providing environment variable and namespace reading methods."""

    def _filter_critical_env_vars(self, pid: int) -> Dict[str, str]:
        """Filter critical environment variables"""
        environ = proc.get_proc_environ(pid)
        return {
            key: environ.get(key, "")
            for key in _CRITICAL_ENV_VARS
            if key in environ
        }

    def _get_namespace_info(self, pid: int) -> Dict[str, str]:
        """Get namespace IDs for a process.

        Args:
            pid: Process ID

        Returns:
            Dictionary mapping namespace types to their IDs
        """
        ns_info = {}
        ns_types = ['mnt', 'pid', 'net', 'uts', 'ipc', 'cgroup']

        for ns_type in ns_types:
            ns_path = f"/proc/{pid}/ns/{ns_type}"
            try:
                result = os.readlink(ns_path)
                ns_info[ns_type] = result
            except (OSError, ValueError):
                continue

        return ns_info

    def _get_non_standard_so_maps(self, pid: int) -> List[str]:
        """Get .so memory mappings from non-standard library directories
        """
        maps = proc.get_proc_maps(pid)
        non_standard = []
        for m in maps:
            pathname = m.get("pathname", "")
            if pathname and ".so" in pathname:
                if not any(
                    pathname.startswith(prefix)
                    for prefix in _STANDARD_LIB_PREFIXES
                ):
                    non_standard.append(pathname)
        return non_standard
