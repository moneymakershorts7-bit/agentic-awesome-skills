"""Mixin for /proc/[pid]/status parsing and file descriptor operations."""
import logging
import os
import threading
from typing import Dict, List
from ...utils import proc
from .constants import _SOCKET_PIPE_TYPES

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


class StatusParserMixin:
    """Mixin providing /proc/[pid]/status parsing and FD operations."""

    def _get_cap_effective(self, pid: int) -> str:
        """Get effective capabilities from /proc/[pid]/status

        Returns hex string of CapEff field, or empty string if unavailable.
        """
        try:
            status_content = proc.read_proc_file(pid, "status")
            if status_content:
                for line in status_content.split('\n'):
                    if line.startswith('CapEff:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
        except (ValueError, IndexError, OSError):
            pass

        return ""

    def _get_all_fd_info(self, pid: int) -> List[Dict]:
        """Get all file descriptor information with full paths

        Returns list of dicts with fd number and resolved path.
        Limited to reduce memory usage in quick mode.
        """
        fd_dir = f"/proc/{pid}/fd"
        fd_info = []

        # Reduce limit in quick mode to save memory
        max_fds = 100

        try:
            fds = os.listdir(fd_dir)
            for fd_num in fds[:max_fds]:  # Limit FDs based on scan mode
                try:
                    fd_path = os.readlink(os.path.join(fd_dir, fd_num))
                    fd_info.append({
                        "fd": int(fd_num),
                        "path": fd_path
                    })
                except (OSError, ValueError):
                    continue
        except OSError:
            pass

        return fd_info

    def _get_socket_pipe_fds(self, pid: int) -> List[Dict]:
        """Get socket and pipe type file descriptors"""
        fd_list = proc.get_proc_fd_list(pid)
        return [
            fd for fd in fd_list
            if fd.get("type") in _SOCKET_PIPE_TYPES
        ][:50]

    def _log_inaccessible_pids(self, pids: List[int]) -> None:
        """Log inaccessible process IDs"""
        if not pids:
            return
        if len(pids) <= 10:
            _get_logger().debug(f"Skipped {len(pids)} inaccessible processes: PIDs {pids}")
        else:
            _get_logger().debug(f"Skipped {len(pids)} inaccessible processes: PIDs {pids[:5]}...{pids[-1]}")
