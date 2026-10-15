"""Process Information Collector - Orchestrator composed from mixins."""
import logging
import threading
import time
from typing import Dict, Any
from ..base import BaseCollector
from ...utils import proc
from .proc_parser_mixin import ProcParserMixin
from .cmdline_mixin import CmdlineMixin
from .tree_builder_mixin import TreeBuilderMixin
from .environ_mixin import EnvironMixin
from .status_parser_mixin import StatusParserMixin
from .timeout_mixin import TimeoutMixin
from .sequential_mixin import SequentialMixin
_logger = None
_logger_lock = threading.Lock()


def _get_logger():
    """Lazy logger initialization."""
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                _logger = logging.getLogger("sec-userspace")
    return _logger


class ProcessCollector(
    ProcParserMixin,
    CmdlineMixin,
    TreeBuilderMixin,
    EnvironMixin,
    StatusParserMixin,
    TimeoutMixin,
    SequentialMixin,
    BaseCollector,
):
    """Process Information Collector - composed from mixins."""
    name = "process"

    def __init__(self):
        """Initialize process collector."""
        super().__init__()

        self.timeout = self._get_config("timeout", 120)
        self._max_processes = self._get_config("max_processes", 500)
        self._thread_count = self._get_config("thread_count", 20)

        self._paths = self._get_config("paths", {})
        self._proc_dir = self._paths.get("proc_dir", "/proc")

        self._partial_processes = []
        self._partial_lock = threading.Lock()
        self._scan_start_time = None
        self._early_return_lock = threading.Lock()
    def _calculate_completeness_internal(self, proc_count: int) -> dict:
        """Calculate data completeness score for partial results (internal, no lock)"""
        phases = {
            "processes_collected": proc_count > 0,
            "kernel_threads_counted": True,
            "user_processes_counted": True,
        }
        phase_weights = {
            "processes_collected": 0.70,
            "kernel_threads_counted": 0.15,
            "user_processes_counted": 0.15,
        }
        score = sum(weight for phase, weight in phase_weights.items()
                    if phases.get(phase, False))
        has_process_list = proc_count > 0
        warnings = []
        if not has_process_list:
            warnings.append("No process data collected - all process-based detections unavailable")

        return {
            "score": round(score, 2),
            "phases_completed": phases,
            "data_sufficient": has_process_list,
            "total_processes": proc_count,
            "warnings": warnings,
        }

    def _calculate_completeness(self) -> dict:
        """Calculate data completeness score for partial results (public, with lock)"""
        with self._partial_lock:
            proc_count = len(self._partial_processes)
            return self._calculate_completeness_internal(proc_count)

    def _update_partial_result(self, processes: list, phase_note: str):
        """Update partial result data for timeout recovery"""
        with self._partial_lock:
            self._partial_processes = list(processes)
            completeness = self._calculate_completeness_internal(len(processes))
            self._partial_data = {
                "processes": list(processes),
                "total_count": len(processes),
                "kernel_threads": 0,
                "user_processes": len(processes),
                "_partial": True,
                "_partial_note": phase_note,
                "_completeness": completeness,
            }

    def get_partial_result(self) -> dict:
        """Get partial result data if available"""
        with self._partial_lock:
            return dict(self._partial_data) if self._partial_data else {}

    def _log_progress(self, stage: str, elapsed: float):
        """Log collection progress with timing information"""
        _get_logger().debug(f"Process collector: {stage} ({elapsed:.1f}s)")

    def _collect_process_details(
        self, pid: int, stat: Dict, cmdline: str,
        system_uptime: float, num_cpu: int, clock_ticks: int
    ) -> Dict[str, Any]:
        """Collect detailed information for a single process (full mode)"""
        exe = proc.get_proc_exe(pid)
        cwd = proc.get_proc_cwd(pid)
        filtered_environ = self._filter_critical_env_vars(pid)
        fd_list = self._get_socket_pipe_fds(pid)
        fd_info = self._get_all_fd_info(pid)
        cap_effective = self._get_cap_effective(pid)
        namespace = self._get_namespace_info(pid)
        maps_summary = self._get_non_standard_so_maps(pid)
        cpu_percent, mem_rss_kb, runtime_seconds = self._get_proc_resource_usage(
            pid, system_uptime, num_cpu, clock_ticks
        )

        return {
            "pid": pid,
            "comm": stat.get("comm", ""),
            "cmdline": cmdline,
            "exe": exe,
            "cwd": cwd,
            "state": stat.get("state", ""),
            "ppid": stat.get("ppid", 0),
            "uid": stat.get("uid", 0),
            "environ": filtered_environ,
            "fd_list": fd_list,
            "fd_info": fd_info,
            "cap_effective": cap_effective,
            "namespace": namespace,
            "maps_summary": maps_summary,
            "cpu_percent": cpu_percent,
            "mem_rss_kb": mem_rss_kb,
            "runtime_seconds": runtime_seconds,
        }
    def collect(self) -> dict:
        """Collect process information with progressive results"""
        self._scan_start_time = time.time()
        self._update_partial_result([], "Starting process collection...")
        return self._collect_sequential()
