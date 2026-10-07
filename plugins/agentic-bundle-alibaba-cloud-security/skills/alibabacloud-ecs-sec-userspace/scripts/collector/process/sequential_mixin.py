"""Mixin for sequential process collection."""
import logging
import os
import time
import threading
from ...utils import proc, throttle

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


class SequentialMixin:
    """Mixin providing sequential collection for standard mode."""

    def _collect_sequential(self) -> dict:
        """Original sequential collection for standard mode."""
        processes = []
        kernel_threads = 0
        user_processes = 0
        inaccessible_pids = []
        skipped_empty_stat = 0
        skipped_permission_error = 0

        throttler = throttle.Throttle()
        system_uptime = self._get_system_uptime()
        num_cpu = proc.get_cpu_count()
        clock_ticks = os.sysconf("SC_CLK_TCK")
        pids = proc.list_pids()
        total_pids = len(pids)

        _get_logger().debug(f"Process collector: starting sequential collection of {total_pids} PIDs")

        for idx, pid in enumerate(pids):
            if (idx + 1) % 50 == 0 and self._should_skip_due_to_timeout():
                elapsed = time.time() - self._scan_start_time
                _get_logger().warning(
                    f"Process collector: soft timeout reached at {idx+1}/{total_pids} PIDs "
                    f"({elapsed:.1f}s), returning partial data with {len(processes)} processes"
                )
                self._update_partial_result(
                    processes,
                    f"Soft timeout: {len(processes)} processes collected from {idx+1}/{total_pids} PIDs ({elapsed:.1f}s)"
                )
                with self._partial_lock:
                    self._partial_data["_partial"] = True
                    self._partial_data["_soft_timeout"] = True
                return self.get_partial_result()

            try:
                stat = proc.get_proc_stat(pid)
                if not stat:
                    skipped_empty_stat += 1
                    continue

                cmdline = proc.get_proc_cmdline(pid, max_length=65536)
                if not cmdline:
                    kernel_threads += 1
                else:
                    user_processes += 1

                process_info = self._collect_process_details(
                    pid, stat, cmdline, system_uptime, num_cpu, clock_ticks
                )
                processes.append(process_info)

                if len(processes) % 50 == 0:
                    elapsed = time.time() - self._scan_start_time
                    self._update_partial_result(
                        processes,
                        f"{len(processes)} processes collected ({elapsed:.1f}s)..."
                    )
                    self._log_progress(
                        f"collected {len(processes)}/{total_pids} processes",
                        elapsed
                    )

                if (idx + 1) % 50 == 0:
                    throttler.batch_sleep(idx + 1, batch_size=50)

            except PermissionError as e:
                skipped_permission_error += 1
                inaccessible_pids.append(pid)
                continue
            except (FileNotFoundError, ProcessLookupError):
                inaccessible_pids.append(pid)
                continue
            except OSError as e:
                _get_logger().warning(f"Process {pid} OS error: {e}")
                continue
            except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as e:
                _get_logger().warning(f"Process {pid} unknown error: {type(e).__name__}: {e}")
                continue

        self._log_inaccessible_pids(inaccessible_pids)

        if skipped_permission_error > 0:
            _get_logger().debug(
                f"Process collector: {skipped_permission_error} PIDs denied by permissions"
            )

        result = {
            "processes": processes,
            "total_count": len(processes),
            "kernel_threads": kernel_threads,
            "user_processes": user_processes,
        }

        elapsed = time.time() - self._scan_start_time
        self._update_partial_result(
            processes,
            f"Complete: {len(processes)} processes collected ({elapsed:.1f}s)"
        )
        with self._partial_lock:
            self._partial_data["_partial"] = False
        self._log_progress("collection completed", elapsed)

        completeness = self._calculate_completeness_internal(len(processes))
        result["_completeness"] = completeness

        _get_logger().debug(
            f"Process collector: returning {len(processes)} processes "
            f"({kernel_threads} kernel threads, {user_processes} user processes)"
        )

        return result
