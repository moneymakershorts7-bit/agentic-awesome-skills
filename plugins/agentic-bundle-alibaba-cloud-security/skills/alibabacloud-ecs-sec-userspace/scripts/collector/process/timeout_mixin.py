"""Mixin for timeout and batch cancellation logic."""
import time
from .constants import _MIN_USER_PROCESS_GUARANTEE


class TimeoutMixin:
    """Mixin providing timeout checking and batch cancellation logic."""

    def _should_skip_due_to_timeout(self) -> bool:
        """Check if we should skip remaining collection due to approaching timeout"""
        if self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time

        soft_timeout = self.timeout * 0.95
        with self._partial_lock:
            proc_count = len(self._partial_processes)
            user_count = sum(1 for p in self._partial_processes if not p.get("_is_kernel_thread"))

        if user_count == 0 and proc_count < _MIN_USER_PROCESS_GUARANTEE:
            if elapsed > 2.0 and proc_count > 0:
                collection_rate = proc_count / elapsed
                if collection_rate < 0.5:
                    return elapsed > 10.0
            return elapsed > self.timeout

        return elapsed > soft_timeout
