"""
TimeoutMixin: Hard deadline and soft timeout enforcement.

Provides methods to track and enforce absolute deadlines for collection
operations, supporting survival mode where partial results are preferred
over complete timeouts.
"""
import time
import threading

from ...exceptions import TimeoutError as SecInspectTimeout


class TimeoutMixin:
    """Mixin for timeout and deadline management."""

    def _check_hard_deadline(self, operation: str = "collection") -> bool:
        """Check if hard deadline has been reached

        Args:
            operation: Current operation name (for logging)

        Returns:
            True if deadline reached (should abort), False otherwise
        """
        if hasattr(self, '_bypass_hard_deadline') and self._bypass_hard_deadline:
            return False

        if self._hard_deadline is None:
            return False

        if time.time() >= self._hard_deadline:
            remaining = self._hard_deadline - time.time()
            _get_logger().warning(
                f"[{self.name}] Hard deadline reached during {operation}, "
                f"aborting to prevent timeout (overdue by {abs(remaining):.1f}s)"
            )
            return True
        return False
    def _should_skip_due_to_timeout(self) -> bool:
        """Check if soft timeout has been reached during progressive collection

        Returns:
            True if 80% of timeout has elapsed, indicating we should stop
        """
        if not hasattr(self, '_scan_start_time') or self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time
        soft_timeout = self.timeout * 0.8  # 80% threshold
        return elapsed > soft_timeout

    def _timeout_handler(self, signum, frame):
        """Timeout signal handler"""
        raise SecInspectTimeout(f"Collector {self.name} timeout ({self.timeout}s)")


_logger = None
_lazy_init_lock = threading.Lock()


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger
