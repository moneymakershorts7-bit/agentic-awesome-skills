"""Mixin for command line argument parsing and process identification."""
import logging
import time
import threading

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


class CmdlineMixin:
    """Mixin providing command line parsing and process identification methods."""

    def _check_hard_deadline(self, context: str = "") -> bool:
        """Check if hard deadline has been reached.

        Args:
            context: Description of what operation is being checked

        Returns:
            True if hard deadline exceeded, False otherwise
        """
        from .constants import _PROCESS_COLLECTION_HARD_TIMEOUT
        if self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time
        if elapsed >= _PROCESS_COLLECTION_HARD_TIMEOUT:
            if context:
                _get_logger().debug(
                    f"Process collector: hard deadline reached during {context} "
                    f"(elapsed={elapsed:.1f}s >= {_PROCESS_COLLECTION_HARD_TIMEOUT:.1f}s)"
                )
            return True
        return False
