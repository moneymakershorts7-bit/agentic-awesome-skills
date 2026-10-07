"""Cilium analyzer helpers - lazy import helpers and module-level utilities."""
import threading

_lazy_init_lock = threading.Lock()

_logger = None
def _get_logger():
    """Lazy logger initialization."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger
