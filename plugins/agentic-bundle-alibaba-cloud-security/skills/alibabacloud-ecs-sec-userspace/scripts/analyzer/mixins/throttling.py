"""
ThrottleMixin: Memory management and throttling for analyzers.

Extracted from BaseAnalyzer to modularize memory/throttling functionality.
Methods: _get_memory_usage_mb, _check_memory_budget, _trigger_gc, _chunk_iterator
"""
import os
import threading
from typing import Generator

_lazy_init_lock = threading.Lock()

_gc_module = None
def _get_gc():
    """Lazy gc import."""
    global _gc_module
    if _gc_module is None:
        with _lazy_init_lock:
            if _gc_module is None:
                import gc
                _gc_module = gc
    return _gc_module

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


class ThrottleMixin:
    """Mixin providing memory management and throttling for analyzers."""

    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB"""
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return usage.ru_maxrss / 1024  # Convert KB to MB on Linux
        except (OSError, ValueError):
            try:
                with open(f'/proc/{os.getpid()}/status', 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            return int(line.split()[1]) / 1024  # Convert KB to MB
            except (OSError, IndexError):
                pass
        return 0.0

    def _check_memory_budget(self) -> bool:
        """Check if current memory usage is within budget

        Returns:
            bool: True if within budget, False if exceeded
        """
        current_mb = self._get_memory_usage_mb()
        if current_mb > 0 and current_mb > self.memory_budget_mb:
            _get_logger().warning(
                f"[{self.name}] Memory budget exceeded: "
                f"{current_mb:.1f}MB > {self.memory_budget_mb:.1f}MB"
            )
            return False
        return True

    def _trigger_gc(self) -> float:
        """Trigger garbage collection and return freed memory

        Returns:
            float: Memory freed in MB
        """
        before_mb = self._get_memory_usage_mb()
        _get_gc().collect()
        after_mb = self._get_memory_usage_mb()
        freed_mb = before_mb - after_mb
        if freed_mb > 10:
            _get_logger().debug(f"[{self.name}] GC freed {freed_mb:.1f}MB")
        return freed_mb

    def _chunk_iterator(self, data: list, chunk_size: int = None) -> Generator[list, None, None]:
        """Yield chunks of data for memory-efficient processing

        Args:
            data: List of items to chunk
            chunk_size: Size of each chunk (defaults to self.chunk_size)

        Yields:
            list: Chunk of items
        """
        if not data:
            return

        size = chunk_size or self.chunk_size
        for i in range(0, len(data), size):
            yield data[i:i + size]
