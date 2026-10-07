"""
Collector base class and data models

BaseCollector uses mixin composition:
  ConfigMixin -> TimeoutMixin -> CacheMixin -> ValidationMixin -> ResourceMixin -> RetryMixin
Only core lifecycle (collect template + safe_collect) remains in base.py.
"""
from abc import ABC, abstractmethod
from typing import Optional, List
import os
import signal
import subprocess
import threading
import time

from .mixins import (
    ConfigMixin,
    TimeoutMixin,
    CacheMixin,
    ValidationMixin,
    ResourceMixin,
    RetryMixin,
)
from ..exceptions import TimeoutError as SecInspectTimeout

_logger = None
_logger_lock = threading.Lock()


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


# Resets on each scan start
_timeout_counter = {"count": 0, "last_reset": time.time()}
_timeout_counter_lock = threading.Lock()


def _increment_timeout_counter():
    """Increment global timeout counter and log warning if threshold reached."""
    global _timeout_counter
    should_warn = False
    with _timeout_counter_lock:
        _timeout_counter["count"] += 1
        count = _timeout_counter["count"]
        should_warn = (count >= 5)

    if should_warn:
        _get_logger().warning(
            f"[collector] Timeout threshold reached: {count} commands timed out in current scan. "
            f"This may indicate system resource issues or hanging commands."
        )

    return count

def safe_run_command(cmd: List[str], timeout: int = 10, **kwargs) -> Optional[subprocess.CompletedProcess]:
    """Safely execute a command with timeout protection

    P1-2026-04-15: Wrapper for subprocess.run that ensures all external commands
    have timeout protection and proper error handling.

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds (default: 10)
        **kwargs: Additional arguments passed to subprocess.run

    Returns:
        CompletedProcess on success, None on timeout/failure
    """
    # Security: prevent kwargs from overriding safety-critical parameters
    kwargs.pop('shell', None)    # Forbid shell=True override
    kwargs.pop('stdin', None)    # Forbid stdin override
    kwargs.pop('timeout', None)  # Forbid timeout override
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            **kwargs
        )
        return result
    except subprocess.TimeoutExpired as e:
        _get_logger().warning(
            f"[collector] Command timed out after {timeout}s: {' '.join(cmd[:3])}... "
            f"(timeout #{_increment_timeout_counter()})"
        )
        return None
    except OSError as e:
        _get_logger().debug(f"[collector] Command not found or OS error: {' '.join(cmd[:3])}: {e}")
        return None
    except (ValueError, TypeError, RuntimeError) as e:
        _get_logger().error(f"[collector] Unexpected error running command: {' '.join(cmd[:3])}: {e}")
        return None


def _get_memory_mb() -> float:
    """Get current process memory usage in MB."""
    try:
        with open('/proc/self/status', 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    parts = line.split()
                    return int(parts[1]) / 1024.0
    except OSError:
        pass
    return 0.0


def get_load_aware_timeout(base_timeout: float, multiplier: float = None) -> float:
    """Calculate timeout adjusted for current system load.

    Adjusts the base timeout based on CPU load ratio to prevent
    premature timeouts under high-load conditions while still
    enforcing reasonable limits.

    Args:
        base_timeout: Base timeout in seconds
        multiplier: Optional override multiplier (for testing)

    Returns:
        Adjusted timeout value in seconds
    """
    if multiplier is not None:
        return base_timeout * multiplier

    try:
        load_avg = os.getloadavg()[0]
        cpu_count = os.cpu_count() or 1
        load_ratio = load_avg / cpu_count

        if load_ratio > 20:
            return base_timeout * 3.0
        elif load_ratio > 10:
            return base_timeout * 2.0
        elif load_ratio > 5:
            return base_timeout * 1.5
        elif load_ratio > 2:
            return base_timeout * 1.2
    except (OSError, AttributeError):
        pass

    return base_timeout


class CollectResult:
    """Collect result class - using explicit __init__ to avoid field name obfuscation issues."""

    def __init__(self, status: str, module: str, data: dict = None,
                 reason: str = "", duration: float = 0.0, items_count: int = 0,
                 memory_before_mb: float = 0.0, memory_after_mb: float = 0.0,
                 warning: str = None, completeness: dict = None,
                 collection_mode: str = "normal", data_quality: str = "complete",
                 expected_completeness: float = 1.0, skipped_optional: list = None,
                 data_quality_score: float = None, degraded_fields: list = None):
        self.status = status
        self.module = module
        self.data = data or {}
        self.reason = reason
        self.duration = duration
        self.items_count = items_count
        self.memory_before_mb = memory_before_mb
        self.memory_after_mb = memory_after_mb
        self.warning = warning
        self.completeness = completeness or {}
        self.collection_mode = collection_mode
        self.data_quality = data_quality
        self.expected_completeness = expected_completeness
        self.skipped_optional = skipped_optional or []
        self.data_quality_score = data_quality_score if data_quality_score is not None else self._calculate_default_quality_score()
        self.degraded_fields = degraded_fields or []

    @property
    def memory_delta_mb(self) -> float:
        """Memory delta in MB (after - before)."""
        return self.memory_after_mb - self.memory_before_mb

    def _calculate_default_quality_score(self) -> float:
        """Calculate default data quality score based on quality level."""
        quality_scores = {"complete": 1.0, "degraded": 0.6, "minimal": 0.3}
        return quality_scores.get(self.data_quality, 0.0)

    def is_degraded(self) -> bool:
        """Check if data quality is degraded."""
        return self.data_quality != "complete"

    def get_quality_metadata(self) -> dict:
        """Get data quality metadata for reporting."""
        return {
            "collection_mode": self.collection_mode,
            "data_quality": self.data_quality,
            "expected_completeness": self.expected_completeness,
            "data_quality_score": self.data_quality_score,
            "degraded_fields": self.degraded_fields,
            "skipped_optional": self.skipped_optional,
            "is_degraded": self.is_degraded()
        }


class BaseCollector(
    ConfigMixin,
    TimeoutMixin,
    CacheMixin,
    ValidationMixin,
    ResourceMixin,
    RetryMixin,
    ABC,
):
    """Base collector class with mixin composition.

    MRO (Method Resolution Order):
      BaseCollector -> ConfigMixin -> TimeoutMixin -> CacheMixin ->
      ValidationMixin -> ResourceMixin -> RetryMixin -> ABC -> object

    Only core lifecycle methods remain here:
      - __init__: Initialization
      - collect: Abstract method (subclass implements)
      - safe_collect: Template method with timeout/error handling
    """

    name: str = "base"
    timeout: int = 60
    max_result_size_mb: float = 50.0
    max_items_limit: int = 100000

    def __init__(self):
        """Initialize base collector."""
        self._partial_data = None
        self._collection_metrics = {}
        self._hard_deadline = None
        self._resource_state = None
        self._resource_state_lock = threading.Lock()
        self._config = self._load_collector_config()

    def get_partial_result(self) -> dict:
        """Get partial result data if available. Override in subclasses for progressive collection."""
        return dict(self._partial_data) if self._partial_data else {}

    @abstractmethod
    def collect(self) -> dict:
        """Abstract method, subclass implements specific collection logic."""

    def safe_collect(self, baseline_memory_mb: float = 0.0) -> CollectResult:
        """Safe execution wrapper with timeout, error handling, and memory tracking.

        Args:
            baseline_memory_mb: Memory baseline before first collector (for delta tracking).
        """
        start_time = time.monotonic()
        old_handler = None
        old_alarm = None
        is_main_thread = threading.current_thread() is threading.main_thread()
        memory_before = _get_memory_mb()

        try:
            if is_main_thread:
                old_handler = signal.signal(signal.SIGALRM, self._timeout_handler)
                old_alarm = signal.alarm(self.timeout)

            _get_logger().info(f"[{self.name}] Starting collection...")
            data = self.collect()

            data, validation_warnings = self._validate_data(data)
            if validation_warnings:
                _get_logger().warning(
                    f"[{self.name}] Data validation warnings: {validation_warnings}"
                )

            data, was_truncated, original_count = self._truncate_data(data)
            memory_after = _get_memory_mb()
            duration = time.monotonic() - start_time
            items_count = self._calculate_items_count(data)

            memory_delta = memory_after - memory_before
            truncation_note = f", truncated from {original_count}" if was_truncated else ""
            _get_logger().info(
                f"[{self.name}] Collection complete ({items_count} items{truncation_note}, "
                f"{duration:.1f}s, memory delta: {memory_delta:+.1f}MB)"
            )

            result_data = data
            if was_truncated:
                result_data = dict(data) if isinstance(data, dict) else list(data)
                if isinstance(result_data, dict):
                    result_data['_truncated'] = True
                    result_data['_original_count'] = original_count

            result = CollectResult(
                status="success",
                module=self.name,
                data=result_data,
                duration=duration,
                items_count=items_count,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after
            )
            self._record_degradation_metadata(result)
            self._record_collection_metrics(result)
            return result

        except PermissionError as e:
            duration = time.monotonic() - start_time
            memory_after = _get_memory_mb()
            reason = f"Permission denied: {str(e)}"
            _get_logger().warning(f"[{self.name}] Collection failed: {reason}")
            default_data = self._get_schema_defaults()
            result = CollectResult(
                status="skipped", module=self.name, data=default_data,
                reason=reason, duration=duration,
                memory_before_mb=memory_before, memory_after_mb=memory_after
            )
            self._record_degradation_metadata(result)
            return result

        except (SecInspectTimeout, TimeoutError):  # custom + builtin
            duration = time.monotonic() - start_time
            memory_after = _get_memory_mb()
            reason = f"Module timeout ({self.timeout}s)"
            _get_logger().warning(f"[{self.name}] Collection failed: {reason}")
            partial_data = self.get_partial_result()
            has_partial = partial_data and len(partial_data) > 0

            if has_partial:
                _get_logger().info(
                    f"[{self.name}] Returning partial data on timeout "
                    f"({len(partial_data)} keys, {partial_data.get('total_count', 0)} items)"
                )
                result = CollectResult(
                    status="partial", module=self.name, data=partial_data,
                    reason=reason, duration=duration,
                    memory_before_mb=memory_before, memory_after_mb=memory_after
                )
            else:
                default_data = self._get_schema_defaults()
                result = CollectResult(
                    status="error", module=self.name, data=default_data,
                    reason=reason, duration=duration,
                    memory_before_mb=memory_before, memory_after_mb=memory_after
                )
            self._record_degradation_metadata(result)
            return result

        except FileNotFoundError as e:
            duration = time.monotonic() - start_time
            memory_after = _get_memory_mb()
            reason = f"File not found: {str(e)}"
            _get_logger().warning(f"[{self.name}] Collection failed: {reason}")
            default_data = self._get_schema_defaults()
            result = CollectResult(
                status="skipped", module=self.name, data=default_data,
                reason=reason, duration=duration,
                memory_before_mb=memory_before, memory_after_mb=memory_after
            )
            self._record_degradation_metadata(result)
            return result

        except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as e:
            duration = time.monotonic() - start_time
            memory_after = _get_memory_mb()
            reason = str(e)
            _get_logger().error(f"[{self.name}] Collection failed: {reason}", exc_info=True)
            default_data = self._get_schema_defaults()
            result = CollectResult(
                status="error", module=self.name, data=default_data,
                reason=reason, duration=duration,
                memory_before_mb=memory_before, memory_after_mb=memory_after
            )
            self._record_degradation_metadata(result)
            return result

        finally:
            if is_main_thread:
                signal.alarm(0)
                if old_handler is not None:
                    signal.signal(signal.SIGALRM, old_handler)
                if old_alarm and old_alarm > 0:
                    elapsed = int(time.monotonic() - start_time)
                    remaining = max(1, old_alarm - elapsed)
                    signal.alarm(remaining)
