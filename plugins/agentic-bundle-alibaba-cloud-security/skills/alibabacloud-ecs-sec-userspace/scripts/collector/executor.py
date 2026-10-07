"""
Collector Executor - Sequential execution framework for collectors

Executes collectors one by one in a simple for loop.
No ThreadPoolExecutor, no parallel execution, no SIGALRM-in-threads complexity.
"""
import inspect
import logging
import threading
import time
from typing import Dict, List, Tuple, Type, Optional

from .base import CollectResult, _get_memory_mb
from .config_loader import get_executor_config

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


class CollectorExecutor:
    """Manages sequential execution of collectors.

    Args:
        workspace_dir: Workspace directory for collectors
    """

    def __init__(
        self,
        workspace_dir: Optional[str] = None,
        **kwargs
    ):
        exec_cfg = get_executor_config()
        self.workspace_dir = workspace_dir
        self._global_timeout = exec_cfg.get("global_timeout", 600)

    def execute_all(
        self,
        collectors: List[Tuple[str, Type]],
        stream_out=None,
        throttle_ctrl=None,
        **kwargs
    ) -> Dict[str, CollectResult]:
        """Execute all collectors sequentially.

        Args:
            collectors: List of (name, class) tuples from COLLECTORS registry
            stream_out: Stream output handler for progress
            throttle_ctrl: Throttle controller for resource management

        Returns:
            Dict mapping collector name to CollectResult
        """
        results = {}
        total = len(collectors)

        if throttle_ctrl:
            baseline_memory = throttle_ctrl.set_baseline_memory()
        else:
            baseline_memory = 0.0

        phase_start = time.time()

        for idx, (name, cls) in enumerate(collectors, 1):
            # Global phase timeout
            elapsed = time.time() - phase_start
            if elapsed >= self._global_timeout:
                _get_logger().warning(
                    "Collection phase timeout ({:.1f}s >= {}s). "
                    "Returning {} completed collectors.".format(
                        elapsed, self._global_timeout, len(results)
                    )
                )
                break

            result = self._run_collector(name, cls, baseline_memory)
            results[name] = result

            # Progress
            if stream_out:
                if result.status == "success":
                    stream_out.progress(
                        idx, total, "Collect {}".format(result.module),
                        "Complete ({} items, {:.1f}s)".format(
                            result.items_count, result.duration
                        )
                    )
                else:
                    stream_out.progress(
                        idx, total, "Collect {}".format(name),
                        "{}: {}".format(result.status, result.reason)
                    )

            # Memory check
            if result.status == "success" and throttle_ctrl:
                throttle_ctrl.check_collector_memory_delta(
                    name, result.memory_before_mb, result.memory_after_mb, None
                )

        # Fill error results for any missing collectors (shouldn't happen in sequential)
        expected_names = {n for n, _ in collectors}
        for missing in expected_names - set(results.keys()):
            results[missing] = CollectResult(
                status="error",
                module=missing,
                reason="Skipped due to phase timeout",
                duration=0.0,
                memory_before_mb=baseline_memory,
                memory_after_mb=baseline_memory,
            )

        return results

    def _run_collector(
        self,
        name: str,
        cls: Type,
        baseline_memory: float,
    ) -> CollectResult:
        """Run a single collector sequentially.

        Args:
            name: Collector name
            cls: Collector class
            baseline_memory: Memory baseline

        Returns:
            CollectResult
        """
        start_time = time.monotonic()
        memory_before = _get_memory_mb()

        try:
            # Instantiate
            try:
                sig = inspect.signature(cls.__init__)
                params = {}
                if 'workspace_dir' in sig.parameters:
                    params['workspace_dir'] = self.workspace_dir
                collector = cls(**params) if params else cls()
            except (ValueError, TypeError):
                collector = cls()

            _get_logger().info("[{}] Starting collection...".format(name))
            data = collector.collect()

            memory_after = _get_memory_mb()
            duration = time.monotonic() - start_time

            # Items count
            if hasattr(collector, '_calculate_items_count'):
                items_count = collector._calculate_items_count(data)
            else:
                items_count = len(data) if isinstance(data, (dict, list)) else 1

            _get_logger().info(
                "[{}] Collection complete ({} items, {:.1f}s)".format(
                    name, items_count, duration
                )
            )

            return CollectResult(
                status="success",
                module=name,
                data=data,
                duration=duration,
                items_count=items_count,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after,
            )

        except PermissionError as e:
            duration = time.monotonic() - start_time
            memory_after = _get_memory_mb()
            reason = "Permission denied: {}".format(e)
            _get_logger().warning("[{}] {}".format(name, reason))
            return CollectResult(
                status="skipped",
                module=name,
                reason=reason,
                duration=duration,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after,
            )

        except FileNotFoundError as e:
            duration = time.monotonic() - start_time
            memory_after = _get_memory_mb()
            reason = "File not found: {}".format(e)
            _get_logger().warning("[{}] {}".format(name, reason))
            return CollectResult(
                status="skipped",
                module=name,
                reason=reason,
                duration=duration,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after,
            )

        except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as e:
            duration = time.monotonic() - start_time
            memory_after = _get_memory_mb()
            reason = str(e)
            _get_logger().error(
                "[{}] Collection failed: {}".format(name, reason), exc_info=True
            )
            return CollectResult(
                status="error",
                module=name,
                reason=reason,
                duration=duration,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after,
            )
