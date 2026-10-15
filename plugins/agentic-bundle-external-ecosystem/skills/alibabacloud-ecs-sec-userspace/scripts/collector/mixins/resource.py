"""
ResourceMixin: System resource detection and collection degradation.

Monitors memory and CPU resources, automatically degrading collection
intensity when system resources are constrained. Provides data truncation
and memory management utilities.
"""
import os
import time
import itertools
import threading


class ResourceMixin:
    """Mixin for resource detection and degradation management."""

    # Memory thresholds (MB) - below these, degrade collection
    MEMORY_DEGRADED_THRESHOLD = 100.0    # < 100MB available -> degraded mode
    MEMORY_MINIMAL_THRESHOLD = 50.0      # < 50MB available -> minimal mode
    # CPU load ratio thresholds - above these, degrade collection
    LOAD_DEGRADED_THRESHOLD = 5.0        # load/CPU > 5x -> degraded mode
    LOAD_MINIMAL_THRESHOLD = 10.0        # load/CPU > 10x -> minimal mode

    def _detect_resources(self) -> dict:
        """Detect current system resources and return resource state

        Returns:
            dict: Resource state with memory, cpu, load info
        """
        with self._resource_state_lock:
            # Cache resource state for 5 seconds to avoid frequent detection
            if self._resource_state and (time.time() - self._resource_state.get("detected_at", 0) < 5):
                return self._resource_state

            resource_state = {
                "detected_at": time.time(),
                "memory_available_mb": 0.0,
                "memory_total_mb": 0.0,
                "memory_usage_pct": 0.0,
                "cpu_count": 1,
                "load_1min": 0.0,
                "load_ratio": 0.0,
                "degradation_level": "normal",  # normal, degraded, minimal
            }

            # Detect memory
            try:
                with open('/proc/meminfo', 'r', encoding='utf-8', errors='replace') as f:
                    mem_info = {}
                    for line in f:
                        parts = line.split(':')
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip().split()[0]  # kB
                            mem_info[key] = int(value) / 1024.0  # Convert to MB

                    total_mb = mem_info.get("MemTotal", 0)
                    available_mb = mem_info.get("MemAvailable", mem_info.get("MemFree", 0))

                    resource_state["memory_total_mb"] = total_mb
                    resource_state["memory_available_mb"] = available_mb
                    if total_mb > 0:
                        resource_state["memory_usage_pct"] = (total_mb - available_mb) / total_mb * 100
            except (OSError, ValueError, KeyError, IndexError) as e:
                _get_logger().debug(f"[{self.name}] Failed to detect memory: {e}")

            # Detect CPU load
            try:
                resource_state["cpu_count"] = max(1, os.cpu_count() or 1)
                load_avg = os.getloadavg()
                resource_state["load_1min"] = load_avg[0]
                resource_state["load_ratio"] = load_avg[0] / resource_state["cpu_count"]
            except (OSError, AttributeError, ZeroDivisionError) as e:
                _get_logger().debug(f"[{self.name}] Failed to detect CPU load: {e}")

            # Determine degradation level
            mem_available = resource_state["memory_available_mb"]
            load_ratio = resource_state["load_ratio"]

            if mem_available < self.MEMORY_MINIMAL_THRESHOLD or load_ratio > self.LOAD_MINIMAL_THRESHOLD:
                resource_state["degradation_level"] = "minimal"
            elif mem_available < self.MEMORY_DEGRADED_THRESHOLD or load_ratio > self.LOAD_DEGRADED_THRESHOLD:
                resource_state["degradation_level"] = "degraded"
            else:
                resource_state["degradation_level"] = "normal"

            self._resource_state = resource_state
            return resource_state
    def _truncate_data(self, data, max_items: int = None) -> tuple:
        """Truncate data if it exceeds item limit

        Args:
            data: Collected data (dict or list)
            max_items: Maximum items (defaults to max_items_limit)

        Returns:
            Tuple of (truncated_data, was_truncated, original_count)
        """
        limit = max_items or self.max_items_limit

        if isinstance(data, list):
            original_count = len(data)
            if original_count > limit:
                _get_logger().warning(
                    f"[{self.name}] Data truncated from {original_count} to {limit} items"
                )
                return data[:limit], True, original_count
            return data, False, original_count

        elif isinstance(data, dict):
            original_count = len(data)
            if original_count > limit:
                _get_logger().warning(
                    f"[{self.name}] Data truncated from {original_count} to {limit} keys"
                )
                truncated = dict(itertools.islice(data.items(), limit))
                return truncated, True, original_count
            return data, False, original_count

        return data, False, 1

    def _calculate_items_count(self, data) -> int:
        """Calculate meaningful item count from collected data

        For dict results, tries to find the primary data key and count its items.
        For list results, returns the list length.

        Args:
            data: Collected data (dict or list)

        Returns:
            Meaningful item count for logging
        """
        if isinstance(data, list):
            return len(data)

        if isinstance(data, dict):
            # Common primary data keys for collectors
            for key in ("processes", "tcp_connections", "tcp6_connections",
                       "udp_connections", "udp6_connections", "listening_ports",
                       "ssl_connections", "files", "logs", "services", "cron_jobs",
                       "users", "connections", "entries"):
                if key in data and isinstance(data[key], (list, dict)):
                    return len(data[key])

            # Fallback: sum of all list/dict values
            total = 0
            for value in data.values():
                if isinstance(value, (list, dict)):
                    total += len(value)
            if total > 0:
                return total

            # Last resort: count dict keys
            return len(data)

        return 1

    def _record_degradation_metadata(self, result: "CollectResult"):
        """Record degradation metadata in CollectResult

        P1-2026-04-15 Task 7: Updates CollectResult with resource state
        and data quality information.

        Args:
            result: CollectResult to update
        """
        resources = self._detect_resources()
        level = resources["degradation_level"]

        # Update collection mode based on resources
        if level == "minimal":
            result.collection_mode = "survival"
            result.data_quality = "minimal"
            result.expected_completeness = 0.3
        elif level == "degraded":
            result.collection_mode = "quick"
            result.data_quality = "degraded"
            result.expected_completeness = 0.6
        else:
            result.collection_mode = "normal"
            result.data_quality = "complete"
            result.expected_completeness = 1.0

        # Record resource state in data for traceability
        if result.data and isinstance(result.data, dict):
            result.data["_resource_state"] = {
                "memory_available_mb": round(resources["memory_available_mb"], 1),
                "load_ratio": round(resources["load_ratio"], 1),
                "degradation_level": level,
            }


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
