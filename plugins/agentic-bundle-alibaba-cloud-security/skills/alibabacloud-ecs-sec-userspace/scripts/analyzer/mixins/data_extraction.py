"""
DataExtractionMixin: Unified CollectResult data extraction.

Original location: scripts/analyzer/mixins.py
Moved to mixins/ package for modularization.
"""
import threading
from functools import wraps

_lazy_init_lock = threading.Lock()

_mixin_logger = None
def _get_mixin_logger():
    """Lazy logger to avoid importing logging at module load."""
    global _mixin_logger
    if _mixin_logger is None:
        with _lazy_init_lock:
            if _mixin_logger is None:
                import logging
                _mixin_logger = logging.getLogger("sec-userspace")
    return _mixin_logger


def _validate_collectresult_usage(func):
    """Decorator to validate CollectResult handling in _get_data implementations.

    This runtime check helps detect when custom _get_data implementations
    don't properly check the status field of CollectResult objects.
    """
    @wraps(func)
    def wrapper(self, collected_data, collector_name, *args, **kwargs):
        # Call the original function
        result = func(self, collected_data, collector_name, *args, **kwargs)

        if collected_data is None or not isinstance(collected_data, dict):
            return result

        # Validate if we're returning data from a CollectResult object
        if collector_name in collected_data:
            collector_result = collected_data[collector_name]

            # Check if it's a CollectResult-like object
            if hasattr(collector_result, 'status') and hasattr(collector_result, 'data'):
                # Log warning if returning data from failed collector
                # Skip warning for 'partial' status as this is expected under survival mode
                if collector_result.status not in ('success', 'partial') and result is not None:
                    _get_mixin_logger().warning(
                        f"[{getattr(self, 'name', 'unknown')}] "
                        f"Returning data from {collector_name} with status '{collector_result.status}'. "
                        f"This may indicate improper CollectResult handling."
                    )

        return result

    return wrapper


class DataExtractionMixin:
    """Mixin providing unified CollectResult data extraction"""

    def extract_data(self, result, default=None):
        """
        Extract data from CollectResult or return raw data.

        Args:
            result: CollectResult object or raw data
            default: Default value if extraction fails

        Returns:
            Extracted data or default
        """
        if result is None:
            return default

        # Check if it's a CollectResult-like object
        if hasattr(result, 'data'):
            if hasattr(result, 'status'):
                if result.status == 'success':
                    return result.data
                elif result.status == 'partial':
                    # Partial result from timeout - return whatever was collected
                    reason = getattr(result, 'reason', 'unknown reason')
                    _get_mixin_logger().warning(f"Using partial data from collector (timeout): {reason}")
                    return result.data if result.data else default
                else:
                    reason = getattr(result, 'reason', 'unknown reason')
                    _get_mixin_logger().warning(f"Collection failed: {reason}")
                    return default
            else:
                return result.data

        # Return raw data (for testing or backward compatibility)
        return result

    def extract_multi(self, collected_data: dict, keys: list, defaults: list = None) -> tuple:
        """
        Extract multiple data sources at once.

        Args:
            collected_data: Dict of collector results
            keys: List of keys to extract
            defaults: Optional list of default values for each key

        Returns:
            Tuple of extracted data in order of keys
        """
        if defaults is None:
            defaults = [None] * len(keys)
        elif len(defaults) != len(keys):
            raise ValueError("defaults length must match keys length")

        return tuple(
            self.extract_data(collected_data.get(key), default)
            for key, default in zip(keys, defaults)
        )

    @_validate_collectresult_usage
    def _get_data(self, collected_data: dict, collector_name: str, default: dict = None, strict=False):
        """
        Get data from specified collector in collected_data.

        This is a convenience wrapper around extract_data() for single collector access.

        Supports three formats:
        1. CollectResult object format: {"collector_name": CollectResult(...)}
        2. Dictionary format (for testing): {"collector_name": {"data_key": ...}}
        3. List format (for testing): {"collector_name": [...]}

        Args:
            collected_data: Dict of collector results
            collector_name: Name of the collector to extract data from
            default: Default value if collector not found or failed (defaults to empty dict)
            strict: If True, raise KeyError when collector not found or failed (default behavior)
                   If False, return default value

        Returns:
            Extracted data or default

        Raises:
            KeyError: If collector not found or failed (when strict=True)
        """
        if collected_data is None:
            _get_mixin_logger().warning(
                f"[{getattr(self, 'name', 'unknown')}] Input data is None, returning empty dict"
            )
            return {}

        if not isinstance(collected_data, dict):
            _get_mixin_logger().warning(
                f"[{getattr(self, 'name', 'unknown')}] Input data type mismatch: "
                f"expected dict, got {type(collected_data).__name__}"
            )
            return {}

        if collector_name not in collected_data:
            if strict:
                raise KeyError(f"Collector '{collector_name}' not found")
            return {}

        result = collected_data[collector_name]

        # CollectResult object format - check this FIRST before dict/list checks
        # CollectResult has both .status and .data attributes
        if hasattr(result, 'status') and hasattr(result, 'data'):
            if result.status == "success":
                return result.data
            elif result.status == "partial":
                # Partial result from timeout - return whatever was collected
                reason = getattr(result, 'reason', 'unknown reason')
                _get_mixin_logger().warning(
                    f"Collector '{collector_name}' has partial result (timeout): {reason}, "
                    f"using partial data ({len(result.data) if result.data else 0} keys)"
                )
                if result.data:
                    return result.data
                if strict:
                    raise KeyError(f"Collector '{collector_name}' partial result has no data: {reason}")
                return {}
            else:
                # Error or skipped status
                reason = getattr(result, 'reason', 'unknown reason')
                _get_mixin_logger().warning(
                    f"Collector '{collector_name}' status is {result.status}: {reason}, "
                    f"attempting to use partial data"
                )
                if strict:
                    raise KeyError(f"Collector '{collector_name}' status is {result.status}: {reason}")
                # Return partial data if available, otherwise empty dict
                return result.data if result.data else {}

        # Support dictionary format (for testing or backward compatibility)
        if isinstance(result, dict):
            return result

        # Support list format (for testing)
        if isinstance(result, list):
            return result

        # Fallback: return as-is
        return result

    def _get_data_safe(self, collected_data: dict, key: str, default=None):
        """Safely extract data from collected data with error handling.

        Wraps _get_data() to catch KeyError and other exceptions,
        returning a default value instead of raising.

        Args:
            collected_data: Dict of collector results
            key: Collector name to extract
            default: Default value if extraction fails (defaults to empty dict)

        Returns:
            Extracted data or default
        """
        try:
            return self._get_data(collected_data, key) or (default if default is not None else {})
        except (KeyError, TypeError, AttributeError):
            return default if default is not None else {}

