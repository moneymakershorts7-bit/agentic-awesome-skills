"""
ValidationMixin: Data validation, schema defaults, and collection metrics.

Ensures analyzers receive valid data even when collectors return incomplete
or empty results. Applies schema defaults for missing required keys.
"""
import copy
import threading


def _get_schemas():
    """Lazy load COLLECTOR_DATA_SCHEMAS to avoid circular imports."""
    from ..schemas import COLLECTOR_DATA_SCHEMAS
    return COLLECTOR_DATA_SCHEMAS


class ValidationMixin:
    """Mixin for data validation and schema enforcement."""

    def _validate_data(self, data: dict) -> tuple:
        """Validate collected data structure and apply defaults for missing fields

        P1-2026-04-15: Ensures analyzers receive valid data even when collectors
        return incomplete or empty results.

        Args:
            data: Raw collected data

        Returns:
            Tuple of (validated_data, validation_warnings)
        """
        schemas = _get_schemas()
        if not isinstance(data, dict):
            _get_logger().warning(
                f"[{self.name}] Collector returned non-dict data type: {type(data).__name__}"
            )
            # Return schema defaults if available
            if self.name in schemas:
                return dict(schemas[self.name]["defaults"]), ["invalid_data_type"]
            return {}, ["invalid_data_type"]

        warnings = []
        schema = schemas.get(self.name, {})
        required_keys = schema.get("required_keys", [])
        defaults = schema.get("defaults", {})

        # Check for required keys
        for key in required_keys:
            if key not in data:
                warnings.append(f"missing_required_key:{key}")
                _get_logger().warning(
                    f"[{self.name}] Missing required key '{key}', applying default"
                )
                if key in defaults:
                    data[key] = copy.deepcopy(defaults[key])
                else:
                    data[key] = []  # Safe default

        # Validate key types - ensure list fields are actually lists
        for key, value in data.items():
            expected_type = defaults.get(key)
            if expected_type is not None:
                if isinstance(expected_type, list) and not isinstance(value, list):
                    warnings.append(f"invalid_type:{key}")
                    _get_logger().warning(
                        f"[{self.name}] Key '{key}' has invalid type {type(value).__name__}, expected list"
                    )
                    data[key] = []
                elif isinstance(expected_type, dict) and not isinstance(value, dict):
                    warnings.append(f"invalid_type:{key}")
                    _get_logger().warning(
                        f"[{self.name}] Key '{key}' has invalid type {type(value).__name__}, expected dict"
                    )
                    data[key] = dict(expected_type)

        return data, warnings

    def _get_schema_defaults(self) -> dict:
        """Get schema defaults for this collector, with deep copy to avoid mutation

        P1-2026-04-15: Returns a copy of schema defaults to prevent
        cross-collector contamination from shared mutable defaults.
        """
        schemas = _get_schemas()
        schema = schemas.get(self.name, {})
        defaults = schema.get("defaults", {})
        # Deep copy to avoid shared mutable defaults
        return copy.deepcopy(defaults)

    def _record_collection_metrics(self, result: "CollectResult"):
        """Record collection effectiveness metrics.

        Args:
            result: CollectResult from safe_collect()
        """
        self._collection_metrics = {
            "collector": self.name,
            "item_count": result.items_count,
            "duration": result.duration,
            "status": result.status,
            "memory_delta_mb": result.memory_delta_mb,
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
