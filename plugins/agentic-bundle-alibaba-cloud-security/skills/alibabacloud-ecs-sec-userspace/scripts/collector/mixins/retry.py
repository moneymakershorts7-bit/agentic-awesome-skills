"""
RetryMixin: Retry logic with exponential backoff and collection metrics.

Provides retry mechanism for transient failures during collection,
with exponential backoff and comprehensive metrics tracking.
"""

class RetryMixin:
    """Mixin for retry logic and collection metrics."""
    def get_collection_metrics(self) -> dict:
        """Get collection effectiveness metrics

        Returns:
            Dict with collection metrics (item_count, duration, status, etc.)
        """
        return dict(self._collection_metrics) if self._collection_metrics else {}
