"""
CacheMixin: Partial result caching and hard deadline setup.

Provides methods to store and retrieve partial collection results
during timeout scenarios, enabling graceful degradation.
"""


class CacheMixin:
    """Mixin for partial result caching and deadline setup."""

    def get_partial_result(self):
        """Return partial data if available (called on timeout)"""
        return self._partial_data

    def set_hard_deadline(self, deadline: float):
        """Set absolute deadline for survival mode enforcement

        Args:
            deadline: Unix timestamp when collection must complete
        """
        self._hard_deadline = deadline
