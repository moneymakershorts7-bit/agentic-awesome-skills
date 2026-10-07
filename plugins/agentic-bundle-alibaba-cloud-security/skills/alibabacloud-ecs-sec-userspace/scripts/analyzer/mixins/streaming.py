"""
StreamingMixin: Streaming and chunked analysis for analyzers.

Extracted from BaseAnalyzer to modularize streaming analysis functionality.
Methods: _stream_analyze_item, stream_analyze, analyze_in_chunks
"""
import threading
from typing import Dict, Generator, List


# Lazy logger
_logger = None
_logger_lock = threading.Lock()
def _get_logger():
    """Lazy logger initialization."""
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


class StreamingMixin:
    """Mixin providing streaming and chunked analysis for analyzers."""

    def _stream_analyze_item(self, item: dict) -> List['Evidence']:
        """Analyze a single item and return evidence

        Default implementation returns empty list. Subclasses can override
        this method to implement per-item analysis for streaming mode.

        Args:
            item: Single data item to analyze

        Returns:
            List[Evidence]: Evidence found for this item
        """
        return []

    def stream_analyze(
        self,
        collected_data: Dict[str, 'CollectResult'],
        collector_name: str,
        data_key: str = None
    ) -> Generator['Evidence', None, None]:
        """Stream analysis over collector data with memory budget enforcement

        This method yields evidence one at a time, processing data in chunks
        to maintain memory efficiency. Subclasses can override to provide
        custom streaming logic.

        Args:
            collected_data: Dict of collector results
            collector_name: Name of collector to stream
            data_key: Key within collector data to iterate (None for list data)

        Yields:
            Evidence: Each evidence item as it's found

        Example:
            for evidence in self.stream_analyze(collected_data, "process", "processes"):
                evidences.append(evidence)
        """
        try:
            data = self._get_data(collected_data, collector_name)
        except KeyError:
            return

        if data_key:
            items = data.get(data_key, [])
        else:
            items = data if isinstance(data, list) else []

        if not items:
            return

        total_items = len(items)
        processed = 0
        chunk_count = 0

        for chunk in self._chunk_iterator(items):
            chunk_count += 1

            # Check memory budget every 10 chunks
            if chunk_count % 10 == 0:
                if not self._check_memory_budget():
                    _get_logger().warning(
                        f"[{self.name}] Memory budget exceeded, "
                        f"running GC and continuing with reduced data"
                    )
                    self._trigger_gc()

            for item in chunk:
                processed += 1
                try:
                    evidences = self._stream_analyze_item(item)
                    for evidence in evidences:
                        yield evidence
                except (OSError, TypeError, KeyError, ValueError, RuntimeError) as e:
                    _get_logger().debug(f"[{self.name}] Failed to process item {processed}: {e}")
                    continue

            # Release chunk memory
            del chunk
            if chunk_count % 5 == 0:
                self._trigger_gc()

        _get_logger().info(
            f"[{self.name}] Stream analysis complete: "
            f"{processed}/{total_items} items processed"
        )

    def analyze_in_chunks(
        self,
        collected_data: Dict[str, 'CollectResult'],
        collector_name: str,
        data_key: str = None,
        process_chunk_func=None
    ) -> List['Evidence']:
        """Process data in chunks with custom chunk processing function

        Args:
            collected_data: Dict of collector results
            collector_name: Name of collector to process
            data_key: Key within collector data (None for list data)
            process_chunk_func: Function to process each chunk, signature:
                func(chunk: list, analyzer: BaseAnalyzer) -> List[Evidence]

        Returns:
            List[Evidence]: All evidence found
        """
        try:
            data = self._get_data(collected_data, collector_name)
        except KeyError:
            return []

        if data_key:
            items = data.get(data_key, [])
        else:
            items = data if isinstance(data, list) else []

        if not items:
            return []

        all_evidences = []
        chunk_count = 0

        for chunk in self._chunk_iterator(items):
            chunk_count += 1

            # Memory budget check
            if chunk_count % 10 == 0 and not self._check_memory_budget():
                _get_logger().warning(f"[{self.name}] Memory budget exceeded, triggering GC")
                self._trigger_gc()

            # Process chunk
            if process_chunk_func:
                evidences = process_chunk_func(chunk, self)
                if evidences:
                    all_evidences.extend(evidences)

            # Release chunk
            del chunk

            # Periodic GC
            if chunk_count % 5 == 0:
                self._trigger_gc()

        return all_evidences
