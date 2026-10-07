"""Report Generation Optimizations

Provides:
1. Template caching with TTL and LRU eviction
2. Alert truncation for large alert counts (>1000)
3. Cached report section generation
4. Parallel report generation
"""
import hashlib
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================================
# Template Cache - Thread-safe LRU cache with TTL
# ============================================================================

class ReportTemplateCache:
    """Thread-safe LRU cache with TTL for report template sections."""

    def __init__(self, ttl_seconds: int = 300, max_size: int = 50):
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._cache: Dict[str, Tuple[float, str]] = {}
        self._access_order: List[str] = []
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            if key not in self._cache:
                return None
            ts, content = self._cache[key]
            if time.monotonic() - ts > self._ttl:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                return None
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
            return content

    def put(self, key: str, content: str) -> None:
        with self._lock:
            if key in self._cache:
                if key in self._access_order:
                    self._access_order.remove(key)
            elif len(self._cache) >= self._max_size:
                if self._access_order:
                    evict_key = self._access_order.pop(0)
                    self._cache.pop(evict_key, None)
                else:
                    oldest_key = next(iter(self._cache))
                    self._cache.pop(oldest_key, None)
            self._cache[key] = (time.monotonic(), content)
            self._access_order.append(key)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._access_order.clear()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total_size = sum(len(c) for _, c in self._cache.values())
            return {
                'entries': len(self._cache),
                'total_size_bytes': total_size,
                'max_size': self._max_size,
                'ttl_seconds': self._ttl,
            }

    def compute_key(self, section_type: str, **kwargs) -> str:
        raw = section_type + '|' + '|'.join(
            f'{k}={v}' for k, v in sorted(kwargs.items())
        )
        return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


_template_cache: Optional[ReportTemplateCache] = None
_cache_lock = threading.Lock()


def get_template_cache() -> ReportTemplateCache:
    global _template_cache
    if _template_cache is None:
        with _cache_lock:
            if _template_cache is None:
                _template_cache = ReportTemplateCache()
    return _template_cache


# ============================================================================
# Cached Report Section Generators
# ============================================================================

def get_cached_system_info_section(system_info: Dict[str, Any]) -> str:
    cache = get_template_cache()
    key = cache.compute_key(
        'system_info',
        hostname=system_info.get('hostname', ''),
        os_release=system_info.get('os_release', ''),
        kernel_version=system_info.get('kernel_version', ''),
    )
    cached = cache.get(key)
    if cached is not None:
        return cached

    section = (
        f"### System Information\n\n"
        f"| Item | Value |\n"
        f"|------|-------|\n"
        f"| Hostname | {system_info.get('hostname', 'N/A')} |\n"
        f"| OS | {system_info.get('os_release', 'N/A')} |\n"
        f"| Kernel | {system_info.get('kernel_version', 'N/A')} |\n"
        f"| CPU | {system_info.get('cpu_count', 'N/A')} cores |\n"
        f"| Memory | {system_info.get('memory_total_mb', 'N/A')}MB |\n"
    )
    cache.put(key, section)
    return section


def get_cached_performance_section(performance: Dict[str, Any]) -> str:
    cache = get_template_cache()
    key = cache.compute_key(
        'performance',
        total_duration=str(performance.get('total_duration', 0)),
        peak_memory_mb=str(performance.get('peak_memory_mb', 0)),
    )
    cached = cache.get(key)
    if cached is not None:
        return cached

    section = (
        f"### Performance\n\n"
        f"| Metric | Value |\n"
        f"|--------|-------|\n"
        f"| Duration | {performance.get('total_duration', 0)}s |\n"
        f"| Peak Memory | {performance.get('peak_memory_mb', 0)}MB |\n"
        f"| CPU Time | {performance.get('cpu_time', 0)}s |\n"
    )
    cache.put(key, section)
    return section


# ============================================================================
# Parallel Report Generator
# ============================================================================

class ParallelReportGenerator:
    """Generate multiple report formats in parallel."""

    def __init__(self, max_workers: int = 2):
        self._max_workers = max_workers

    def generate_reports_parallel(
        self,
        markdown_generator,
        json_generator,
        markdown_args: tuple,
        json_args: tuple,
        output_dir: str,
        date_str: str,
    ) -> Dict[str, Optional[str]]:
        results: Dict[str, Optional[str]] = {'markdown': None, 'json': None}

        def _gen_markdown():
            try:
                content = markdown_generator.generate(*markdown_args)
                path = os.path.join(output_dir, f"report-{date_str}.md")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return path
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                logger.exception("Markdown report generation failed")
                return None

        def _gen_json():
            try:
                content = json_generator.generate(*json_args)
                path = os.path.join(output_dir, f"report-{date_str}.json")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return path
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                logger.exception("JSON report generation failed")
                return None

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            md_future = pool.submit(_gen_markdown)
            json_future = pool.submit(_gen_json)
            results['markdown'] = md_future.result()
            results['json'] = json_future.result()

        return results


# ============================================================================
# Alert Truncation - Smart truncation for large alert counts
# ============================================================================

MAX_ALERTS_IN_REPORT = 1000  # Maximum alerts to include in full report
TOP_ALERTS_TO_SHOW = 50  # Show top N alerts in detail
TRUNCATION_NOTICE = (
    "\n> **注意**: 告警数量超过 {max_alerts} 条，仅显示前 {top_n} 条最重要告警。\n"
    "> 完整告警列表请查看 JSON 报告。\n\n"
)


def truncate_alerts_for_report(
    evidences: List[Any],
    max_alerts: int = MAX_ALERTS_IN_REPORT,
    top_to_show: int = TOP_ALERTS_TO_SHOW,
) -> Tuple[List[Any], bool, Dict[str, int]]:
    """Truncate alerts for report generation when count exceeds threshold.

    Args:
        evidences: List of evidence objects
        max_alerts: Maximum alerts to include in report
        top_to_show: Number of top alerts to show in detail

    Returns:
        Tuple of (truncated_evidences, was_truncated, stats)
    """
    total_count = len(evidences) if evidences else 0

    if total_count <= max_alerts:
        return evidences, False, {'total': total_count, 'included': total_count, 'truncated': 0}

    # Sort by weighted_score to keep most important alerts
    try:
        import math
        def _safe_score(e):
            s = getattr(e, 'weighted_score', 0)
            return 0 if (isinstance(s, float) and (math.isnan(s) or math.isinf(s))) else s
        sorted_evidences = sorted(
            evidences,
            key=_safe_score,
            reverse=True
        )
    except (TypeError, ValueError):
        sorted_evidences = evidences

    # Keep top alerts
    truncated = sorted_evidences[:top_to_show]

    stats = {
        'total': total_count,
        'included': len(truncated),
        'truncated': total_count - len(truncated),
        'truncation_threshold': max_alerts,
    }

    logger.info(
        "Alert truncation: {} total alerts -> {} included "
        "({} truncated, threshold: {})".format(
            total_count, len(truncated), total_count - len(truncated), max_alerts
        )
    )

    return truncated, True, stats


def get_truncation_markdown(stats: Dict[str, int]) -> str:
    """Generate truncation notice markdown."""
    return TRUNCATION_NOTICE.format(
        max_alerts=stats.get('truncation_threshold', MAX_ALERTS_IN_REPORT),
        top_n=stats.get('included', TOP_ALERTS_TO_SHOW),
    )
