"""CPU/Memory Throttle Control Tool"""
import time
import resource
import gc
import logging
from ..collector.base import _get_memory_mb as get_memory_mb_from_base


class Throttle:
    """CPU adaptive throttle + memory monitoring"""

    def __init__(self, target_cpu_percent: float = 5.0, memory_limit_mb: int = 300,
                 per_collector_budget_mb: float = 50.0):
        self.target_cpu_percent = target_cpu_percent
        self.memory_limit_mb = memory_limit_mb
        self.per_collector_budget_mb = per_collector_budget_mb  # Per-collector memory delta budget
        self._last_check_time = time.monotonic()
        self._last_cpu_time = self._get_cpu_time()
        self._peak_memory_mb = 0.0
        self._memory_samples = []
        self._baseline_memory_mb = 0.0  # Baseline memory before first collector
        self._collector_memory_deltas = {}  # Track per-collector memory deltas
        self.logger = logging.getLogger("sec-userspace")

    def _get_cpu_time(self) -> float:
        """Get process CPU time"""
        ru = resource.getrusage(resource.RUSAGE_SELF)
        return ru.ru_utime + ru.ru_stime

    def _get_memory_mb(self) -> float:
        """Get current VmRSS in MB - delegates to shared implementation"""
        return get_memory_mb_from_base()

    def force_gc(self) -> float:
        """Force garbage collection and return freed memory in MB"""
        before = self._get_memory_mb()
        gc.collect()
        gc.collect()
        after = self._get_memory_mb()
        freed = before - after
        if freed > 5:
            self.logger.info(f"GC freed {freed:.1f}MB (before={before:.1f}MB, after={after:.1f}MB)")
        return freed

    def throttle(self):
        """Core throttle method, call between batch operations"""
        now = time.monotonic()
        cpu_time = self._get_cpu_time()

        wall_delta = now - self._last_check_time
        cpu_delta = cpu_time - self._last_cpu_time

        if wall_delta > 0 and cpu_delta > 0:
            cpu_percent = (cpu_delta / wall_delta) * 100

            if cpu_percent > self.target_cpu_percent:
                sleep_time = cpu_delta * (100 / self.target_cpu_percent - 1) - (wall_delta - cpu_delta)
                sleep_time = max(0.01, min(1.0, sleep_time))
                time.sleep(sleep_time)

        self._last_check_time = time.monotonic()
        self._last_cpu_time = self._get_cpu_time()

    def check_memory(self) -> bool:
        """Check current memory usage

        Returns:
            True if memory is within limits, False if exceeded
        """
        current_mb = self._get_memory_mb()
        if current_mb <= 0:
            self.logger.warning("Unable to read memory information")
            return True

        # Track peak memory
        if current_mb > self._peak_memory_mb:
            self._peak_memory_mb = current_mb

        # Sample for reporting
        self._memory_samples.append(current_mb)
        if len(self._memory_samples) > 100:
            self._memory_samples = self._memory_samples[-50:]

        if current_mb > self.memory_limit_mb:
            self.logger.error(
                f"Memory usage exceeded: {current_mb:.1f}MB > {self.memory_limit_mb}MB "
                f"(peak={self._peak_memory_mb:.1f}MB)"
            )
            # Attempt aggressive GC before declaring failure
            freed = self.force_gc()
            after_mb = self._get_memory_mb()
            if after_mb <= self.memory_limit_mb:
                self.logger.info(
                    f"Memory recovered to {after_mb:.1f}MB after GC (freed {freed:.1f}MB)"
                )
                return True
            return False
        elif current_mb > self.memory_limit_mb * 0.8:
            self.logger.warning(
                f"Memory usage high: {current_mb:.1f}MB, attempting GC "
                f"(limit={self.memory_limit_mb}MB, peak={self._peak_memory_mb:.1f}MB)"
            )
            self.force_gc()
            return True
        return True

    def set_baseline_memory(self) -> float:
        """Set baseline memory before first collector runs
        
        Returns:
            Baseline memory in MB
        """
        self._baseline_memory_mb = self._get_memory_mb()
        self.logger.info(f"Memory baseline established: {self._baseline_memory_mb:.1f}MB")
        return self._baseline_memory_mb

    def check_collector_memory_delta(self, collector_name: str, memory_before_mb: float, 
                                       memory_after_mb: float, extra_stats: dict = None) -> bool:
        """Check if a collector's memory delta exceeds the per-collector budget
        
        This replaces the total memory check with delta-based checking to avoid
        false warnings for cumulative memory growth.
        
        Args:
            collector_name: Name of the collector
            memory_before_mb: Memory before collector ran
            memory_after_mb: Memory after collector ran
            extra_stats: Optional additional stats from collector (e.g., memory_phases)
            
        Returns:
            True if delta is within budget, False if exceeded
        """
        delta_mb = memory_after_mb - memory_before_mb
        
        # Track delta for reporting
        delta_info = {
            'before_mb': round(memory_before_mb, 1),
            'after_mb': round(memory_after_mb, 1),
            'delta_mb': round(delta_mb, 1),
        }
        
        # Include extra stats if provided
        if extra_stats:
            delta_info['extra_stats'] = extra_stats
        
        self._collector_memory_deltas[collector_name] = delta_info
        
        # Only warn if delta exceeds per-collector budget
        if delta_mb > self.per_collector_budget_mb:
            self.logger.warning(
                f"[{collector_name}] Memory delta exceeded budget: "
                f"{delta_mb:+.1f}MB > {self.per_collector_budget_mb:.1f}MB budget"
            )
            # Attempt GC to see if we can recover
            freed = self.force_gc()
            after_gc = self._get_memory_mb()
            new_delta = after_gc - memory_before_mb
            
            if new_delta > self.per_collector_budget_mb:
                self.logger.error(
                    f"[{collector_name}] Memory delta still high after GC: "
                    f"{new_delta:+.1f}MB (freed {freed:.1f}MB)"
                )
                return False
            else:
                self.logger.info(
                    f"[{collector_name}] GC recovered {freed:.1f}MB, "
                    f"delta now {new_delta:+.1f}MB"
                )
                # Update tracked delta
                new_delta_info = {
                    'before_mb': round(memory_before_mb, 1),
                    'after_mb': round(after_gc, 1),
                    'delta_mb': round(new_delta, 1),
                    'gc_freed_mb': round(freed, 1),
                }
                if extra_stats:
                    new_delta_info['extra_stats'] = extra_stats
                self._collector_memory_deltas[collector_name] = new_delta_info
                return True
        
        return True

    def get_collector_memory_report(self) -> dict:
        """Get per-collector memory usage report"""
        return dict(self._collector_memory_deltas)

    def get_memory_report(self) -> dict:
        """Get memory usage summary for scan report"""
        current_mb = self._get_memory_mb()
        avg_mb = sum(self._memory_samples) / len(self._memory_samples) if self._memory_samples else 0
        return {
            "current_mb": round(current_mb, 1),
            "peak_mb": round(self._peak_memory_mb, 1),
            "avg_mb": round(avg_mb, 1),
            "limit_mb": self.memory_limit_mb,
            "baseline_mb": round(self._baseline_memory_mb, 1),
            "per_collector_budget_mb": self.per_collector_budget_mb,
            "samples_count": len(self._memory_samples),
            "collector_deltas": self.get_collector_memory_report(),
        }

    def batch_sleep(self, items_processed: int, batch_size: int = 100):
        """Sleep between batch operations"""
        if items_processed > 0 and items_processed % batch_size == 0:
            time.sleep(0.01)
            self.throttle()
