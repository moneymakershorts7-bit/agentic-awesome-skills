"""Process-level resource usage monitor for sec-userspace."""
import resource
import time


class ResourceMonitor:
    """Process-level resource usage monitor.

    Initializes at scan start and outputs a summary at scan end.
    Uses only Python standard library (resource, time, os).
    """

    def __init__(self):
        self._start_wall_time = time.monotonic()
        self._start_usage = resource.getrusage(resource.RUSAGE_SELF)
        self._start_rss_mb = self._get_rss_mb()
        self._peak_rss_mb = self._start_rss_mb

    @staticmethod
    def _get_rss_mb() -> float:
        """Get current RSS (Resident Set Size) in MB from /proc/self/status."""
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        # VmRSS:   123456 kB
                        parts = line.split()
                        return int(parts[1]) / 1024.0
        except (OSError, IndexError, ValueError):
            pass
        return 0.0

    def snapshot(self):
        """Sample current resource state and update peak RSS."""
        current_rss = self._get_rss_mb()
        if current_rss > self._peak_rss_mb:
            self._peak_rss_mb = current_rss

    def get_summary(self) -> dict:
        """Return resource usage summary dict."""
        end_usage = resource.getrusage(resource.RUSAGE_SELF)
        wall_time = time.monotonic() - self._start_wall_time

        user_cpu = end_usage.ru_utime - self._start_usage.ru_utime
        sys_cpu = end_usage.ru_stime - self._start_usage.ru_stime
        total_cpu = user_cpu + sys_cpu
        cpu_percent = (total_cpu / wall_time * 100) if wall_time > 0 else 0

        # ru_maxrss on Linux is in KB
        peak_rss_kb = end_usage.ru_maxrss
        peak_rss_mb = peak_rss_kb / 1024.0
        current_rss_mb = self._get_rss_mb()

        return {
            "wall_time_seconds": round(wall_time, 2),
            "cpu_user_seconds": round(user_cpu, 2),
            "cpu_system_seconds": round(sys_cpu, 2),
            "cpu_total_seconds": round(total_cpu, 2),
            "cpu_percent": round(cpu_percent, 1),
            "peak_rss_mb": round(peak_rss_mb, 1),
            "current_rss_mb": round(current_rss_mb, 1),
            "rss_delta_mb": round(current_rss_mb - self._start_rss_mb, 1),
        }

    def format_summary(self) -> str:
        """Format resource usage summary for human-readable output."""
        s = self.get_summary()
        lines = [
            "\u2500" * 50,
            "Resource Usage Summary",
            "\u2500" * 50,
            f"  Wall time     : {s['wall_time_seconds']:.1f}s",
            f"  CPU time      : {s['cpu_total_seconds']:.1f}s (user {s['cpu_user_seconds']:.1f}s + sys {s['cpu_system_seconds']:.1f}s)",
            f"  CPU usage     : {s['cpu_percent']:.1f}%",
            f"  Peak memory   : {s['peak_rss_mb']:.1f} MB",
            f"  Memory delta  : {s['rss_delta_mb']:+.1f} MB",
            "\u2500" * 50,
        ]
        return "\n".join(lines)
