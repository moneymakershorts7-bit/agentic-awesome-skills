"""Mixin for /proc filesystem parsing operations."""
from ...utils import proc


class ProcParserMixin:
    """Mixin providing /proc filesystem parsing methods."""
    @staticmethod
    def _get_proc_resource_usage(pid: int, system_uptime: float,
                                  num_cpu: int, clock_ticks: int,
                                  stat_raw: str = None) -> tuple:
        """Collect CPU and memory usage from /proc/{pid}/stat and status

        Args:
            pid: Process ID
            system_uptime: System uptime in seconds
            num_cpu: Number of CPUs
            clock_ticks: Clock ticks per second
            stat_raw: Optional pre-read /proc/{pid}/stat content (avoids redundant read)

        Returns:
            (cpu_percent, mem_rss_kb, runtime_seconds)
        """
        cpu_percent = 0.0
        mem_rss_kb = 0
        runtime_seconds = 0.0

        try:
            # Use provided stat content or read from /proc
            content = stat_raw
            if content is None:
                content = proc.read_proc_file(pid, "stat")

            if content and ')' in content:
                last_paren = content.rfind(')')
                fields = content[last_paren + 2:].split()
                if len(fields) >= 20:
                    utime = int(fields[11])    # User-mode CPU time
                    stime = int(fields[12])    # Kernel-mode CPU time
                    starttime = int(fields[19])  # Process start time

                    # Calculate runtime duration
                    if system_uptime > 0 and clock_ticks > 0:
                        start_secs = starttime / clock_ticks
                        runtime_seconds = system_uptime - start_secs
                        if runtime_seconds > 0:
                            total_time = (utime + stime) / clock_ticks
                            cpu_percent = (total_time / runtime_seconds) * 100.0 / num_cpu
                            cpu_percent = min(cpu_percent, 100.0 * num_cpu)

            # Read /proc/{pid}/status to get memory information
            status_content = proc.read_proc_file(pid, "status")
            if status_content:
                for line in status_content.split('\n'):
                    if line.startswith('VmRSS:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            mem_rss_kb = int(parts[1])
                        break

        except (ValueError, IndexError, OSError):
            pass

        return cpu_percent, mem_rss_kb, runtime_seconds

    @staticmethod
    def _get_system_uptime() -> float:
        """Read system uptime in seconds from /proc/uptime"""
        try:
            with open("/proc/uptime", "r", errors='replace', encoding='utf-8') as f:
                return float(f.read(64).split()[0])  # Limit to 64 bytes
        except (OSError, ValueError, IndexError):
            return 0.0
