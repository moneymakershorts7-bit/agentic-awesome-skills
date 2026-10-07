"""Scheduled Task Collector"""
import os
import time
import threading
from ..collector.base import BaseCollector
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

# File size limit constant (config-driven, fallback to 1MB)
_MAX_CRON_SCRIPT_SIZE_DEFAULT = 1048576  # 1MB

class CronCollector(BaseCollector):
    """Scheduled Task Collector"""
    name = "cron"

    def __init__(self):
        """Initialize cron collector"""
        super().__init__()
        self._scan_start_time = None
        self._partial_data = {}
        self._partial_lock = threading.Lock()

        self.timeout = self._get_config("timeout", 30)

        self._soft_timeout_ratio = self._get_config("soft_timeout_ratio", 0.85)
        self._max_cron_d_files = self._get_config("max_cron_d_files", 100)
        self._max_periodic_files = self._get_config("max_periodic_files", 100)
        self._max_user_crontabs = self._get_config("max_user_crontabs", 50)
        self._max_cron_script_size = self._get_config("max_cron_script_size", _MAX_CRON_SCRIPT_SIZE_DEFAULT)

        self._paths = self._get_config("paths", {})
        self._timer_dirs = self._get_config("timer_dirs", [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ])

    def _should_skip_due_to_timeout(self) -> bool:
        """Check if we should skip remaining collection due to approaching timeout"""
        if self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time
        soft_timeout = self.timeout * self._soft_timeout_ratio
        return elapsed > soft_timeout

    def _update_partial_result(self, result: dict, note: str):
        """Update partial result data for timeout recovery"""
        with self._partial_lock:
            self._partial_data = {
                **result,
                "_partial": True,
                "_partial_note": note,
            }

    def get_partial_result(self) -> dict:
        """Get partial result data if available"""
        with self._partial_lock:
            return dict(self._partial_data) if self._partial_data else {}

    def collect(self) -> dict:
        """Collect scheduled task information"""
        self._scan_start_time = time.time()

        result = {
            "system_crontab": [],
            "cron_d_entries": [],
            "cron_periodic": [],
            "user_crontabs": [],
            "systemd_timers": [],
        }

        # 1. Parse /etc/crontab (essential, always collect)
        crontab_path = self._paths.get("crontab", "/etc/crontab")
        result["system_crontab"] = self._parse_crontab(crontab_path)

        # Check soft timeout before continuing
        if self._should_skip_due_to_timeout():
            elapsed = time.time() - self._scan_start_time
            _get_logger().warning(f"Cron collector: soft timeout reached after {elapsed:.1f}s, returning partial data")
            self._update_partial_result(result, f"Soft timeout after system crontab ({elapsed:.1f}s)")
            return self.get_partial_result()

        # 2. Parse /etc/cron.d/* (high value for persistence detection)
        cron_d_dir = self._paths.get("cron_d", "/etc/cron.d")
        if os.path.isdir(cron_d_dir):
            with os.scandir(cron_d_dir) as it:
                for idx, entry in enumerate(it):
                    if idx >= self._max_cron_d_files:
                        break
                    filepath = entry.path
                    if entry.is_file(follow_symlinks=False):
                        entries = self._parse_crontab(filepath, has_user=True)
                        for cron_entry in entries:
                            cron_entry["file"] = entry.name
                            result["cron_d_entries"].append(cron_entry)

        # Check soft timeout before continuing
        if self._should_skip_due_to_timeout():
            elapsed = time.time() - self._scan_start_time
            _get_logger().warning(f"Cron collector: soft timeout reached after {elapsed:.1f}s, skipping remaining collections")
            self._update_partial_result(result, f"Soft timeout after cron.d ({elapsed:.1f}s)")
            return self.get_partial_result()

        # 3. Parse /etc/cron.{hourly,daily,weekly,monthly}/*
        for period in ["hourly", "daily", "weekly", "monthly"]:
            period_dir = f"/etc/cron.{period}"
            if os.path.isdir(period_dir):
                with os.scandir(period_dir) as it:
                    for idx, entry in enumerate(it):
                        if idx >= self._max_periodic_files:
                            break
                        filepath = entry.path
                        if entry.is_file(follow_symlinks=False):
                            # Check file size to prevent OOM
                            try:
                                file_size = os.path.getsize(filepath)
                                if file_size > self._max_cron_script_size:
                                    _get_logger().debug(f"cron periodic file too large ({file_size}B), skipping: {filepath}")
                                    continue
                            except OSError:
                                pass

                            stat_info = os.stat(filepath)
                            content_preview = ""
                            try:
                                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                                    lines = []
                                    for i, line in enumerate(f):
                                        if i >= 5:
                                            break
                                        lines.append(line.rstrip())
                                    content_preview = '\n'.join(lines)
                            except OSError:
                                pass
                            result["cron_periodic"].append({
                                "period": period,
                                "file": filepath,
                                "permissions": oct(stat_info.st_mode)[-4:],
                                "size": stat_info.st_size,
                                "content_preview": content_preview,
                            })

        # Check soft timeout before continuing
        if self._should_skip_due_to_timeout():
            elapsed = time.time() - self._scan_start_time
            _get_logger().warning(f"Cron collector: soft timeout reached after {elapsed:.1f}s, skipping remaining collections")
            self._update_partial_result(result, f"Soft timeout after cron periodic ({elapsed:.1f}s)")
            return self.get_partial_result()

        # 4. Parse /var/spool/cron/crontabs/*
        crontabs_dir = self._paths.get("crontab_dir", "/var/spool/cron/crontabs")
        try:
            if os.path.isdir(crontabs_dir):
                with os.scandir(crontabs_dir) as it:
                    for idx, entry in enumerate(it):
                        if idx >= self._max_user_crontabs:
                            break
                        filepath = entry.path
                        if entry.is_file(follow_symlinks=False):
                            entries = self._parse_crontab(filepath, has_user=False)
                            result["user_crontabs"].append({
                                "user": entry.name,
                                "entries": entries,
                            })
        except OSError:
            pass

        # Check soft timeout before continuing
        if self._should_skip_due_to_timeout():
            elapsed = time.time() - self._scan_start_time
            _get_logger().warning(f"Cron collector: soft timeout reached after {elapsed:.1f}s, skipping systemd timers")
            self._update_partial_result(result, f"Soft timeout after user crontabs ({elapsed:.1f}s)")
            return self.get_partial_result()

        # 5. Scan systemd timers
        result["systemd_timers"] = self._scan_systemd_timers()

        elapsed = time.time() - self._scan_start_time
        _get_logger().debug(f"Cron collector: collection complete ({elapsed:.1f}s)")
        return result

    def _parse_crontab(self, filepath: str, has_user: bool = True) -> list:
        """Parse crontab file"""
        entries = []
        try:
            with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    # Skip environment variable definitions
                    if '=' in line and not line[0].isdigit() and line[0] != '*':
                        continue
                    
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    
                    # First 5 fields are the schedule
                    schedule = ' '.join(parts[:5])
                    
                    if has_user:
                        # System crontab has user field
                        if len(parts) >= 7:
                            user = parts[5]
                            command = ' '.join(parts[6:])
                            entries.append({
                                "schedule": schedule,
                                "user": user,
                                "command": command,
                                "source": filepath,
                            })
                    else:
                        # User crontab has no user field
                        if len(parts) >= 6:
                            command = ' '.join(parts[5:])
                            entries.append({
                                "schedule": schedule,
                                "command": command,
                            })
        except OSError:
            pass
        
        return entries

    def _scan_systemd_timers(self) -> list:
        """Scan systemd timers"""
        timers = []
        
        for timer_dir in self._timer_dirs:
            if not os.path.isdir(timer_dir):
                continue
            
            try:
                with os.scandir(timer_dir) as it:
                    for entry in it:
                        if not entry.name.endswith('.timer'):
                            continue
                        
                        filepath = entry.path
                        timer_info = self._parse_timer_unit(filepath)
                        if timer_info:
                            timers.append(timer_info)
            except OSError:
                pass
        
        return timers

    def _parse_timer_unit(self, filepath: str) -> dict:
        """Parse systemd timer unit file with complete fields"""
        timer_info = {
            "name": os.path.basename(filepath),
            "unit_file": filepath,
            "on_calendar": "",
            "on_boot_sec": "",
            "on_unit_active_sec": "",
            "randomized_delay_sec": "",
            "persistent": "",
            "unit": "",
            "description": "",
            "last_trigger": "",
            "next_elapse": "",
        }
        
        current_section = ""
        try:
            with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    
                    # Parse sections
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1]
                        continue
                    
                    # Parse key-value pairs
                    if '=' not in line:
                        continue
                    
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if current_section == "Unit":
                        if key == "Description":
                            timer_info["description"] = value
                    elif current_section == "Timer":
                        if key == "OnCalendar":
                            timer_info["on_calendar"] = value
                        elif key == "OnBootSec":
                            timer_info["on_boot_sec"] = value
                        elif key == "OnUnitActiveSec":
                            timer_info["on_unit_active_sec"] = value
                        elif key == "RandomizedDelaySec":
                            timer_info["randomized_delay_sec"] = value
                        elif key == "Persistent":
                            timer_info["persistent"] = value
                        elif key == "Unit":
                            timer_info["unit"] = value
                    elif current_section == "Install":
                        pass  # Not needed for timer detection
        
        except OSError:
            pass
        
        # Return timer info if it has any trigger configuration
        has_trigger = any([
            timer_info["on_calendar"],
            timer_info["on_boot_sec"],
            timer_info["on_unit_active_sec"],
        ])
        
        return timer_info if has_trigger else {}
