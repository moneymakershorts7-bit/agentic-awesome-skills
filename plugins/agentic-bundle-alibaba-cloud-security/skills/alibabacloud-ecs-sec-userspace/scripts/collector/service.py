"""Service and Startup Item Collector"""
import os
import threading
import time
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

class ServiceCollector(BaseCollector):
    """Service and Startup Item Collector"""
    name = "service"

    def __init__(self):
        """Initialize service collector"""
        super().__init__()
        self._partial_data = {}
        self._partial_lock = threading.Lock()
        self._scan_start_time = None
        
        self.timeout = self._get_config("timeout", 60)
        
        self._soft_timeout_ratio = self._get_config("soft_timeout_ratio", 0.85)
        self._max_services = self._get_config("max_services", 500)

    def _update_partial_result(self, services: list, partial: bool = False):
        """Update partial result data for timeout recovery
        
        Args:
            services: List of services collected so far
            partial: Whether this is a partial result (True) or complete (False)
        """
        with self._partial_lock:
            self._partial_data = {
                "services": list(services),
                "total_count": len(services),
                "_partial": partial,
            }

    def get_partial_result(self) -> dict:
        """Get partial result data if available
        
        Returns:
            Partial result dict or empty dict
        """
        with self._partial_lock:
            return dict(self._partial_data) if self._partial_data else {}

    def _should_skip_due_to_timeout(self) -> bool:
        """Check if we should skip remaining collection due to approaching timeout"""
        if self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time
        soft_timeout = self.timeout * self._soft_timeout_ratio
        return elapsed > soft_timeout

    def collect(self) -> dict:
        """Collect service and startup item information"""
        self._scan_start_time = time.time()

        result = {
            "systemd_services": self._collect_systemd_services(),
        }

        # Check soft timeout before continuing
        if self._should_skip_due_to_timeout():
            elapsed = time.time() - self._scan_start_time
            _get_logger().warning(f"Service collector: soft timeout reached after {elapsed:.1f}s, skipping remaining collections")
            self._update_partial_result(result["systemd_services"], partial=True)
            return self.get_partial_result()

        result["systemd_timers"] = self._collect_systemd_timers()

        # Check soft timeout before continuing
        if self._should_skip_due_to_timeout():
            elapsed = time.time() - self._scan_start_time
            _get_logger().warning(f"Service collector: soft timeout reached after {elapsed:.1f}s, skipping remaining collections")
            self._update_partial_result(result["systemd_services"], partial=True)
            return self.get_partial_result()

        result["dbus_services"] = self._collect_dbus_services()

        # Check soft timeout before continuing
        if self._should_skip_due_to_timeout():
            elapsed = time.time() - self._scan_start_time
            _get_logger().warning(f"Service collector: soft timeout reached after {elapsed:.1f}s, skipping remaining collections")
            self._update_partial_result(result["systemd_services"], partial=True)
            return self.get_partial_result()

        result["initd_scripts"] = self._collect_initd_scripts()
        result["rc_local"] = self._collect_rc_local()
        result["profile_d_scripts"] = self._collect_profile_d()
        result["ld_so_preload"] = self._collect_ld_so_preload()
        result["modules_load_d"] = self._collect_modules_load_d()
        result["modprobe_d"] = self._collect_modprobe_d()

        # Mark as complete (not partial)
        elapsed = time.time() - self._scan_start_time
        _get_logger().debug(f"Service collector: collection complete ({elapsed:.1f}s)")
        self._update_partial_result(
            services=result.get("systemd_services", []),
            partial=False
        )

        return result

    def _collect_systemd_services(self) -> list:
        """Collect systemd service information"""
        services = []
        service_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ]

        # In quick mode, limit the number of services to parse
        max_services = self._max_services

        for service_dir in service_dirs:
            if not os.path.isdir(service_dir):
                continue

            try:
                count = 0
                for entry in os.scandir(service_dir):
                    if count >= max_services:
                        break
                    if not entry.name.endswith('.service'):
                        continue

                    service_info = self._parse_service_file(entry.path)
                    if service_info:
                        services.append(service_info)
                        count += 1
                        
                        # Save partial result every 50 services for timeout recovery
                        if len(services) % 50 == 0:
                            self._update_partial_result(services, partial=True)
                            _get_logger().debug(
                                f"[{self.name}] Partial result saved: {len(services)} services"
                            )
            except OSError:
                continue

        return services

    def _collect_systemd_timers(self) -> list:
        """Collect systemd timer unit files"""
        timers = []
        timer_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
        ]

        for timer_dir in timer_dirs:
            if not os.path.isdir(timer_dir):
                continue

            try:
                for entry in os.scandir(timer_dir):
                    if not entry.name.endswith('.timer'):
                        continue

                    timer_info = self._parse_timer_file(entry.path)
                    if timer_info:
                        timers.append(timer_info)
            except OSError:
                continue

        return timers

    def _parse_timer_file(self, filepath: str) -> dict:
        """Parse systemd timer unit file"""
        try:
            with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                content = f.read(65536)
        except OSError:
            return None

        timer_info = {
            "name": os.path.basename(filepath),
            "unit_file": filepath,
            "description": "",
            "on_calendar": [],
            "on_boot_sec": "",
            "on_unit_active_sec": "",
            "randomized_delay_sec": "",
            "persistent": "",
            "unit": "",
            "wanted_by": "",
        }

        current_section = ""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                continue

            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                if current_section == "Unit":
                    if key == "Description":
                        timer_info["description"] = value
                elif current_section == "Timer":
                    if key == "OnCalendar":
                        timer_info["on_calendar"].append(value)
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
                    if key == "WantedBy":
                        timer_info["wanted_by"] = value

        # Return only if has trigger configuration
        has_trigger = any([
            timer_info["on_calendar"],
            timer_info["on_boot_sec"],
            timer_info["on_unit_active_sec"],
        ])

        return timer_info if has_trigger else None

    def _collect_dbus_services(self) -> list:
        """Collect D-Bus activatable services"""
        services = []
        dbus_dirs = [
            "/usr/share/dbus-1/system-services",
            "/usr/share/dbus-1/services",
        ]

        for dbus_dir in dbus_dirs:
            if not os.path.isdir(dbus_dir):
                continue

            try:
                for entry in os.scandir(dbus_dir):
                    if not entry.name.endswith('.service'):
                        continue

                    service_info = self._parse_dbus_service_file(entry.path)
                    if service_info:
                        services.append(service_info)
            except OSError:
                continue

        return services

    def _parse_dbus_service_file(self, filepath: str) -> dict:
        """Parse D-Bus service file"""
        try:
            with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                content = f.read(8192)
        except OSError:
            return None

        service_info = {
            "file": filepath,
            "name": os.path.basename(filepath),
            "dbus_name": "",
            "exec": "",
            "user": "",
        }

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == "Name":
                    service_info["dbus_name"] = value
                elif key == "Exec":
                    service_info["exec"] = value
                elif key == "User":
                    service_info["user"] = value

        return service_info if service_info["exec"] else None

    def _parse_service_file(self, filepath: str) -> dict:
        """Parse systemd service file"""
        try:
            with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                lines = f.read(65536).splitlines()
        except OSError:
            return None

        service_info = {
            "name": os.path.basename(filepath),
            "unit_file": filepath,
            "type": "",
            "exec_start": "",
            "exec_start_pre": "",
            "exec_start_post": "",
            "restart": "",
            "restart_sec": "",
            "wanted_by": "",
            "user": "",
        }

        current_section = ""
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                continue

            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                if current_section == "Service":
                    if key == "Type":
                        service_info["type"] = value
                    elif key == "ExecStart":
                        service_info["exec_start"] = value
                    elif key == "ExecStartPre":
                        service_info["exec_start_pre"] = value
                    elif key == "ExecStartPost":
                        service_info["exec_start_post"] = value
                    elif key == "Restart":
                        service_info["restart"] = value
                    elif key == "RestartSec":
                        service_info["restart_sec"] = value
                    elif key == "User":
                        service_info["user"] = value
                elif current_section == "Install":
                    if key == "WantedBy":
                        service_info["wanted_by"] = value

        return service_info

    def _collect_initd_scripts(self) -> list:
        """Collect init.d scripts"""
        initd_dir = "/etc/init.d"
        if not os.path.isdir(initd_dir):
            return []

        scripts = []
        try:
            for entry in os.scandir(initd_dir):
                if entry.is_file() and os.access(entry.path, os.X_OK):
                    scripts.append(entry.name)
        except OSError:
            pass

        return scripts

    def _collect_rc_local(self) -> dict:
        """Collect rc.local information"""
        rc_local_path = "/etc/rc.local"
        result = {
            "exists": False,
            "executable": False,
            "content": "",
        }

        if os.path.exists(rc_local_path):
            result["exists"] = True
            result["executable"] = os.access(rc_local_path, os.X_OK)

            try:
                with open(rc_local_path, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(4096)  # rc.local should be small
                    result["content"] = content
            except OSError:
                pass

        return result

    def _collect_profile_d(self) -> list:
        """Collect profile.d scripts"""
        profile_d_dir = "/etc/profile.d"
        if not os.path.isdir(profile_d_dir):
            return []

        scripts = []
        try:
            for entry in os.scandir(profile_d_dir):
                if entry.name.endswith('.sh') and entry.is_file():
                    try:
                        size = entry.stat().st_size
                        with open(entry.path, 'r', errors='ignore', encoding='utf-8') as f:
                            preview = ''.join(f.readline() for _ in range(10))
                        scripts.append({
                            "name": entry.name,
                            "size": size,
                            "content_preview": preview[:500],
                        })
                    except OSError:
                        continue
        except OSError:
            pass

        return scripts

    def _collect_ld_so_preload(self) -> dict:
        """Collect ld.so.preload information"""
        preload_path = "/etc/ld.so.preload"
        result = {
            "exists": False,
            "content": "",
        }

        if os.path.exists(preload_path):
            result["exists"] = True
            try:
                with open(preload_path, 'r', errors='ignore', encoding='utf-8') as f:
                    result["content"] = f.read(4096).strip()  # preload is tiny
            except OSError:
                pass

        return result

    def _collect_modules_load_d(self) -> list:
        """Collect modules-load.d config"""
        modules_dir = "/etc/modules-load.d"
        if not os.path.isdir(modules_dir):
            return []

        modules = []
        try:
            for entry in os.scandir(modules_dir):
                if entry.name.endswith('.conf') and entry.is_file():
                    try:
                        with open(entry.path, 'r', errors='ignore', encoding='utf-8') as f:
                            module_list = [
                                line.strip()
                                for line in f
                                if line.strip() and not line.strip().startswith('#')
                            ]
                        modules.append({
                            "file": entry.name,
                            "modules": module_list,
                        })
                    except OSError:
                        continue
        except OSError:
            pass

        return modules

    def _collect_modprobe_d(self) -> list:
        """Collect modprobe.d config"""
        modprobe_dir = "/etc/modprobe.d"
        if not os.path.isdir(modprobe_dir):
            return []

        configs = []
        try:
            for entry in os.scandir(modprobe_dir):
                if entry.name.endswith('.conf') and entry.is_file():
                    try:
                        with open(entry.path, 'r', errors='ignore', encoding='utf-8') as f:
                            content = f.read(2048)  # Read with limit
                        configs.append({
                            "file": entry.name,
                            "content": content,
                        })
                    except OSError:
                        continue
        except OSError:
            pass

        return configs
