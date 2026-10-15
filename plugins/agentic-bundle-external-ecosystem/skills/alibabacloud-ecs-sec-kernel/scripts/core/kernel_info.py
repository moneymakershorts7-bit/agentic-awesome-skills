"""
Kernel infoCollect - SafeRead-onlyOperation

OnlypassedRead /proc, /sys, /boot etcFileSystemGetInfo。
AbsolutenotExecuteAnycancanModifySystemStateOperation。
"""
import os
import re
import gzip
import platform
import sys
if sys.version_info < (3, 7):
    from ..thirdparties.dataclasses_backport import dataclass, field
else:
    from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class KernelInfo:
    """Kernel info data class"""
    version: str = ""                # uname -r (e.g. "6.8.0-31-generic")
    full_version: str = ""           # /proc/version complete content
    version_tuple: tuple = ()        # Parsed version tuple (6, 8, 0)
    arch: str = ""                   # uname -m (e.g. "x86_64")
    config: Dict[str, str] = field(default_factory=dict)  # Kernel config
    loaded_modules: List[str] = field(default_factory=list)  # Already loaded modules
    module_params: Dict[str, Dict] = field(default_factory=dict)  # Module parameters
    kernel_cmdline: str = ""         # /proc/cmdline
    tainted_flags: int = 0           # /proc/sys/kernel/tainted
    distro: str = ""                 # Distribution name
    distro_version: str = ""         # Distribution version
    patch_level: str = ""            # Patch level
    compile_date: str = ""           # Kernel compile date
    run_env: str = "host"            # Run environment: "host" (Linux server only)


class KernelInfoCollector:
    """
    Kernel info collection handler

    All operations are read-only, only read filesystem and execute read-only commands.
    Designed for Linux server environments only.
    """

    def __init__(self, host_proc: str = "/proc", host_boot: str = "/boot",
                 host_etc_modprobe: str = "/etc/modprobe.d"):
        self._proc = host_proc
        self._boot = host_boot
        self._modprobe_dir = host_etc_modprobe

    def collect(self) -> KernelInfo:
        """CollectCompleteKernel info"""
        info = KernelInfo()
        info.version = self._get_kernel_version()
        info.full_version = self._get_proc_version()
        info.version_tuple = self._parse_version_tuple(info.version)
        info.arch = platform.machine()
        info.config = self._get_kernel_config(info.version)
        info.loaded_modules = self._get_loaded_modules()
        info.kernel_cmdline = self._get_cmdline()
        info.tainted_flags = self._get_tainted()
        info.distro, info.distro_version = self._get_distro_info()
        info.compile_date = self._extract_compile_date(info.full_version)
        return info

    def _get_kernel_version(self) -> str:
        """GetKernelVersion (uname -r)"""
        try:
            return platform.release()
        except Exception:
            content = self._read_file(f"{self._proc}/version")
            if content:
                parts = content.split()
                if len(parts) >= 3:
                    return parts[2]
            return ""

    def _get_proc_version(self) -> str:
        """Read /proc/version"""
        return self._read_file(f"{self._proc}/version")

    def _parse_version_tuple(self, version: str) -> tuple:
        """ParseVersionStringas元组: '6.8.0-31-generic' -> (6, 8, 0)"""
        match = re.match(r'(\d+)\.(\d+)\.(\d+)', version)
        if match:
            return tuple(int(x) for x in match.groups())
        return ()

    def _get_kernel_config(self, version: str) -> Dict[str, str]:
        """GetKernelConfiguration (优先 /proc/config.gz, backup /boot/config-*)"""
        config = {}
        # Attempt /proc/config.gz
        config_gz = f"{self._proc}/config.gz"
        if os.path.exists(config_gz):
            try:
                with gzip.open(config_gz, 'rt', encoding='utf-8') as f:
                    config = self._parse_config_content(f.read())
                    if config:
                        return config
            except (OSError, gzip.BadGzipFile):
                pass

        # Attempt /boot/config-<version>
        boot_config = f"{self._boot}/config-{version}"
        if os.path.exists(boot_config):
            content = self._read_file(boot_config)
            if content:
                config = self._parse_config_content(content)

        return config

    def _parse_config_content(self, content: str) -> Dict[str, str]:
        """ParseKernelConfigurationFileContent"""
        config = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, _, value = line.partition('=')
                config[key.strip()] = value.strip()
        return config

    def _get_loaded_modules(self) -> List[str]:
        """Get list of loaded kernel modules (read /proc/modules)"""
        modules = []
        content = self._read_file(f"{self._proc}/modules")
        if content:
            for line in content.splitlines():
                parts = line.split()
                if parts:
                    modules.append(parts[0])
        return modules

    def _get_cmdline(self) -> str:
        """GetKernel启动commandrow"""
        return self._read_file(f"{self._proc}/cmdline")

    def _get_tainted(self) -> int:
        """GetKernel tainted Flag"""
        content = self._read_file(f"{self._proc}/sys/kernel/tainted")
        try:
            return int(content.strip()) if content else 0
        except ValueError:
            return 0

    def _get_distro_info(self) -> tuple:
        """Get发row版Info"""
        # Attempt /etc/os-release
        os_release = self._read_file("/etc/os-release")
        if os_release:
            name = ""
            version = ""
            for line in os_release.splitlines():
                if line.startswith("NAME="):
                    name = line.split("=", 1)[1].strip('"')
                elif line.startswith("VERSION_ID="):
                    version = line.split("=", 1)[1].strip('"')
            return name, version
        return "Unknown", ""

    def _extract_compile_date(self, full_version: str) -> str:
        """from /proc/version 提取编译日期"""
        # 典型Format: Linux version 6.8.0 ... #1 SMP Mon Apr 1 12:00:00 UTC 2026
        match = re.search(r'#\d+.*?(\w+ \w+ \d+ \d+:\d+:\d+ \w+ \d+)', full_version)
        return match.group(1) if match else ""

    def _read_file(self, path: str) -> str:
        """SafeReadFileContent"""
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except (OSError, PermissionError):
            return ""
