"""
SafedetectionTool - Read-onlyCheckHelper functions

AllFunctionOnlyExecuteRead-onlyOperation，notModifySystemState。
"""
import os
import subprocess
import logging
from typing import Optional, List

logger = logging.getLogger(__name__)

# GlobalTimeoutSet
DEFAULT_TIMEOUT = 5  # seconds


def safe_read_file(path: str) -> str:
    """Safely Read File, return empty String on failure"""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except (OSError, PermissionError):
        return ""


def safe_run_command(cmd: List[str], timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """
    Safely execute read-only command

    Args:
        cmd: command列表 (e.g. ["uname", "-r"])
        timeout: Timeoutseconds数

    Returns:
        (stdout, stderr, returncode)
    """
    try:
        # Python 3.6 compatibility: capture_output was added in 3.7
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,  # text=True alias for 3.6
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out ({timeout}s): {' '.join(cmd)}")
        return "", "timeout", -1
    except (OSError, FileNotFoundError) as e:
        return "", str(e), -1


def check_module_loaded(module_name: str, proc_path: str = "/proc") -> bool:
    """Check if kernel module is already loaded"""
    modules_path = f"{proc_path}/modules"
    content = safe_read_file(modules_path)
    for line in content.splitlines():
        parts = line.split()
        if parts and parts[0] == module_name:
            return True
    return False


def check_config_enabled(config_key: str, kernel_config: dict) -> Optional[str]:
    """
    Check if kernel configuration item is enabled

    Returns:
        Configuration value (e.g. "y", "m") or None (not found/not enabled)
    """
    value = kernel_config.get(config_key)
    if value in ("y", "m"):
        return value
    return None


def check_modprobe_disabled(module_name: str,
                            modprobe_dir: str = "/etc/modprobe.d") -> bool:
    """Check if module is disabled via modprobe.d"""
    if not os.path.isdir(modprobe_dir):
        return False

    for filename in os.listdir(modprobe_dir):
        if not filename.endswith('.conf'):
            continue
        filepath = os.path.join(modprobe_dir, filename)
        content = safe_read_file(filepath)
        # Check "install <module> /bin/false" or "blacklist <module>"
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('#'):
                continue
            if f"install {module_name}" in line and "/bin/false" in line:
                return True
            if line == f"blacklist {module_name}":
                return True
    return False


def count_setuid_binaries(search_dirs: List[str] = None) -> int:
    """统计 setuid BinaryFile数量（Read-onlyOperation）"""
    if search_dirs is None:
        search_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]

    count = 0
    for dir_path in search_dirs:
        if not os.path.isdir(dir_path):
            continue
        try:
            for entry in os.scandir(dir_path):
                if entry.is_file():
                    try:
                        st = entry.stat()
                        if st.st_mode & 0o4000:  # setuid bit
                            count += 1
                    except OSError:
                        pass
        except OSError:
            pass
    return count
