"""
/proc filesystem read utility

Prefer using /proc filesystem to collect Linux system data, avoid using shell commands.
All function exceptions don't propagate upward, return default values or empty values.
"""
import os
import logging
from typing import List, Dict

logger = logging.getLogger("sec-userspace")

# TCP state code mapping (module-level constant, avoid recreating in loops)
_TCP_STATE_MAP = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING',
}


def list_pids() -> List[int]:
    """Traverse /proc/ directory, return PID list corresponding to all numeric directory names

    Uses os.scandir for better performance (reduces stat calls).
    """
    pids = []
    try:
        with os.scandir('/proc') as it:
            for entry in it:
                if entry.name.isdigit():
                    pids.append(int(entry.name))
    except OSError as e:
        logger.warning(f"Failed to read /proc directory: {e}")
    return pids


def get_process_list() -> List[Dict]:
    """Get list of all processes with basic info
    
    Returns:
        List of process info dicts with keys: pid, name, cmdline, exe
    """
    processes = []
    for pid in list_pids():
        try:
            cmdline = get_proc_cmdline(pid)
            stat = get_proc_stat(pid)
            exe = get_proc_exe(pid)
            
            processes.append({
                "pid": pid,
                "name": stat.get("comm", "") if stat else "",
                "cmdline": cmdline,
                "exe": exe,
            })
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue
    return processes


def read_proc_file(pid: int, filename: str, max_bytes: int = 65536) -> str:
    """
    Read content of /proc/{pid}/{filename}
    Limit: single read not exceeding max_bytes (default 64KB)
    """
    try:
        filepath = f"/proc/{pid}/{filename}"
        with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
            return f.read(max_bytes)
    except OSError as e:
        logger.debug(f"Failed to read {filepath}: {e}")
        return ""


def get_proc_stat(pid: int) -> dict:
    """
    Parse /proc/{pid}/stat file
    Return: {pid, comm, state, ppid, uid}
    """
    try:
        content = read_proc_file(pid, "stat")
        if not content:
            return {}

        # comm field may contain spaces and parentheses, split by last ')'
        if ')' not in content:
            return {}

        # Find position of first '(' and last ')'
        first_paren = content.index('(')
        last_paren = content.rfind(')')
        comm = content[first_paren + 1:last_paren]
        rest = content[last_paren+2:].split()  # Skip ')' and spaces

        if len(rest) < 2:
            return {}

        # rest[0]=state, rest[1]=ppid
        state = rest[0]
        ppid = int(rest[1])

        # Get uid from status file
        uid = _get_uid_from_status(pid)

        return {
            "pid": pid,
            "comm": comm,
            "state": state,
            "ppid": ppid,
            "uid": uid,
        }
    except (ValueError, IndexError) as e:
        logger.debug(f"Failed to parse proc stat (PID {pid}): {e}")
        return {}




def _get_uid_from_status(pid: int) -> int:
    """Get UID from /proc/{pid}/status"""
    try:
        content = read_proc_file(pid, "status")
        for line in content.split('\n'):
            if line.startswith('Uid:'):
                # Uid: real effective saved_fs saved_setuid
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1])
    except (ValueError, IndexError):
        pass
    return -1


def get_proc_cmdline(pid: int, max_length: int = 65536) -> str:
    """
    Read /proc/{pid}/cmdline
    Replace \\x00 with spaces
    Limit output to max_length characters to avoid excessive I/O

    Args:
        pid: Process ID
        max_length: Maximum characters to read (default 64KB, quick mode can use 512)
    """
    try:
        content = read_proc_file(pid, "cmdline", max_bytes=max_length)
        if not content:
            return ""
        # cmdline separated by \0, replace with spaces and strip trailing whitespace
        return content.replace('\x00', ' ').strip()
    except (OSError, ValueError) as e:
        logger.debug(f"Failed to read cmdline (PID {pid}): {e}")
        return ""


def get_proc_exe(pid: int) -> str:
    """
    Read /proc/{pid}/exe symbolic link target
    Return value may contain ' (deleted)' suffix
    """
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except FileNotFoundError:
        return ""  # Process exited, silently skip
    except OSError as e:
        logger.debug(f"Failed to read exe link (PID {pid}): {e}")
        return ""


def get_proc_cwd(pid: int) -> str:
    """
    Read /proc/{pid}/cwd symbolic link target
    Returns process current working directory
    """
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except FileNotFoundError:
        return ""  # Process exited, silently skip
    except OSError as e:
        logger.debug(f"Failed to read cwd link (PID {pid}): {e}")
        return ""


def get_proc_environ(pid: int) -> Dict[str, str]:
    """
    Read /proc/{pid}/environ
    Split by \\x00 into key-value pairs, each entry split by first '=' into key/value
    """
    try:
        content = read_proc_file(pid, "environ")
        if not content:
            return {}

        environ = {}
        for entry in content.split('\x00'):
            if '=' in entry:
                key, value = entry.split('=', 1)
                environ[key] = value
        return environ
    except (OSError, ValueError) as e:
        logger.debug(f"Failed to read environ (PID {pid}): {e}")
        return {}


def get_proc_fd_list(pid: int) -> List[dict]:
    """
    Traverse /proc/{pid}/fd/ directory
    Return: [{"fd": int, "target": str, "type": str}]
    type: "socket", "pipe", "file", "anon_inode", "other"
    """
    try:
        fd_dir = f"/proc/{pid}/fd"
        if not os.path.exists(fd_dir):
            return []

        result = []
        for fd_name in os.listdir(fd_dir):
            try:
                fd_path = os.path.join(fd_dir, fd_name)
                target = os.readlink(fd_path)

                # Determine type
                if target.startswith("socket:"):
                    fd_type = "socket"
                elif target.startswith("pipe:"):
                    fd_type = "pipe"
                elif target.startswith("anon_inode:"):
                    fd_type = "anon_inode"
                else:
                    fd_type = "file"

                result.append({
                    "fd": int(fd_name),
                    "target": target,
                    "type": fd_type,
                })
            except (OSError, ValueError):
                # Skip fds that cannot be read
                continue

        return result
    except FileNotFoundError:
        return []  # Process exited
    except OSError as e:
        logger.debug(f"Failed to read fd list (PID {pid}): {e}")
        return []


def get_proc_maps(pid: int) -> List[dict]:
    """
    Parse /proc/{pid}/maps
    Return: [{"addr_start": str, "addr_end": str, "perms": str, "pathname": str}]
    Only keep entries with non-empty pathname, return at most 500 entries
    """
    try:
        content = read_proc_file(pid, "maps")
        if not content:
            return []

        result = []
        for line in content.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.strip().split()
            if len(parts) < 5:
                continue

            # Format: addr_start-addr_end perms offset dev inode pathname
            addr_range = parts[0]
            perms = parts[1]
            pathname = " ".join(parts[5:]) if len(parts) > 5 else ""

            # Only keep entries with non-empty pathname
            if not pathname:
                continue

            if '-' in addr_range:
                addr_start, addr_end = addr_range.split('-', 1)
                result.append({
                    "addr_start": addr_start,
                    "addr_end": addr_end,
                    "perms": perms,
                    "pathname": pathname,
                })

                # Limit to at most 500 entries
                if len(result) >= 500:
                    break

        return result
    except FileNotFoundError:
        return []  # Process exited
    except (OSError, ValueError) as e:
        logger.debug(f"Failed to read maps (PID {pid}): {e}")
        return []


def get_loadavg() -> dict:
    """
    Read /proc/loadavg
    Return: {"load1": float, "load5": float, "load15": float, "running": int, "total": int}
    """
    try:
        with open('/proc/loadavg', 'r', errors='replace', encoding='utf-8') as f:
            content = f.read(1024).strip()  # /proc file, tiny

        parts = content.split()
        if len(parts) < 5:
            return {}

        # Format: load1 load5 load15 running/total last_pid
        load1, load5, load15 = float(parts[0]), float(parts[1]), float(parts[2])
        running_total = parts[3].split('/')
        running, total = int(running_total[0]), int(running_total[1])

        return {
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "running": running,
            "total": total,
        }
    except (ValueError, IndexError, OSError) as e:
        logger.warning(f"Failed to read loadavg: {e}")
        return {}


def get_meminfo() -> dict:
    """
    Read /proc/meminfo
    Return at least: {"MemTotal": int, "MemAvailable": int, "MemFree": int} (in KB)
    """
    try:
        # Check file size (prevent OOM)
        if os.path.getsize('/proc/meminfo') > 1024 * 1024:  # 1MB
            logger.warning("meminfo file too large, skip reading")
            return {}
        
        with open('/proc/meminfo', 'r', errors='replace', encoding='utf-8') as f:
            lines = f.readlines()

        meminfo = {}
        for line in lines:
            # Format: Key: Value kB
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                # Extract numeric value (remove kB unit)
                if value.endswith('kB'):
                    value = value[:-2].strip()
                try:
                    meminfo[key] = int(value)
                except ValueError:
                    pass

        return meminfo
    except OSError as e:
        logger.warning(f"Failed to read meminfo: {e}")
        return {}


def get_cpu_count() -> int:
    """
    Read /proc/cpuinfo to count CPU cores
    Or use os.cpu_count() as fallback option
    """
    try:
        with open('/proc/cpuinfo', 'r', errors='replace', encoding='utf-8') as f:
            content = f.read(1048576)  # 1MB limit for cpuinfo

        # Count "processor" lines
        count = sum(1 for line in content.split('\n') if line.startswith('processor'))
        if count > 0:
            return count
    except OSError:
        pass

    # Fallback option
    return os.cpu_count() or 1


def get_self_status() -> dict:
    """
    Read /proc/self/status
    Return at least: {"VmRSS": int, "VmPeak": int, "Threads": int} (in KB)
    """
    try:
        content = read_proc_file(os.getpid(), "status")
        if not content:
            return {}

        result = {}
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                # Extract fields of interest
                if key in ('VmRSS', 'VmPeak', 'VmSize', 'Threads'):
                    try:
                        # Remove kB unit
                        if value.endswith('kB'):
                            value = value[:-2].strip()
                        result[key] = int(value)
                    except ValueError:
                        pass

        return result
    except (OSError, ValueError) as e:
        logger.debug(f"Failed to read self status: {e}")
        return {}


# UDP state code mapping (connectionless, limited state machine)
_UDP_STATE_MAP = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
}


def parse_proc_net_tcp(path: str = "/proc/net/tcp") -> List[dict]:
    """
    Parse /proc/net/tcp (or tcp6)
    Return: [{"local_ip": str, "local_port": int, "remote_ip": str, "remote_port": int, "state": str, "inode": int}]
    """
    try:
        # Check file size (prevent OOM)
        if os.path.getsize(path) > 1024 * 1024:  # 1MB
            logger.warning(f"{path} file too large, skip reading")
            return []
        
        with open(path, 'r', errors='replace', encoding='utf-8') as f:
            lines = f.readlines()

        # Skip header line
        if not lines or 'sl' not in lines[0]:
            return []

        result = []
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 10:
                continue

            try:
                # Parse local address
                local_addr = parts[1]
                local_ip, local_port = _parse_hex_addr(local_addr)

                # Parse remote address
                remote_addr = parts[2]
                remote_ip, remote_port = _parse_hex_addr(remote_addr)

                # State mapping
                state_hex = parts[3]
                state = _TCP_STATE_MAP.get(state_hex, state_hex)

                # inode
                inode = int(parts[9])

                result.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "inode": inode,
                })
            except (ValueError, IndexError):
                continue

        return result
    except OSError as e:
        logger.debug(f"Failed to read {path}: {e}")
        return []


def parse_proc_net_tcp_streaming(path: str = "/proc/net/tcp", timeout: float = None) -> tuple:
    """
    Parse /proc/net/tcp (or tcp6) with streaming and timeout support.
    
    This implementation reads line-by-line instead of loading the entire file,
    allowing it to return partial results if timeout is reached.
    
    Uses adaptive timeout check frequency: checks every 0.1% of the timeout
    budget instead of every line, reducing overhead for large files.
    
    Args:
        path: Path to TCP file (/proc/net/tcp or /proc/net/tcp6)
        timeout: Maximum seconds for parsing. None means no timeout.
        
    Returns:
        tuple: (result_list, timed_out) where:
            - result_list: List of connection dicts (may be partial if timeout)
            - timed_out: Boolean indicating if timeout was reached
            
    Example:
        >>> connections, timeout = parse_proc_net_tcp_streaming("/proc/net/tcp", timeout=5.0)
        >>> if timeout:
        ...     print(f"Partial results: {len(connections)} connections")
    """
    import time
    
    try:
        # Check file size (prevent OOM)
        if os.path.getsize(path) > 10 * 1024 * 1024:  # 10MB (increased from 1MB)
            logger.warning(f"{path} file too large (>10MB), skip reading")
            return [], False
        
        result = []
        start_time = time.time() if timeout else None
        header_seen = False
        timed_out = False
        
        # Adaptive check interval: check timeout every 0.1% of budget
        # to ensure partial data is returned even under extreme load
        check_interval_lines = 100  # Reduced from 500 for better partial data return
        if start_time is not None and timeout > 0:
            estimated_lines = 10000  # Typical /proc/net/tcp size
            check_interval_lines = max(100, min(2000, estimated_lines // 1000))  # Increased minimum
        
        lines_since_check = 0
        
        with open(path, 'r', errors='replace', encoding='utf-8') as f:
            for line in f:
                # Check timeout at adaptive intervals
                if start_time is not None:
                    lines_since_check += 1
                    if lines_since_check >= check_interval_lines:
                        lines_since_check = 0
                        if (time.time() - start_time) > timeout:
                            logger.warning(
                                f"{path} streaming parse timed out after {timeout:.1f}s "
                                f"(partial: {len(result)} connections)"
                            )
                            timed_out = True
                            break
                
                # Skip header line
                if not header_seen:
                    if 'sl' in line:
                        header_seen = True
                    continue
                
                # Parse line
                parts = line.strip().split()
                if len(parts) < 10:
                    continue

                try:
                    local_addr = parts[1]
                    local_ip, local_port = _parse_hex_addr(local_addr)

                    remote_addr = parts[2]
                    remote_ip, remote_port = _parse_hex_addr(remote_addr)

                    state_hex = parts[3]
                    state = _TCP_STATE_MAP.get(state_hex, state_hex)

                    inode = int(parts[9])

                    result.append({
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                        "inode": inode,
                    })
                except (ValueError, IndexError):
                    continue
        
        return result, timed_out
        
    except OSError as e:
        logger.debug(f"Failed to read {path}: {e}")
        return [], False


def parse_proc_net_udp(path: str = "/proc/net/udp") -> List[dict]:
    """
    Parse /proc/net/udp (or udp6)
    Return: [{"local_ip": str, "local_port": int, "remote_ip": str, "remote_port": int, "state": str, "inode": int}]
    """
    try:
        if os.path.getsize(path) > 1024 * 1024:
            logger.warning(f"{path} file too large, skip reading")
            return []
        with open(path, 'r', errors='replace', encoding='utf-8') as f:
            lines = f.readlines()
        if not lines or 'sl' not in lines[0]:
            return []
        result = []
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            try:
                local_addr = parts[1]
                local_ip, local_port = _parse_hex_addr(local_addr)
                remote_addr = parts[2]
                remote_ip, remote_port = _parse_hex_addr(remote_addr)
                state_hex = parts[3]
                state = _UDP_STATE_MAP.get(state_hex, state_hex)
                inode = int(parts[9])
                result.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "inode": inode,
                })
            except (ValueError, IndexError):
                continue
        return result
    except OSError as e:
        logger.debug(f"Failed to read {path}: {e}")
        return []


def parse_proc_net_udp_streaming(path: str = "/proc/net/udp", timeout: float = None) -> tuple:
    """
    Parse /proc/net/udp (or udp6) with streaming and timeout support.
    
    This implementation reads line-by-line instead of loading the entire file,
    allowing it to return partial results if timeout is reached.
    
    Uses adaptive timeout check frequency: checks every 0.1% of the timeout
    budget instead of every line, reducing overhead for large files.
    
    Args:
        path: Path to UDP file (/proc/net/udp or /proc/net/udp6)
        timeout: Maximum seconds for parsing. None means no timeout.
        
    Returns:
        tuple: (result_list, timed_out) where:
            - result_list: List of connection dicts (may be partial if timeout)
            - timed_out: Boolean indicating if timeout was reached
    """
    import time
    
    try:
        if os.path.getsize(path) > 1024 * 1024:
            logger.warning(f"{path} file too large, skip reading")
            return [], False
        
        result = []
        start_time = time.time() if timeout else None
        header_seen = False
        timed_out = False
        
        # Adaptive check interval: check timeout every 0.1% of budget
        # to ensure partial data is returned even under extreme load
        check_interval_lines = 50
        if start_time is not None and timeout > 0:
            estimated_lines = 5000  # Typical /proc/net/udp size
            check_interval_lines = max(50, min(1000, estimated_lines // 1000))
        
        lines_since_check = 0
        
        with open(path, 'r', errors='replace', encoding='utf-8') as f:
            for line in f:
                if start_time is not None:
                    lines_since_check += 1
                    if lines_since_check >= check_interval_lines:
                        lines_since_check = 0
                        if (time.time() - start_time) > timeout:
                            logger.warning(
                                f"{path} streaming parse timed out after {timeout:.1f}s "
                                f"(partial: {len(result)} connections)"
                            )
                            timed_out = True
                            break
                
                if not header_seen:
                    if 'sl' in line:
                        header_seen = True
                    continue
                
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                try:
                    local_addr = parts[1]
                    local_ip, local_port = _parse_hex_addr(local_addr)
                    remote_addr = parts[2]
                    remote_ip, remote_port = _parse_hex_addr(remote_addr)
                    state_hex = parts[3]
                    state = _UDP_STATE_MAP.get(state_hex, state_hex)
                    inode = int(parts[9])
                    result.append({
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                        "inode": inode,
                    })
                except (ValueError, IndexError):
                    continue
        
        return result, timed_out
        
    except OSError as e:
        logger.debug(f"Failed to read {path}: {e}")
        return [], False


def _parse_hex_addr(hex_addr: str) -> tuple:
    """
    Parse hexadecimal address format: IP:PORT
    Support IPv4 (8-bit hex) and IPv6 (32-bit hex) addresses
    """
    ip_hex, port_hex = hex_addr.split(':')

    if len(ip_hex) == 8:
        # IPv4: little-endian 32-bit
        ip_int = int(ip_hex, 16)
        ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
    elif len(ip_hex) == 32:
        # IPv6: 4 groups little-endian 32-bit
        groups = []
        for i in range(0, 32, 8):
            word = int(ip_hex[i:i+8], 16)
            # Byte order conversion for each 32 bits
            word = ((word & 0xFF) << 24) | ((word & 0xFF00) << 8) | \
                   ((word >> 8) & 0xFF00) | ((word >> 24) & 0xFF)
            groups.append(f"{(word >> 16) & 0xFFFF:x}:{word & 0xFFFF:x}")
        ip = ":".join(groups)
    else:
        ip = ip_hex  # fallback

    port = int(port_hex, 16)

    return ip, port
