"""Safe Command Execution Wrapper Module"""
import subprocess
import logging
import os
from typing import List


logger = logging.getLogger("sec-userspace")

# Command whitelist
ALLOWED_COMMANDS = {
    "ps", "ls", "stat", "readlink", "id", "uname",
    "systemctl", "journalctl", "last", "lastlog",
    "lsmod", "modinfo", "ss", "netstat",
    "bpftool", "dmesg",
}


def safe_run(cmd, args: List[str] = None, timeout: int = 30) -> dict:
    """
    Safely execute a command with timeout control and exception handling
    
    Args:
        cmd: Command string or command list
        args: Additional argument list (used when cmd is a string)
        timeout: Timeout in seconds, default 30 seconds
        
    Returns:
        dict: {
            "returncode": int,
            "stdout": str,
            "stderr": str,
            "success": bool
        }
    """
    # Normalize command format
    if isinstance(cmd, str):
        full_cmd = [cmd] + (args or [])
    else:
        full_cmd = list(cmd)

    # Check command whitelist
    if full_cmd and full_cmd[0]:
        cmd_basename = os.path.basename(full_cmd[0])
        if cmd_basename not in ALLOWED_COMMANDS:
            logger.warning(f"Refusing to execute non-whitelisted command: {full_cmd[0]}")
            return {"returncode": -1, "stdout": "", "stderr": f"Command {full_cmd[0]} is not in whitelist", "success": False}
    
    try:
        result = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            shell=False
        )
        
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timeout ({timeout}s): {full_cmd[0] if full_cmd else 'unknown'}")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timeout",
            "success": False
        }
        
    except FileNotFoundError:
        logger.debug(f"Command not found: {full_cmd[0] if full_cmd else 'unknown'}")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command not found",
            "success": False
        }
        
    except (ValueError, TypeError, RuntimeError) as e:
        logger.error(f"Command execution failed: {e}", exc_info=True)
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "success": False
        }
