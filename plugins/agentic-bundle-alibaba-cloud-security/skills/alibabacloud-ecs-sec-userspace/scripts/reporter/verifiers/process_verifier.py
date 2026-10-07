"""ProcessVerifier - Verify process-related alerts

Verifies:
- Whether process still exists
- Process signature/binary validation
- Known legitimate process patterns
"""
import os
import logging
from typing import Dict, Optional
from dataclasses import dataclass

from ..evidence import Evidence

logger = logging.getLogger("sec-userspace")


@dataclass
class VerifyCheckResult:
    """Result of a single verification check"""
    is_false_positive: bool
    is_confirmed_threat: bool
    reason: str


class ProcessVerifier:
    """Verify process-related security alerts"""
    
    def __init__(self, collected_data: Optional[Dict] = None):
        """Initialize process verifier
        
        Args:
            collected_data: Collected data from collectors
        """
        self.collected_data = collected_data or {}
        self.processes_cache = self._build_process_cache()
        
        # Known legitimate processes
        self.legitimate_processes = {
            'sshd', 'systemd', 'init', 'cron', 'crond',
            'nginx', 'apache2', 'httpd', 'mysql', 'mysqld',
            'postgres', 'postgresql', 'redis-server', 'mongod',
            'dockerd', 'containerd', 'kubelet', 'docker-proxy',
            'python', 'python3', 'node', 'java', 'go',
            'vim', 'nvim', 'code', 'bash', 'sh', 'zsh',
            'git', 'ssh', 'scp', 'rsync', 'curl', 'wget',
            'apt', 'apt-get', 'yum', 'dnf', 'pacman',
            'systemctl', 'journalctl', 'dmesg', 'ps', 'top',
        }
    
    def _build_process_cache(self) -> Dict[str, dict]:
        """Build cache of currently running processes
        
        Returns:
            Dict mapping PID to process info
        """
        cache = {}
        
        # Try to read from /proc
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                
                pid = int(pid_dir)
                try:
                    with open(f'/proc/{pid}/cmdline', 'rb') as f:
                        cmdline = f.read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
                    
                    with open(f'/proc/{pid}/comm', 'rb') as f:
                        comm = f.read().decode('utf-8', errors='replace').strip()
                    
                    with open(f'/proc/{pid}/exe', 'rb') as f:
                        pass  # Just check if readable
                    
                    exe_path = os.readlink(f'/proc/{pid}/exe') if pid > 0 else ''
                    
                    cache[str(pid)] = {
                        'pid': pid,
                        'name': comm,
                        'cmdline': cmdline,
                        'exe': exe_path,
                    }
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    continue
        except (OSError, ValueError, KeyError) as e:
            logger.debug(f"Failed to build process cache: {e}")
        
        # Also use collected data if available
        if 'process' in self.collected_data:
            proc_data = self.collected_data['process']
            if isinstance(proc_data, dict) and 'processes' in proc_data:
                for proc in proc_data.get('processes', []):
                    pid_str = str(proc.get('pid', ''))
                    if pid_str:
                        cache[pid_str] = proc
        
        return cache
    
    def verify(self, evidence: Evidence) -> VerifyCheckResult:
        """Verify process-related evidence
        
        Args:
            evidence: Evidence to verify
            
        Returns:
            VerifyCheckResult: Verification result
        """
        raw_data = evidence.raw_data or {}
        
        # Check by PID
        pid = raw_data.get('pid') or raw_data.get('target_pid')
        if pid:
            return self._verify_by_pid(str(pid), evidence)
        
        # Check by process name
        process_name = raw_data.get('process') or raw_data.get('name') or raw_data.get('comm')
        if process_name:
            return self._verify_by_name(process_name, evidence)
        
        # Check by cmdline pattern
        cmdline = raw_data.get('cmdline') or raw_data.get('command')
        if cmdline:
            return self._verify_by_cmdline(cmdline, evidence)
        
        # No process indicators found
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason="No process indicators to verify"
        )
    
    def _verify_by_pid(self, pid: str, evidence: Evidence) -> VerifyCheckResult:
        """Verify by checking if PID exists
        
        Args:
            pid: Process ID to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        # Check if process still exists
        if pid in self.processes_cache:
            proc_info = self.processes_cache[pid]
            proc_name = proc_info.get('name', '').lower()
            
            # Check if it's a known legitimate process
            base_name = os.path.basename(proc_name).lower()
            if base_name in self.legitimate_processes:
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Process {proc_name} (PID {pid}) is a known legitimate process"
                )
            
            # Process exists but unknown - needs more investigation
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=False,
                reason=f"Process (PID {pid}) still exists, requires manual review"
            )
        else:
            # Process no longer exists - could be transient or historical
            # This doesn't confirm it was malicious, just that it's gone
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=False,
                reason=f"Process (PID {pid}) no longer exists"
            )
    
    def _verify_by_name(self, process_name: str, evidence: Evidence) -> VerifyCheckResult:
        """Verify by process name
        
        Args:
            process_name: Process name to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        base_name = os.path.basename(process_name).lower()
        
        # Check against known legitimate processes
        if base_name in self.legitimate_processes:
            # Check if path matches expected location
            raw_data = evidence.raw_data or {}
            path = raw_data.get('path') or raw_data.get('exe')
            
            if path and self._is_legitimate_path(base_name, path):
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Process {process_name} at {path} is legitimate"
                )
            
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=False,
                reason=f"Legitimate process name {process_name}, verify path"
            )
        
        # Unknown process - check if running
        matching_procs = [
            p for p in self.processes_cache.values()
            if p.get('name', '').lower() == base_name
        ]
        
        if matching_procs:
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=False,
                reason=f"Unknown process {process_name} is running ({len(matching_procs)} instances)"
            )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Unknown process {process_name} not currently running"
        )
    
    def _verify_by_cmdline(self, cmdline: str, evidence: Evidence) -> VerifyCheckResult:
        """Verify by command line pattern
        
        Args:
            cmdline: Command line to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        cmdline_lower = cmdline.lower()
        
        # Check for sec-userspace itself (avoid self-detection)
        if 'sec-userspace' in cmdline_lower or 'scripts.main' in cmdline_lower:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason="Process is sec-userspace scanner itself"
            )
        
        # Check for AI tooling (Claude Code, Qoder, etc.)
        ai_tools = ['claude', 'qoder', 'cursor', 'opencode', 'copilot']
        for tool in ai_tools:
            if tool in cmdline_lower:
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Process related to AI tooling: {tool}"
                )
        
        # Check for container runtime
        container_patterns = ['docker', 'containerd', 'kubelet', 'kubectl']
        for pattern in container_patterns:
            if pattern in cmdline_lower:
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Process related to container runtime: {pattern}"
                )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Command line requires review: {cmdline[:50]}..."
        )
    
    def _is_legitimate_path(self, process_name: str, path: str) -> bool:
        """Check if process path is legitimate
        
        Args:
            process_name: Process name
            path: Process executable path
            
        Returns:
            bool: Whether path is legitimate
        """
        legitimate_paths = {
            'sshd': ['/usr/sbin/sshd'],
            'nginx': ['/usr/sbin/nginx'],
            'python3': ['/usr/bin/python3'],
            'bash': ['/bin/bash'],
            'systemd': ['/lib/systemd/systemd', '/usr/lib/systemd/systemd'],
        }
        
        if process_name in legitimate_paths:
            return any(path.startswith(lp) for lp in legitimate_paths[process_name])
        
        # Generic check: system binaries in standard locations
        system_prefixes = ['/usr/', '/bin/', '/sbin/', '/opt/']
        return any(path.startswith(prefix) for prefix in system_prefixes)
