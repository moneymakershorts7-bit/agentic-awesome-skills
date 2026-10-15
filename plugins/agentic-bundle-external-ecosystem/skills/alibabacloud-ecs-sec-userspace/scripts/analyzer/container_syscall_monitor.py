"""Container Syscall Anomaly Monitor - Detect Container Escape via Syscall Analysis

Monitors container environments for suspicious syscall patterns that may indicate
container escape attempts. Focuses on detecting:
1. Sensitive syscalls used in container escapes (mount, ptrace, bpf, etc.)
2. Seccomp profile bypass or misconfiguration
3. Device file access from within containers
4. Host filesystem mount operations

ATT&CK mapping:
- T1611 - Escape to Host
- T1610 - Deploy Container
- T1609 - Container Administration Command

References:
- Container escapes frequently use mount/sys_admin capabilities
- Seccomp profiles restrict syscalls but can be bypassed
- Device access (/dev/mem, /dev/sda) indicates host-level access
"""
import os
import re
from typing import List, Dict
from pathlib import Path
from ..reporter.evidence import Evidence
from ..reporter.severity import Severity
from .base import BaseAnalyzer
from ..utils.remediation_generator import generate_generic_remediation
import threading
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

class ContainerSyscallMonitorAnalyzer(BaseAnalyzer):
    """Monitor container syscall behavior for escape detection
    
    Analyzes process capabilities, mount operations, and device access patterns
    to detect potential container escape attempts at the syscall level.
    """
    name = 'container_syscall_monitor'
    timeout = 30
    required_collectors = ['process', 'filesystem']
    estimated_time = 5.0
    analyzer_type = 'important'
    ESCAPE_SYSCALLS = {'mount': {'risk': 'CRITICAL', 'description': 'Mount filesystem operations can access host filesystem', 'attack_id': 'T1611', 'indicators': ['mount\\s+--bind', 'mount\\s+-t\\s+(proc|sysfs|devtmpfs)', 'mount\\s+/dev/', 'mount\\s+.*host']}, 'umount': {'risk': 'HIGH', 'description': 'Unmount operations may hide escape evidence', 'attack_id': 'T1611', 'indicators': ['umount\\s+/proc', 'umount\\s+/sys', 'umount\\s+.*host']}, 'ptrace': {'risk': 'CRITICAL', 'description': 'Process tracing can inject code into host processes', 'attack_id': 'T1055', 'indicators': ['ptrace\\s*\\(', 'gdb\\s+-p\\s+\\d+', 'strace\\s+-p\\s+\\d+', '/proc/\\d+/mem']}, 'bpf': {'risk': 'CRITICAL', 'description': 'eBPF syscalls can hook kernel operations', 'attack_id': 'T1611', 'indicators': ['bpf\\s*\\(', 'bpftool\\s+prog\\s+load']}, 'unshare': {'risk': 'HIGH', 'description': 'Namespace creation can break container isolation', 'attack_id': 'T1611', 'indicators': ['unshare\\s+--mount', 'unshare\\s+--pid', 'unshare\\s+--net', 'unshare\\s+-[mnpU]']}, 'nsenter': {'risk': 'CRITICAL', 'description': 'Enter existing namespaces to escape container', 'attack_id': 'T1611', 'indicators': ['nsenter\\s+--target\\s+\\d+', 'nsenter\\s+-t\\s+\\d+\\s+-[mntpiduts]', 'nsenter\\s+--all']}, 'pivot_root': {'risk': 'CRITICAL', 'description': 'Change root filesystem to escape container', 'attack_id': 'T1611', 'indicators': ['pivot_root\\s+']}, 'kexec_load': {'risk': 'CRITICAL', 'description': 'Load new kernel to bypass container restrictions', 'attack_id': 'T1611', 'indicators': ['kexec\\s+-l']}}
    DANGEROUS_DEVICES = {'/dev/mem': {'risk': 'CRITICAL', 'description': 'Physical memory access - can read host memory', 'attack_id': 'T1611'}, '/dev/kmem': {'risk': 'CRITICAL', 'description': 'Kernel memory access - can modify kernel', 'attack_id': 'T1611'}, '/dev/sda': {'risk': 'HIGH', 'description': 'Host disk access - can read/write host data', 'attack_id': 'T1611'}, '/dev/nvme0': {'risk': 'HIGH', 'description': 'Host NVMe disk access', 'attack_id': 'T1611'}, '/dev/vda': {'risk': 'HIGH', 'description': 'Host virtio disk access', 'attack_id': 'T1611'}}
    SECCOMP_PATTERNS = {'seccomp_disabled': {'pattern': re.compile('--security-opt\\s+seccomp=unconfined', re.IGNORECASE), 'description': 'Seccomp profile disabled', 'severity': Severity.HIGH, 'attack_id': 'T1611'}, 'privileged_mode': {'pattern': re.compile('--privileged', re.IGNORECASE), 'description': 'Container running in privileged mode', 'severity': Severity.CRITICAL, 'attack_id': 'T1611'}, 'cap_add_all': {'pattern': re.compile('--cap-add\\s+ALL', re.IGNORECASE), 'description': 'All capabilities added', 'severity': Severity.CRITICAL, 'attack_id': 'T1611'}, 'apparmor_disabled': {'pattern': re.compile('--security-opt\\s+apparmor=unconfined', re.IGNORECASE), 'description': 'AppArmor profile disabled', 'severity': Severity.MEDIUM, 'attack_id': 'T1611'}}

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        if not self.is_container_env():
            return True, "Not a container environment"
        return False, ""

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute container syscall monitoring analysis
        
        Args:
            collected_data: Dictionary of collector results
            
        Returns:
            List of Evidence objects for syscall anomalies
        """
        evidences = []
        if not self._is_container_environment():
            _get_logger().debug('Not a container environment, skipping syscall monitoring')
            return evidences
        _get_logger().info('Container environment detected, starting syscall monitoring')
        try:
            process_data = self._get_data(collected_data, 'process')
        except KeyError:
            _get_logger().warning('Process data not available for syscall monitoring')
            return evidences
        try:
            filesystem_data = self._get_data(collected_data, 'filesystem')
        except KeyError:
            filesystem_data = {}
        evidences.extend(self._check_escape_syscalls(process_data))
        evidences.extend(self._check_device_access(filesystem_data))
        evidences.extend(self._check_seccomp_config(process_data))
        evidences.extend(self._check_mount_operations(process_data))
        evidences.extend(self._validate_syscall_restrictions())
        _get_logger().info(f'Container syscall monitoring complete: {len(evidences)} evidences found')
        return evidences

    def _is_container_environment(self) -> bool:
        """Detect if running in container environment
        
        Returns:
            True if container environment detected
        """
        if os.path.exists('/.dockerenv'):
            return True
        try:
            with open('/proc/1/cgroup', 'r', errors='replace', encoding='utf-8') as f:
                content = f.read(65536)
                if any((marker in content for marker in ['docker', 'kubepods', 'containerd'])):
                    return True
        except OSError:
            pass
        if os.path.exists('/run/.containerenv'):
            return True
        return False

    def _check_escape_syscalls(self, process_data: Dict) -> List[Evidence]:
        """Detect processes using escape-related syscalls
        
        Args:
            process_data: Process collector data
            
        Returns:
            List of Evidence objects for syscall abuse
        """
        evidences = []
        for proc in process_data.get('processes', []):
            cmdline = proc.get('cmdline', '')
            comm = proc.get('comm', '')
            pid = proc.get('pid', 0)
            if not cmdline:
                continue
            for syscall_name, syscall_info in self.ESCAPE_SYSCALLS.items():
                for indicator in syscall_info['indicators']:
                    if re.search(indicator, cmdline, re.IGNORECASE):
                        severity = Severity.CRITICAL if syscall_info['risk'] == 'CRITICAL' else Severity.HIGH
                        evidences.append(self._create_evidence(title=f'Container Escape Syscall: {syscall_name}', description=f"Process {comm} (PID {pid}) executing syscall-pattern associated with container escape: {syscall_info['description']}. Command: {cmdline[:150]}", severity=severity, confidence=0.75, attack_id=syscall_info['attack_id'], attack_tactic='Lateral Movement', raw_data={'pid': pid, 'comm': comm, 'cmdline': cmdline[:200], 'syscall': syscall_name, 'indicator': indicator}, remediation=f'Investigate process PID={pid} using {syscall_name} syscall. Verify container security profile and seccomp configuration. Review process lineage for escape attempts.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection', pid=pid, cmdline=cmdline[:200]), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'container_syscall_monitor'})))
                        break
        return evidences

    def _check_device_access(self, filesystem_data: Dict) -> List[Evidence]:
        """Detect access to dangerous host device files
        
        Args:
            filesystem_data: Filesystem collector data
            
        Returns:
            List of Evidence objects for device access
        """
        evidences = []
        for file_info in filesystem_data.get('recent_files', []):
            filepath = file_info.get('path', '')
            for device, device_info in self.DANGEROUS_DEVICES.items():
                if filepath.startswith(device):
                    evidences.append(self._create_evidence(title=f'Host Device Access: {device}', description=f"Container process accessed host device {device}: {device_info['description']}. File: {filepath}", severity=Severity.CRITICAL if device_info['risk'] == 'CRITICAL' else Severity.HIGH, confidence=0.85, attack_id=device_info['attack_id'], attack_tactic='Lateral Movement', raw_data={'device': device, 'filepath': filepath, 'file_info': file_info}, remediation=f'Block access to {device} in container seccomp profile. Review container device mappings. Investigate process accessing host device.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection', file_path=filepath), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'container_syscall_monitor'})))
        try:
            for pid_dir in Path('/proc').iterdir():
                if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                    continue
                fd_dir = pid_dir / 'fd'
                if not fd_dir.exists():
                    continue
                try:
                    for fd in fd_dir.iterdir():
                        if fd.is_symlink():
                            target = os.readlink(str(fd))
                            for device in self.DANGEROUS_DEVICES:
                                if target.startswith(device):
                                    evidences.append(self._create_evidence(title=f'Open Host Device FD: {device}', description=f'Process PID={pid_dir.name} has open file descriptor to host device {device}. FD path: {fd}, Target: {target}', severity=Severity.CRITICAL, confidence=0.9, attack_id='T1611', attack_tactic='Lateral Movement', raw_data={'pid': pid_dir.name, 'device': device, 'fd_path': str(fd), 'target': target}, remediation=f'Immediately investigate PID={pid_dir.name}. Block device access in seccomp profile. Check for data exfiltration via device.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection'), remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'container_syscall_monitor'})))
                except OSError:
                    continue
        except OSError:
            pass
        return evidences

    def _check_seccomp_config(self, process_data: Dict) -> List[Evidence]:
        """Detect seccomp profile misconfiguration or bypass
        
        Args:
            process_data: Process collector data
            
        Returns:
            List of Evidence objects for seccomp issues
        """
        evidences = []
        for proc in process_data.get('processes', []):
            cmdline = proc.get('cmdline', '')
            pid = proc.get('pid', 0)
            if not cmdline:
                continue
            for pattern_name, pattern_info in self.SECCOMP_PATTERNS.items():
                if pattern_info['pattern'].search(cmdline):
                    evidences.append(self._create_evidence(title=f"Seccomp Misconfiguration: {pattern_info['description']}", description=f'Container process executed with insecure security profile. Pattern: {pattern_name}. Command: {cmdline[:150]}', severity=pattern_info['severity'], confidence=0.8, attack_id=pattern_info['attack_id'], attack_tactic='Defense Evasion', raw_data={'pid': pid, 'cmdline': cmdline[:200], 'pattern': pattern_name}, remediation='Apply restrictive seccomp profile to container. Avoid running containers in privileged mode. Use --cap-drop=ALL and add only required capabilities.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection', pid=pid, cmdline=cmdline[:200]), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'container_syscall_monitor'})))
        try:
            with open('/proc/self/status', 'r', errors='replace', encoding='utf-8') as f:
                status_content = f.read()
            for line in status_content.split('\n'):
                if line.startswith('Seccomp:'):
                    seccomp_mode = line.split(':')[1].strip()
                    if seccomp_mode == '0':
                        evidences.append(self._create_evidence(title='Seccomp Disabled in Container', description=f'Container process running with seccomp disabled (mode={seccomp_mode}). All syscalls are allowed, increasing escape risk.', severity=Severity.MEDIUM, confidence=0.6, attack_id='T1611', attack_tactic='Defense Evasion', raw_data={'seccomp_mode': seccomp_mode, 'mode_description': 'disabled'}, remediation='Enable seccomp filtering for container. Use docker run --security-opt seccomp=default.json or custom seccomp profile.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection'), remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'container_syscall_monitor'})))
                    break
        except OSError:
            pass
        return evidences

    def _check_mount_operations(self, process_data: Dict) -> List[Evidence]:
        """Detect mount operations that may indicate host filesystem access
        
        Args:
            process_data: Process collector data
            
        Returns:
            List of Evidence objects for suspicious mounts
        """
        evidences = []
        try:
            with open('/proc/self/mountinfo', 'r', errors='replace', encoding='utf-8') as f:
                mountinfo = f.read()
            suspicious_mounts = [('/proc/\\d+/root', 'Host root filesystem via proc'), ('/host', 'Host filesystem mount'), ('/mnt/host', 'Host mount point'), ('/rootfs', 'Root filesystem mount'), ('/var/run/docker\\.sock', 'Docker socket mount'), ('/var/run/containerd/containerd\\.sock', 'Containerd socket mount')]
            for pattern, description in suspicious_mounts:
                if re.search(pattern, mountinfo):
                    evidences.append(self._create_evidence(title=f'Suspicious Mount: {description}', description=f'Container has suspicious mount: {description}. Pattern matched: {pattern}', severity=Severity.HIGH, confidence=0.7, attack_id='T1611', attack_tactic='Lateral Movement', raw_data={'pattern': pattern, 'description': description, 'mount_sample': mountinfo[:500]}, remediation=f'Review container mount configuration. Remove unnecessary host filesystem mounts. Use read-only mounts where possible.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection'), remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'container_syscall_monitor'})))
        except OSError:
            pass
        for proc in process_data.get('processes', []):
            cmdline = proc.get('cmdline', '')
            pid = proc.get('pid', 0)
            if not cmdline:
                continue
            host_mount_patterns = [('mount\\s+.*\\/proc\\/\\d+\\/root', 'Proc-based host root mount'), ('mount\\s+.*host.*-t\\s+', 'Explicit host filesystem mount'), ('mount\\s+--bind\\s+/\\s+', 'Root bind mount')]
            for pattern, description in host_mount_patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    evidences.append(self._create_evidence(title=f'Host Mount Attempt: {description}', description=f"Process {proc.get('comm')} (PID {pid}) attempting to mount host filesystem: {description}. Command: {cmdline[:150]}", severity=Severity.CRITICAL, confidence=0.85, attack_id='T1611', attack_tactic='Lateral Movement', raw_data={'pid': pid, 'cmdline': cmdline[:200], 'pattern': description}, remediation='Block mount syscalls in container seccomp profile. Investigate process attempting host mount. Review container security configuration.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection', pid=pid, cmdline=cmdline[:200]), remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'container_syscall_monitor'})))
        return evidences

    def _validate_syscall_restrictions(self) -> List[Evidence]:
        """Validate that container has proper syscall restrictions
        
        Returns:
            List of Evidence objects for restriction issues
        """
        evidences = []
        try:
            with open('/proc/self/status', 'r', errors='replace', encoding='utf-8') as f:
                status_content = f.read()
            cap_eff = None
            for line in status_content.split('\n'):
                if line.startswith('CapEff:'):
                    cap_eff = line.split(':')[1].strip()
                    break
            if cap_eff:
                cap_int = int(cap_eff, 16)
                if cap_int & 1 << 21:
                    evidences.append(self._create_evidence(title='Container Has CAP_SYS_ADMIN Capability', description='Container process has CAP_SYS_ADMIN capability, which allows mount operations, namespace manipulation, and many other privileged operations that can lead to container escape.', severity=Severity.HIGH, confidence=0.75, attack_id='T1611', attack_tactic='Lateral Movement', raw_data={'capability': 'CAP_SYS_ADMIN', 'cap_hex': cap_eff, 'bit': 21}, remediation='Remove CAP_SYS_ADMIN from container unless absolutely required. Use specific capabilities instead of ALL. Apply seccomp profile to restrict mount syscalls.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection'), remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'container_syscall_monitor'})))
                if cap_int & 1 << 19:
                    evidences.append(self._create_evidence(title='Container Has CAP_SYS_PTRACE Capability', description='Container process has CAP_SYS_PTRACE capability, which allows ptrace operations on host processes, enabling code injection and process manipulation.', severity=Severity.HIGH, confidence=0.7, attack_id='T1055', attack_tactic='Defense Evasion', raw_data={'capability': 'CAP_SYS_PTRACE', 'cap_hex': cap_eff, 'bit': 19}, remediation='Remove CAP_SYS_PTRACE from container. Block ptrace syscall in seccomp profile. Investigate if process tracing is required.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection'), remediation_commands=generate_generic_remediation(attack_id='1055', context={'analyzer': 'container_syscall_monitor'})))
                if cap_int & 1 << 1:
                    evidences.append(self._create_evidence(title='Container Has CAP_DAC_OVERRIDE Capability', description='Container process has CAP_DAC_OVERRIDE capability, which bypasses file read/write/execute permission checks, allowing access to sensitive host files.', severity=Severity.MEDIUM, confidence=0.65, attack_id='T1611', attack_tactic='Lateral Movement', raw_data={'capability': 'CAP_DAC_OVERRIDE', 'cap_hex': cap_eff, 'bit': 1}, remediation='Remove CAP_DAC_OVERRIDE unless required. Use specific file permissions instead. Monitor access to sensitive files.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection'), remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'container_syscall_monitor'})))
        except (OSError, ValueError):
            pass
        try:
            with open('/proc/self/status', 'r', errors='replace', encoding='utf-8') as f:
                status_content = f.read()
            for line in status_content.split('\n'):
                if line.startswith('Seccomp:'):
                    seccomp_mode = line.split(':')[1].strip()
                    if seccomp_mode == '0':
                        evidences.append(self._create_evidence(title='Seccomp Filtering Disabled', description=f'Container running with seccomp disabled (mode={seccomp_mode}). No syscall filtering is active, allowing all syscalls including those used for container escape.', severity=Severity.MEDIUM, confidence=0.6, attack_id='T1611', attack_tactic='Defense Evasion', raw_data={'seccomp_mode': seccomp_mode}, remediation='Enable seccomp filtering with restrictive profile. Use Docker default seccomp profile or custom profile. Block dangerous syscalls like mount, ptrace, bpf.', evidence_details=self._create_evidence_details(service_type='container', content='Container  detection'), remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'container_syscall_monitor'})))
                    break
        except OSError:
            pass
        return evidences