"""Memory Resident Threat Detection Analyzer"""
import os
from typing import List, Dict
from ..reporter.evidence import Evidence, Severity
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

class MemoryThreatAnalyzer(BaseAnalyzer):
    """Detect memory-resident threats including code injection and rogue libraries"""
    name = 'memory_threat_analyzer'
    timeout = 30
    required_collectors = ['process']
    estimated_time = 5.0
    analyzer_type = BaseAnalyzer.CRITICAL
    SUSPICIOUS_MEMFD_NAMES = ['memfd:', 'anon_inode:', '[deleted]']
    DANGEROUS_ENV_VARS = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG', 'DYLD_INSERT_LIBRARIES']
    INJECTION_INDICATORS = ['/proc/self/mem', '/proc/kcore', '/dev/mem', '/dev/kmem']

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze processes for memory-resident threats"""
        evidences = []
        processes = self._get_data(collected_data, 'process')
        if not processes:
            _get_logger().warning(f'[{self.name}] No process data available')
            return evidences
        try:
            process_list = processes.get('processes', [])
            if not process_list:
                _get_logger().info(f'[{self.name}] Empty process list')
                return evidences
            for proc in process_list:
                pid = str(proc.get('pid', ''))
                if not pid:
                    continue
                evidences.extend(self._check_memfd_abuse(pid, proc))
                evidences.extend(self._check_ld_preload_abuse(proc))
                evidences.extend(self._check_ptrace_attachment(pid, proc))
                evidences.extend(self._check_suspicious_maps(pid, proc))
            if evidences:
                _get_logger().info(f'[{self.name}] Found {len(evidences)} memory threat indicators')
            else:
                _get_logger().info(f'[{self.name}] No memory threats detected')
        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().error(f'[{self.name}] Error during analysis: {e}', exc_info=True)
        return evidences

    def should_skip(self) -> tuple:
        """Don't skip; uses lightweight checks in quick mode."""
        return (False, '')
    def _check_memfd_abuse(self, pid: str, proc: Dict) -> List[Evidence]:
        """Check for memfd_create abuse (fileless malware indicator)"""
        evidences = []
        cmdline = proc.get('cmdline', '')
        exe = proc.get('exe', '')
        has_memfd = any((indicator in exe or indicator in cmdline for indicator in self.SUSPICIOUS_MEMFD_NAMES))
        if has_memfd:
            evidence = self._create_evidence(title='Potential Fileless Malware via memfd_create', description=f"Process may be using memfd_create for fileless execution:\n  PID: {pid}\n  Process: {proc.get('comm')}\n  Executable: {exe}\n  Command: {cmdline}\n  User: {proc.get('username', 'N/A')}", severity=Severity.CRITICAL, confidence=0.85, attack_id='T1620', attack_tactic='Defense Evasion', source_path=f'/proc/{pid}/exe', raw_data={'pid': pid, 'name': proc.get('comm'), 'exe': exe, 'cmdline': cmdline}, remediation='Investigate if this is legitimate use of memfd_create. Fileless malware often uses this technique to avoid disk-based detection. Capture memory dump and terminate if malicious.', evidence_details=self._create_evidence_details(service_type='memory_inspection'), remediation_commands=generate_generic_remediation(attack_id='1620', context={'analyzer': 'memory_threat_analyzer'}))
            evidences.append(evidence)
        return evidences

    def _check_ld_preload_abuse(self, proc: Dict) -> List[Evidence]:
        """Check for LD_PRELOAD library injection"""
        evidences = []
        environ_dict = proc.get('environ', {})
        for dangerous_var in self.DANGEROUS_ENV_VARS:
            if dangerous_var in environ_dict:
                var_value = environ_dict[dangerous_var]
                evidence = self._create_evidence(title=f'Suspicious Environment Variable: {dangerous_var}', description=f"Process has potentially injected library via environment:\n  PID: {proc.get('pid')}\n  Process: {proc.get('comm')}\n  Variable: {dangerous_var}\n  Value: {var_value}\n  Command: {proc.get('cmdline')}", severity=Severity.HIGH, confidence=0.8, attack_id='T1574.006', attack_tactic='Persistence', source_path=f"/proc/{proc.get('pid', '')}/environ", raw_data={'pid': proc.get('pid'), 'name': proc.get('comm'), 'env_var': dangerous_var, 'env_value': var_value}, remediation=f'Check if {dangerous_var} is set intentionally. Attackers use this to inject malicious shared libraries. Unset the variable if unauthorized and restart the process.', evidence_details=self._create_evidence_details(service_type='memory_inspection'), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'memory_threat_analyzer'}))
                evidences.append(evidence)
        return evidences

    def _check_ptrace_attachment(self, pid: str, proc: Dict) -> List[Evidence]:
        """Check for suspicious ptrace attachments (code injection indicator)"""
        evidences = []
        fd_list = proc.get('fd_list', [])
        for fd_info in fd_list:
            target = fd_info.get('target', '')
            if target in self.INJECTION_INDICATORS:
                evidence = self._create_evidence(title=f'Kernel Memory Access Detected: {target}', description=f"Process has opened kernel memory interface:\n  PID: {pid}\n  Process: {proc.get('comm')}\n  File: {target}\n  Command: {proc.get('cmdline')}", severity=Severity.CRITICAL, confidence=0.85, attack_id='T1014', attack_tactic='Defense Evasion', source_path=f'/proc/{pid}/fd', raw_data={'pid': pid, 'name': proc.get('comm'), 'file': target, 'cmdline': proc.get('cmdline')}, remediation='Access to /dev/mem or /proc/kcore indicates potential rootkit activity. Investigate immediately and consider system compromise.', evidence_details=self._create_evidence_details(service_type='memory_inspection'), remediation_commands=generate_generic_remediation(attack_id='1014', context={'analyzer': 'memory_threat_analyzer'}))
                evidences.append(evidence)
        status_path = f'/proc/{pid}/status'
        try:
            if os.path.exists(status_path):
                with open(status_path, 'r', encoding='utf-8') as f:
                    status_content = f.read()
                tracer_pid_line = None
                for line in status_content.split('\n'):
                    if line.startswith('TracerPid:'):
                        tracer_pid_line = line
                        break
                if tracer_pid_line:
                    tracer_pid = tracer_pid_line.split(':')[1].strip()
                    if tracer_pid != '0':
                        tracer_name = self._get_process_name(tracer_pid)
                        evidence = self._create_evidence(title='Process Being Traced (Potential Code Injection)', description=f"Process is being traced by another process:\n  Target PID: {pid}\n  Target: {proc.get('comm')}\n  Tracer PID: {tracer_pid}\n  Tracer: {tracer_name}\n  Command: {proc.get('cmdline')}", severity=Severity.MEDIUM, confidence=0.65, attack_id='T1055.008', attack_tactic='Defense Evasion', source_path=status_path, raw_data={'target_pid': pid, 'target_name': proc.get('comm'), 'tracer_pid': tracer_pid, 'tracer_name': tracer_name}, remediation='Ptrace can be used for legitimate debugging or malicious injection. Verify if the tracer is authorized. Investigate if unexpected.', evidence_details=self._create_evidence_details(service_type='memory_inspection'), remediation_commands=generate_generic_remediation(attack_id='1055.008', context={'analyzer': 'memory_threat_analyzer'}))
                        evidences.append(evidence)
        except OSError:
            pass
        return evidences

    def _check_suspicious_maps(self, pid: str, proc: Dict) -> List[Evidence]:
        """Check for suspicious memory mappings"""
        evidences = []
        maps_path = f'/proc/{pid}/maps'
        try:
            if os.path.exists(maps_path):
                with open(maps_path, 'r', encoding='utf-8') as f:
                    maps_content = f.read()
                suspicious_regions = []
                for line in maps_content.split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    perms = parts[1] if len(parts) > 1 else ''
                    path = parts[-1] if len(parts) > 0 else ''
                    if 'x' in perms and ('[heap]' in path or '[stack]' in path or path == ''):
                        suspicious_regions.append({'perms': perms, 'path': path, 'region': parts[0]})
                if len(suspicious_regions) > 3:
                    evidence = self._create_evidence(title='Suspicious Executable Memory Regions', description=f"Process has multiple executable memory regions:\n  PID: {pid}\n  Process: {proc.get('comm')}\n  Suspicious regions: {len(suspicious_regions)}\n  Command: {proc.get('cmdline')}", severity=Severity.MEDIUM, confidence=0.6, attack_id='T1055.001', attack_tactic='Defense Evasion', source_path=maps_path, raw_data={'pid': pid, 'name': proc.get('comm'), 'suspicious_count': len(suspicious_regions), 'regions': suspicious_regions[:5]}, remediation='Multiple executable memory regions may indicate code injection. Investigate the process and consider memory forensics.', evidence_details=self._create_evidence_details(service_type='memory_inspection'), remediation_commands=generate_generic_remediation(attack_id='1055.001', context={'analyzer': 'memory_threat_analyzer'}))
                    evidences.append(evidence)
        except OSError:
            pass
        return evidences

    def _get_process_name(self, pid: str) -> str:
        """Get process name from PID"""
        try:
            comm_path = f'/proc/{pid}/comm'
            if os.path.exists(comm_path):
                with open(comm_path, 'r', encoding='utf-8') as f:
                    return f.read().strip()
        except OSError:
            pass
        return 'unknown'