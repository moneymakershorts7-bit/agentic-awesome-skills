"""File Access Pattern Analysis Analyzer - Runtime Behavior Monitoring"""
import re
from typing import List, Dict
from ..reporter.evidence import Evidence, Severity
from ..utils.remediation_generator import generate_generic_remediation
from .base import BaseAnalyzer
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

class FileBehaviorAnalyzer(BaseAnalyzer):
    """Monitor sensitive file access patterns and detect credential theft attempts
    
    ATT&CK Coverage: T1083 (File Discovery), T1005 (Data from Local System),
                     T1552 (Unsecured Credentials), T1564 (Hide Artifacts)
    """
    name = 'file_behavior_analyzer'
    timeout = 30
    required_collectors = ['filesystem', 'process']
    estimated_time = 4.0
    analyzer_type = BaseAnalyzer.IMPORTANT
    SENSITIVE_FILES = {'/etc/shadow': {'severity': Severity.CRITICAL, 'attack_id': 'T1552.004'}, '/etc/gshadow': {'severity': Severity.CRITICAL, 'attack_id': 'T1552.004'}, '/etc/ssh/sshd_config': {'severity': Severity.HIGH, 'attack_id': 'T1552.004'}, '/root/.ssh/authorized_keys': {'severity': Severity.HIGH, 'attack_id': 'T1098.004'}, '/root/.ssh/id_rsa': {'severity': Severity.CRITICAL, 'attack_id': 'T1552.004'}, '/root/.bash_history': {'severity': Severity.MEDIUM, 'attack_id': 'T1552.001'}, '/var/log/auth.log': {'severity': Severity.HIGH, 'attack_id': 'T1070.002'}, '/var/log/secure': {'severity': Severity.HIGH, 'attack_id': 'T1070.002'}}
    CREDENTIAL_PATTERNS = [(re.compile('.*\\.pem$', re.IGNORECASE), 'Private key file'), (re.compile('.*\\.key$', re.IGNORECASE), 'Key file'), (re.compile('.*\\.p12$', re.IGNORECASE), 'PKCS12 certificate'), (re.compile('.*\\.pfx$', re.IGNORECASE), 'PFX certificate'), (re.compile('.*/\\.env$', re.IGNORECASE), 'Environment file with secrets'), (re.compile('.*/credentials$', re.IGNORECASE), 'Credentials file'), (re.compile('.*/\\.aws/.*', re.IGNORECASE), 'AWS credentials'), (re.compile('.*/\\.kube/config$', re.IGNORECASE), 'Kubernetes config'), (re.compile('.*/id_rsa$', re.IGNORECASE), 'SSH private key'), (re.compile('.*/id_ed25519$', re.IGNORECASE), 'SSH Ed25519 key')]
    SUSPICIOUS_ACCESS_SEQUENCES = {'credential_harvesting': {'files': ['/etc/shadow', '/etc/passwd', '/etc/group'], 'description': 'Sequential access to authentication files', 'severity': Severity.CRITICAL, 'attack_id': 'T1552'}, 'log_tampering': {'files': ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages'], 'description': 'Access to multiple log files (potential tampering)', 'severity': Severity.HIGH, 'attack_id': 'T1070.002'}, 'ssh_key_theft': {'patterns': ['.ssh/authorized_keys', '.ssh/id_rsa', '.ssh/known_hosts'], 'description': 'SSH key enumeration or theft', 'severity': Severity.CRITICAL, 'attack_id': 'T1552.004'}}

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze file access patterns for suspicious activity"""
        evidences = []
        fs_data = self._get_data(collected_data, 'filesystem')
        if not fs_data:
            _get_logger().warning(f'[{self.name}] No filesystem data available')
            return evidences
        try:
            modified_files = fs_data.get('modified_files', [])
            suspicious_files = fs_data.get('suspicious_files', [])
            evidences.extend(self._check_sensitive_file_access(modified_files))
            evidences.extend(self._check_credential_file_patterns(suspicious_files))
            evidences.extend(self._check_mass_enumeration(modified_files))
            if evidences:
                _get_logger().info(f'[{self.name}] Found {len(evidences)} suspicious file access patterns')
            else:
                _get_logger().info(f'[{self.name}] No suspicious file access patterns detected')
        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().error(f'[{self.name}] Error during analysis: {e}', exc_info=True)
        return evidences
    def _check_sensitive_file_access(self, modified_files: List[Dict]) -> List[Evidence]:
        """Check for access to known sensitive files"""
        evidences = []
        accessed_sensitive = []
        for file_info in modified_files:
            filepath = file_info.get('path', '')
            if filepath in self.SENSITIVE_FILES:
                config = self.SENSITIVE_FILES[filepath]
                accessed_sensitive.append((filepath, file_info, config))
        if len(accessed_sensitive) >= 2:
            evidence = self._create_evidence(title='Multiple Sensitive Files Accessed', description=f'Detected access to {len(accessed_sensitive)} sensitive system files:\n\n' + '\n'.join([f"  - {filepath}\n    Modified: {fi.get('mtime', 'N/A')}" for filepath, fi, cfg in accessed_sensitive[:5]]), severity=Severity.CRITICAL, confidence=0.85, attack_id='T1552', attack_tactic='Credential Access', source_path='filesystem_monitoring', raw_data={'accessed_files': [fp for fp, fi, cfg in accessed_sensitive], 'count': len(accessed_sensitive)}, remediation='Investigate which process accessed these files. Check audit logs for unauthorized access. Review file integrity monitoring alerts.', evidence_details=self._create_evidence_details(service_type='file_system'), remediation_commands=generate_generic_remediation(attack_id='T1552', context={'analyzer': 'file_behavior_analyzer'}))
            evidences.append(evidence)
        elif len(accessed_sensitive) == 1:
            filepath, file_info, config = accessed_sensitive[0]
            evidence = self._create_evidence(title=f'Sensitive File Accessed: {filepath}', description=f"Access detected to critical system file:\n  File: {filepath}\n  Modified: {file_info.get('mtime', 'N/A')}\n  Size: {file_info.get('size', 'N/A')} bytes", severity=config['severity'], confidence=0.75, attack_id=config['attack_id'], attack_tactic='Credential Access', source_path=filepath, raw_data=file_info, remediation='Verify this access is authorized and expected.', evidence_details=self._create_evidence_details(service_type='file_system'), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'file_behavior_analyzer'}))
            evidences.append(evidence)
        return evidences

    def _check_credential_file_patterns(self, suspicious_files: List[Dict]) -> List[Evidence]:
        """Check for credential-related file patterns"""
        evidences = []
        matched_credentials = []
        for file_info in suspicious_files:
            filepath = file_info.get('path', '')
            for pattern, description in self.CREDENTIAL_PATTERNS:
                if pattern.match(filepath):
                    matched_credentials.append((filepath, description, file_info))
                    break
        if matched_credentials:
            evidence = self._create_evidence(title='Credential-Related Files Detected', description=f'Found {len(matched_credentials)} files potentially containing credentials:\n\n' + '\n'.join([f'  - {filepath}\n    Type: {desc}' for filepath, desc, fi in matched_credentials[:10]]), severity=Severity.HIGH, confidence=0.7, attack_id='T1552.001', attack_tactic='Credential Access', source_path='filesystem_scan', raw_data={'credential_files': [fp for fp, desc, fi in matched_credentials], 'count': len(matched_credentials)}, remediation='Ensure these files have proper permissions (600 or stricter). Rotate any exposed credentials. Move secrets to a vault solution.', evidence_details=self._create_evidence_details(service_type='file_system'), remediation_commands=generate_generic_remediation(attack_id='T1552.001', context={'analyzer': 'file_behavior_analyzer'}))
            evidences.append(evidence)
        return evidences

    def _check_mass_enumeration(self, modified_files: List[Dict]) -> List[Evidence]:
        """Detect mass file enumeration (reconnaissance indicator)"""
        evidences = []
        if len(modified_files) > 100:
            evidence = self._create_evidence(title='Mass File Enumeration Detected', description=f'Unusually high number of file modifications/accesses:\n  Total files: {len(modified_files)}\n  This may indicate reconnaissance or ransomware activity', severity=Severity.MEDIUM, confidence=0.65, attack_id='T1083', attack_tactic='Discovery', source_path='filesystem_monitoring', raw_data={'file_count': len(modified_files), 'sample_files': [fi.get('path', '') for fi in modified_files[:10]]}, remediation='Investigate the process performing mass file operations. Check if this matches backup or indexing activity. If unexpected, isolate the system immediately.', evidence_details=self._create_evidence_details(service_type='file_system'), remediation_commands=generate_generic_remediation(attack_id='1083', context={'analyzer': 'file_behavior_analyzer'}))
            evidences.append(evidence)
        return evidences