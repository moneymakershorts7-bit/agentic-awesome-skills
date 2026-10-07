"""Cloud data exfiltration detection analyzer

Detects unauthorized transfer of data to cloud storage accounts for data exfiltration.
Covers AWS S3, GCP Cloud Storage, Azure Blob Storage, and Alibaba Cloud OSS.

ATT&CK Mapping:
- T1537: Transfer Data to Cloud Account
- Tactic: Exfiltration
"""
import re
from typing import Dict, List
from ..reporter.evidence import Evidence, Severity
from ..utils.remediation_generator import generate_generic_remediation
from .base import BaseAnalyzer
from ..utils.fp_tracker import get_tracker, is_false_positive, record_fp
from ..utils.i18n import get_attack_tactic_name
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

class CloudExfiltrationAnalyzer(BaseAnalyzer):
    """Cloud data exfiltration detection analyzer"""
    name = 'cloud_exfiltration_analyzer'
    timeout = 45
    required_collectors = ['process', 'network']
    estimated_time = 2.0
    analyzer_type = BaseAnalyzer.IMPORTANT
    CLOUD_UPLOAD_COMMANDS = {'aws_s3': [re.compile('aws\\s+s3\\s+cp\\s+', re.IGNORECASE), re.compile('aws\\s+s3\\s+sync\\s+', re.IGNORECASE), re.compile('aws\\s+s3api\\s+put-object\\s+', re.IGNORECASE), re.compile('aws\\s+s3api\\s+upload-part\\s+', re.IGNORECASE), re.compile('s3cmd\\s+put\\s+', re.IGNORECASE), re.compile('s3cmd\\s+sync\\s+', re.IGNORECASE)], 'gcp_storage': [re.compile('gsutil\\s+cp\\s+', re.IGNORECASE), re.compile('gsutil\\s+-m\\s+cp\\s+', re.IGNORECASE), re.compile('gsutil\\s+rsync\\s+', re.IGNORECASE), re.compile('gcloud\\s+storage\\s+cp\\s+', re.IGNORECASE), re.compile('gcloud\\s+storage\\s+rsync\\s+', re.IGNORECASE)], 'azure_blob': [re.compile('az\\s+storage\\s+blob\\s+upload\\s+', re.IGNORECASE), re.compile('az\\s+storage\\s+blob\\s+upload-batch\\s+', re.IGNORECASE), re.compile('azcopy\\s+copy\\s+', re.IGNORECASE), re.compile('azcopy\\s+sync\\s+', re.IGNORECASE)], 'alibaba_oss': [re.compile('ossutil\\s+cp\\s+', re.IGNORECASE), re.compile('ossutil\\s+sync\\s+', re.IGNORECASE), re.compile('aliyun\\s+oss\\s+PutObject\\s+', re.IGNORECASE), re.compile('aliyun\\s+oss\\s+UploadPart\\s+', re.IGNORECASE)]}
    CLOUD_STORAGE_ENDPOINTS = {'aws_s3': [re.compile('s3\\.[a-z0-9-]+\\.amazonaws\\.com', re.IGNORECASE), re.compile('\\.s3[a-z0-9-]*\\.amazonaws\\.com', re.IGNORECASE)], 'gcp_storage': [re.compile('storage\\.googleapis\\.com', re.IGNORECASE), re.compile('\\.storage\\.googleapis\\.com', re.IGNORECASE)], 'azure_blob': [re.compile('\\.blob\\.core\\.windows\\.net', re.IGNORECASE), re.compile('\\.blob\\.storage\\.azure\\.net', re.IGNORECASE)], 'alibaba_oss': [re.compile('\\.oss-[a-z0-9-]+\\.aliyuncs\\.com', re.IGNORECASE), re.compile('oss-[a-z0-9-]+\\.aliyuncs\\.com', re.IGNORECASE)]}
    SENSITIVE_FILE_PATTERNS = [re.compile('\\.(sql|dump|bak|backup|tar\\.gz|zip|7z)', re.IGNORECASE), re.compile('(passwd|shadow|\\.ssh|authorized_keys)', re.IGNORECASE), re.compile('(credential|secret|token|key|password)', re.IGNORECASE), re.compile('/etc/(shadow|passwd|ssh/)', re.IGNORECASE), re.compile('\\.(env|config|conf|ini|yaml|yml)$', re.IGNORECASE), re.compile('(database|db_|mysql|postgres|mongo)', re.IGNORECASE)]
    LEGITIMATE_BACKUP_TOOLS = {'rsync', 'scp', 'sftp', 'ftp', 'restic', 'borg', 'duplicity', 'rclone', 'aws-cli', 'gsutil', 'az', 'ossutil', 'backup-agent', 'cloud-backup'}
    PROVIDER_NAMES = {'aws_s3': 'AWS S3', 'gcp_storage': 'GCP Cloud Storage', 'azure_blob': 'Azure Blob Storage', 'alibaba_oss': 'Alibaba Cloud OSS'}
    AUTOMATION_SERVICES = {'jenkins', 'gitlab-runner', 'circleci', 'travis', 'github-actions', 'azure-pipelines', 'cron', 'systemd', 'supervisord', 'airflow'}
    CLOUD_CLI_COMMS = {'aws', 'gsutil', 'gcloud', 'az', 'azcopy', 'ossutil', 'aliyun', 's3cmd'}

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze process and network data for cloud exfiltration.
        
        In quick mode: only checks process command lines for known upload patterns.
        In full mode: performs comprehensive analysis including network connections,
        credential correlation, and abnormal transfer patterns.
        """
        evidences = []
        tracker = get_tracker()
        tracker.record_detection('cloud_exfiltration_analyzer', 1)
        
        try:
            process_data = self._get_data(collected_data, 'process')
            
            if not process_data:
                return evidences
            
            # Always check upload commands (lightweight regex matching)
            evidences.extend(self._detect_upload_commands(process_data))
            
            # Quick mode: only run lightweight command checks
            
            # Full mode: run comprehensive analysis
            network_data = self._get_data(collected_data, 'network')
            if not network_data:
                return evidences
            
            evidences.extend(self._detect_cloud_storage_connections(network_data))
            evidences.extend(self._correlate_with_credential_access(process_data, collected_data))
            evidences.extend(self._detect_abnormal_transfer_patterns(process_data))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().error(f'Cloud exfiltration analysis failed: {e}')
        
        return evidences

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def _detect_upload_commands(self, process_data: Dict) -> List[Evidence]:
        """Detect cloud CLI upload commands in process history"""
        evidences = []
        try:
            processes = process_data.get('processes', [])
            for proc in processes:
                cmdline = proc.get('cmdline', '')
                comm = proc.get('comm', '')
                pid = proc.get('pid', 0)
                if not cmdline:
                    continue
                
                # Fast filter: skip if comm is not a cloud CLI tool
                comm_lower = comm.lower() if comm else ''
                if comm_lower and comm_lower not in self.CLOUD_CLI_COMMS:
                    continue
                
                for provider, patterns in self.CLOUD_UPLOAD_COMMANDS.items():
                    for pattern in patterns:
                        match = pattern.search(cmdline)
                        if match:
                            if self._is_automation_service(comm):
                                continue
                            is_sensitive = self._contains_sensitive_files(cmdline)
                            context = f'upload_command:{provider}:{cmdline[:100]}'
                            if is_false_positive('cloud_exfiltration_analyzer', 'upload_command', context=context):
                                record_fp('cloud_exfiltration_analyzer', 'upload_command', context=f'Suppressed: {context}')
                                continue
                            provider_name = self.PROVIDER_NAMES.get(provider, provider)
                            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
                            confidence = 0.8 if is_sensitive else 0.65
                            evidences.append(self._create_evidence(title=f'Cloud storage upload detected: {provider_name}', description=f"Detected cloud storage upload command:\nProvider: {provider_name}\nProcess: {comm} (PID {pid})\nCommand: {cmdline[:200]}\nSensitive files: {('Yes' if is_sensitive else 'No')}", severity=severity, confidence=confidence, attack_id='T1537', attack_tactic=get_attack_tactic_name('T1537'), source_path=f'/proc/{pid}/cmdline', raw_data={'pid': pid, 'command': comm, 'cmdline': cmdline, 'provider': provider_name, 'matched_pattern': match.group(0), 'sensitive_files': is_sensitive}, remediation=f'Verify this upload is authorized. Check destination bucket/container permissions. Review data classification policies. Enable cloud storage access logging.', evidence_details=self._create_evidence_details(service_type='cloud_exfiltration'), remediation_commands=generate_generic_remediation(attack_id='1537', context={'analyzer': 'cloud_exfiltration_analyzer'})))
                            break
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f'Upload command detection failed: {e}')
        return evidences

    def _detect_cloud_storage_connections(self, network_data: Dict) -> List[Evidence]:
        """Detect network connections to cloud storage endpoints"""
        evidences = []
        try:
            http_connections = network_data.get('http_connections', [])
            dns_queries = network_data.get('dns_queries', [])
            provider_connections = {}
            for conn in http_connections:
                url = conn.get('url', '')
                remote_ip = conn.get('remote_ip', '')
                for provider, patterns in self.CLOUD_STORAGE_ENDPOINTS.items():
                    for pattern in patterns:
                        if pattern.search(url) or (remote_ip and pattern.search(remote_ip)):
                            if provider not in provider_connections:
                                provider_connections[provider] = []
                            provider_connections[provider].append({'type': 'http', 'url': url, 'remote_ip': remote_ip, 'method': conn.get('method', ''), 'bytes_sent': conn.get('bytes_sent', 0)})
                            break
            for query in dns_queries:
                domain = query.get('domain', '')
                for provider, patterns in self.CLOUD_STORAGE_ENDPOINTS.items():
                    for pattern in patterns:
                        if pattern.search(domain):
                            if provider not in provider_connections:
                                provider_connections[provider] = []
                            provider_connections[provider].append({'type': 'dns', 'domain': domain, 'query_type': query.get('type', '')})
                            break
            for provider, connections in provider_connections.items():
                if not connections:
                    continue
                context = f'cloud_connection:{provider}'
                if is_false_positive('cloud_exfiltration_analyzer', 'cloud_connection', context=context):
                    record_fp('cloud_exfiltration_analyzer', 'cloud_connection', context=f'Suppressed: {context}')
                    continue
                provider_name = self.PROVIDER_NAMES.get(provider, provider)
                conn_count = len(connections)
                confidence = 0.7 if conn_count < 5 else 0.85
                severity = Severity.HIGH if conn_count >= 5 else Severity.MEDIUM
                total_bytes = sum((c.get('bytes_sent', 0) for c in connections if 'bytes_sent' in c))
                if total_bytes > 100 * 1024 * 1024:
                    confidence = min(confidence + 0.1, 0.95)
                    severity = Severity.CRITICAL
                evidences.append(self._create_evidence(title=f'Cloud storage endpoint connections: {provider_name}', description=f'Detected {conn_count} connection(s) to {provider_name} storage endpoints.\nTotal bytes sent: {total_bytes:,}\nSample connections: {connections[:3]}', severity=severity, confidence=confidence, attack_id='T1537', attack_tactic=get_attack_tactic_name('T1537'), source_path='/proc/net/tcp', raw_data={'provider': provider_name, 'connection_count': conn_count, 'total_bytes_sent': total_bytes, 'sample_connections': connections[:5]}, remediation=f'Verify cloud storage access is authorized. Check for unusual data transfer volumes. Review VPC/service endpoint configurations. Enable cloud storage access logging and alerts.', evidence_details=self._create_evidence_details(service_type='cloud_exfiltration'), remediation_commands=generate_generic_remediation(attack_id='1537', context={'analyzer': 'cloud_exfiltration_analyzer'})))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f'Cloud storage connection detection failed: {e}')
        return evidences

    def _correlate_with_credential_access(self, process_data: Dict, collected_data: Dict) -> List[Evidence]:
        """Correlate cloud uploads with recent credential access events
        
        Note: The 'auth' collector does not exist in the current collector registry.
        This method attempts to gather credential-related data from available collectors
        (log, filesystem, process) and degrades gracefully if none are available.
        """
        evidences = []
        try:
            credential_events = []
            log_data = self._get_data(collected_data, 'log')
            if log_data:
                auth_log = log_data.get('auth_log', {})
                if auth_log:
                    failed_logins = auth_log.get('failed_logins', [])
                    successful_logins = auth_log.get('successful_logins', [])
                    credential_events.extend(failed_logins + successful_logins)
            if not credential_events:
                _get_logger().debug('No credential access data available for correlation')
                return evidences
            processes = process_data.get('processes', [])
            for proc in processes:
                cmdline = proc.get('cmdline', '')
                comm = proc.get('comm', '')
                if not cmdline:
                    continue
                has_upload = False
                provider = ''
                for prov, patterns in self.CLOUD_UPLOAD_COMMANDS.items():
                    for pattern in patterns:
                        if pattern.search(cmdline):
                            has_upload = True
                            provider = prov
                            break
                    if has_upload:
                        break
                if has_upload and credential_events:
                    context = f'cred_correlation:{provider}:{cmdline[:100]}'
                    if is_false_positive('cloud_exfiltration_analyzer', 'cred_correlation', context=context):
                        record_fp('cloud_exfiltration_analyzer', 'cred_correlation', context=f'Suppressed: {context}')
                        continue
                    provider_name = self.PROVIDER_NAMES.get(provider, provider)
                    evidences.append(self._create_evidence(title=f'Cloud upload correlated with credential access', description=f'Cloud storage upload detected shortly after credential access event.\nThis pattern may indicate data exfiltration using stolen credentials.\nProvider: {provider_name}\nProcess: {comm}\nCommand: {cmdline[:200]}\nCredential events: {len(credential_events)}', severity=Severity.CRITICAL, confidence=0.9, attack_id='T1537', attack_tactic=get_attack_tactic_name('T1537'), source_path=f"/proc/{proc.get('pid', 0)}/cmdline", raw_data={'provider': provider_name, 'command': cmdline, 'credential_event_count': len(credential_events), 'correlation': 'temporal_proximity'}, remediation=f'Investigate potential credential theft immediately. Rotate all cloud credentials. Review cloud IAM policies and restrict permissions. Enable MFA for all cloud accounts.', evidence_details=self._create_evidence_details(service_type='cloud_exfiltration'), remediation_commands=generate_generic_remediation(attack_id='1537', context={'analyzer': 'cloud_exfiltration_analyzer'})))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f'Credential correlation analysis failed: {e}')
        return evidences

    def _detect_abnormal_transfer_patterns(self, process_data: Dict) -> List[Evidence]:
        """Detect abnormal data transfer patterns"""
        evidences = []
        try:
            processes = process_data.get('processes', [])
            upload_counts = {}
            upload_details = []
            for proc in processes:
                cmdline = proc.get('cmdline', '')
                comm = proc.get('comm', '')
                if not cmdline:
                    continue
                
                # Fast filter: skip if comm is not a cloud CLI tool
                comm_lower = comm.lower() if comm else ''
                if comm_lower and comm_lower not in self.CLOUD_CLI_COMMS:
                    continue
                
                for provider, patterns in self.CLOUD_UPLOAD_COMMANDS.items():
                    for pattern in patterns:
                        if pattern.search(cmdline):
                            if provider not in upload_counts:
                                upload_counts[provider] = 0
                            upload_counts[provider] += 1
                            upload_details.append({'provider': provider, 'command': comm, 'cmdline': cmdline[:200]})
            for provider, count in upload_counts.items():
                if count >= 5:
                    context = f'bulk_upload:{provider}:{count}'
                    if is_false_positive('cloud_exfiltration_analyzer', 'bulk_upload', context=context):
                        record_fp('cloud_exfiltration_analyzer', 'bulk_upload', context=f'Suppressed: {context}')
                        continue
                    provider_name = self.PROVIDER_NAMES.get(provider, provider)
                    evidences.append(self._create_evidence(title=f'Bulk cloud upload activity detected: {provider_name}', description=f"Detected {count} upload commands to {provider_name} in single scan.\nThis pattern may indicate automated data exfiltration.\nSample commands: {[d['cmdline'] for d in upload_details[:3]]}", severity=Severity.CRITICAL, confidence=0.85, attack_id='T1537', attack_tactic=get_attack_tactic_name('T1537'), source_path='/proc', raw_data={'provider': provider_name, 'upload_count': count, 'sample_commands': upload_details[:5]}, remediation=f'Investigate bulk upload activity immediately. Check if this matches expected backup schedules. Review cloud storage bucket policies. Implement data loss prevention (DLP) controls.', evidence_details=self._create_evidence_details(service_type='cloud_exfiltration'), remediation_commands=generate_generic_remediation(attack_id='1537', context={'analyzer': 'cloud_exfiltration_analyzer'})))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f'Abnormal transfer pattern detection failed: {e}')
        return evidences

    def _contains_sensitive_files(self, cmdline: str) -> bool:
        """Check if command references sensitive files"""
        for pattern in self.SENSITIVE_FILE_PATTERNS:
            if pattern.search(cmdline):
                return True
        return False

    def _is_automation_service(self, comm: str) -> bool:
        """Check if process is a known automation service"""
        if not comm:
            return False
        return comm.lower() in self.AUTOMATION_SERVICES
