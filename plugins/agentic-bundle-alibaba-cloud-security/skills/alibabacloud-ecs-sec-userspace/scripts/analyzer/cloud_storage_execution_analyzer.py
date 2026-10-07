"""Cloud storage execution detection analyzer - T1204.005"""
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Pattern

from ..reporter.evidence import Evidence, EvidenceDetail, Severity
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

class CloudStorageExecutionAnalyzer(BaseAnalyzer):
    """Detect execution from cloud storage services (ATT&CK T1204.005)"""
    
    name = "cloud_storage_execution_analyzer"
    timeout = 30
    required_collectors = ["process"]
    
    estimated_time = 3.0
    analyzer_type = BaseAnalyzer.IMPORTANT
    
    ATTACK_ID = "T1204.005"
    ATTACK_TACTIC = "Execution"
    
    EXECUTION_WINDOW_SECONDS = 60
    
    def __init__(self, workspace_dir: str = None):
        super().__init__(workspace_dir)
        self.cloud_providers = self._load_cloud_providers()
        self.execution_patterns = self._compile_execution_patterns()
    
    def _load_cloud_providers(self) -> dict:
        """Load cloud provider database from assets"""
        from ..utils.path_resolver import get_asset_path
        providers_file = get_asset_path('whitelist', 'cloud-providers.json')
        
        try:
            if os.path.exists(providers_file):
                with open(providers_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    _get_logger().info(f"Loaded {len(data.get('providers', []))} cloud providers")
                    return data
        except (OSError, KeyError, ValueError) as e:
            _get_logger().warning(f"Failed to load cloud providers database: {e}")
        
        return {"providers": [], "execution_patterns": []}
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def _compile_execution_patterns(self) -> List[Pattern]:
        """Compile regex patterns for execution detection"""
        patterns = []
        for pattern_str in self.cloud_providers.get('execution_patterns', []):
            try:
                patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error as e:
                _get_logger().warning(f"Invalid execution pattern: {e}")
        return patterns
    
    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Main analysis entry point"""
        evidences = []
        
        process_data = self._get_data(collected_data, "process", default={}, strict=False)
        network_data = self._get_data(collected_data, "network", default={}, strict=False)
        
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        network = network_data.get("connections", []) if isinstance(network_data, dict) else []
        
        if not processes:
            _get_logger().debug("No process data available for cloud storage analysis")
            return evidences
        
        evidence_list = []
        
        evidence_list.extend(self._detect_direct_pipe_execution(processes))
        
        evidence_list.extend(self._correlate_download_execute(processes, network))
        
        evidence_list.extend(self._check_cloud_api_usage(processes))
        
        evidence_list.extend(self._detect_sync_folder_execution(processes))
        
        for ev in evidence_list:
            if not self._check_whitelist(ev.raw_data.get('cmdline', '')):
                evidences.append(ev)
        
        return evidences
    
    def _identify_cloud_provider(self, url_or_cmdline: str) -> Optional[Dict]:
        """Identify cloud storage provider from URL or command line"""
        url_lower = url_or_cmdline.lower()
        
        for provider in self.cloud_providers.get('providers', []):
            domains = provider.get('domains', [])
            api_patterns = provider.get('api_patterns', [])
            
            for domain in domains:
                domain_pattern = domain.replace('*.', '').lower()
                if domain_pattern in url_lower:
                    return provider
            
            for pattern in api_patterns:
                if pattern.lower() in url_lower:
                    return provider
        
        return None
    
    def _detect_direct_pipe_execution(self, processes: List) -> List[Evidence]:
        """Detect direct pipe execution from cloud URLs (CRITICAL severity)"""
        evidences = []
        
        pipe_patterns = [
            re.compile(r'curl\s+.*(?:https?://|s3://).*\|\s*(?:bash|sh|zsh|python|perl|ruby)', re.IGNORECASE),
            re.compile(r'wget\s+.*(?:https?://|s3://).*\|\s*(?:bash|sh|zsh|python|perl|ruby)', re.IGNORECASE),
            re.compile(r'(?:bash|sh|zsh)\s+<\s*\(curl\s+.*(?:s3\.|blob\.|storage\.|onedrive|drive\.google)'),
        ]
        
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            if not cmdline:
                continue
            
            is_suspicious = False
            for pattern in pipe_patterns:
                if pattern.search(cmdline):
                    is_suspicious = True
                    break
            
            if not is_suspicious:
                for exec_pattern in self.execution_patterns:
                    if exec_pattern.search(cmdline):
                        is_suspicious = True
                        break
            
            if is_suspicious:
                provider = self._identify_cloud_provider(cmdline)
                provider_name = provider['name'] if provider else 'Unknown'
                
                evidence = self._create_evidence(
                    title=f"Direct Execution from Cloud Storage: {provider_name}",
                    description=f"Suspicious pipe execution detected from cloud storage. "
                               f"Command: {cmdline[:200]}",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    attack_id=self.ATTACK_ID,
                    attack_tactic=self.ATTACK_TACTIC,
                    source_path=proc.get('exe', ''),
                    raw_data={
                        'pid': proc.get('pid'),
                        'cmdline': cmdline,
                        'user': proc.get('user', ''),
                        'cloud_provider': provider_name,
                        'execution_method': 'direct_pipe',
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    },
                    remediation="Investigate the process immediately. Block direct pipe execution "
                               "from cloud URLs. Review network logs for data exfiltration.",
                    evidence_details=EvidenceDetail(
                        pid=proc.get('pid', 0),
                        cmdline=proc.get('cmdline', '')[:300],
                        executable=proc.get('exe', ''),
                        file_path=proc.get('file_path', proc.get('path', '')),
                        remote_address=proc.get('remote_address', proc.get('ip', '')),
                        connection_state=proc.get('state', ''),
                        user=proc.get('user', proc.get('username', ''))
                    ),
                    remediation_commands=[
                        "Investigate user activity and lock account if compromised",
                        "Review user authentication logs",
                        "Check for unauthorized access from this user",
                        "Audit user permissions and group memberships"
                    ]
                )
                evidences.append(evidence)
        
        return evidences
    
    def _correlate_download_execute(self, processes: List, network: List) -> List[Evidence]:
        """Correlate downloads from cloud storage with subsequent execution (HIGH severity)"""
        evidences = []
        
        download_indicators = [
            re.compile(r'(?:curl|wget|aws\s+s3\s+cp|gsutil\s+cp|az\s+storage\s+blob\s+download)'),
            re.compile(r'(?:boto3|google.cloud|azure.storage|dropbox).*\.get|\.download'),
        ]
        
        execution_indicators = [
            re.compile(r'chmod\s+\+x'),
            re.compile(r'\./\S+'),
            re.compile(r'(?:bash|sh|python|python3|perl|ruby)\s+\S+\.(?:sh|py|pl|rb)'),
        ]
        
        cloud_downloads = []
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            if not cmdline:
                continue
            
            is_download = any(p.search(cmdline) for p in download_indicators)
            if is_download:
                provider = self._identify_cloud_provider(cmdline)
                if provider:
                    cloud_downloads.append({
                        'process': proc,
                        'provider': provider,
                        'timestamp': proc.get('start_time', '')
                    })
        
        for download_info in cloud_downloads:
            proc = download_info['process']
            provider = download_info['provider']
            cmdline = proc.get('cmdline', '')
            
            has_execution = any(p.search(cmdline) for p in execution_indicators)
            
            if has_execution:
                evidence = self._create_evidence(
                    title=f"Download and Execute from Cloud Storage: {provider['name']}",
                    description=f"File downloaded from {provider['name']} and executed. "
                               f"Command: {cmdline[:200]}",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    attack_id=self.ATTACK_ID,
                    attack_tactic=self.ATTACK_TACTIC,
                    source_path=proc.get('exe', ''),
                    raw_data={
                        'pid': proc.get('pid'),
                        'cmdline': cmdline,
                        'user': proc.get('user', ''),
                        'cloud_provider': provider['name'],
                        'execution_method': 'download_execute',
                        'execution_delay_seconds': 0,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    },
                    remediation="Review downloaded files and scan for malware. "
                               "Implement application whitelisting to prevent unauthorized execution.",
                    evidence_details=EvidenceDetail(
                        pid=proc.get('pid', 0),
                        cmdline=proc.get('cmdline', '')[:300],
                        executable=proc.get('exe', ''),
                        file_path=proc.get('file_path', proc.get('path', '')),
                        remote_address=proc.get('remote_address', proc.get('ip', '')),
                        connection_state=proc.get('state', ''),
                        user=proc.get('user', proc.get('username', ''))
                    ),
                    remediation_commands=[
                        "Investigate user activity and lock account if compromised",
                        "Review user authentication logs",
                        "Check for unauthorized access from this user",
                        "Audit user permissions and group memberships"
                    ]
                )
                evidences.append(evidence)
        
        return evidences
    
    def _check_cloud_api_usage(self, processes: List) -> List[Evidence]:
        """Detect suspicious cloud API usage patterns (MEDIUM severity)"""
        evidences = []
        
        sdk_patterns = [
            (re.compile(r'import\s+boto3'), 'AWS SDK (boto3)'),
            (re.compile(r'from\s+google\.cloud\s+import\s+storage'), 'Google Cloud Storage SDK'),
            (re.compile(r'from\s+azure\.storage\.blob'), 'Azure Blob Storage SDK'),
            (re.compile(r'import\s+dropbox'), 'Dropbox SDK'),
            (re.compile(r'import\s+oss2'), 'Alibaba Cloud OSS SDK'),
            (re.compile(r'from\s+qcloud_cos'), 'Tencent Cloud COS SDK'),
        ]
        
        suspicious_api_calls = [
            re.compile(r'(?:boto3|client)\.download|\.get_object|\.read'),
            re.compile(r'subprocess\.(?:call|run|Popen).*(?:downloaded|tmp)'),
            re.compile(r'os\.system|exec.*(?:/tmp|/var/tmp)'),
        ]
        
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            if not cmdline:
                continue
            
            sdk_detected = []
            for pattern, sdk_name in sdk_patterns:
                if pattern.search(cmdline):
                    sdk_detected.append(sdk_name)
            
            if sdk_detected:
                has_suspicious_call = any(p.search(cmdline) for p in suspicious_api_calls)
                
                if has_suspicious_call:
                    evidence = self._create_evidence(
                        title=f"Suspicious Cloud API Usage: {', '.join(sdk_detected)}",
                        description=f"Process using cloud SDK with suspicious execution pattern. "
                                   f"SDKs: {', '.join(sdk_detected)}. Command: {cmdline[:200]}",
                        severity=Severity.MEDIUM,
                        confidence=0.70,
                        attack_id=self.ATTACK_ID,
                        attack_tactic=self.ATTACK_TACTIC,
                        source_path=proc.get('exe', ''),
                        raw_data={
                            'pid': proc.get('pid'),
                            'cmdline': cmdline,
                            'user': proc.get('user', ''),
                            'sdks_detected': sdk_detected,
                            'execution_method': 'api_based',
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        },
                        remediation="Review cloud API access patterns and implement least privilege. "
                                   "Monitor for unusual data transfer volumes.",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            user=proc.get('user', proc.get('username', ''))
                        ),
                        remediation_commands=[
                        "Investigate user activity and lock account if compromised",
                        "Review user authentication logs",
                        "Check for unauthorized access from this user",
                        "Audit user permissions and group memberships"
                    ]
                    )
                    evidences.append(evidence)
        
        return evidences
    
    def _detect_sync_folder_execution(self, processes: List) -> List[Evidence]:
        """Detect execution from cloud sync folders (MEDIUM severity)"""
        evidences = []
        
        sync_folder_patterns = [
            re.compile(r'/OneDrive/', re.IGNORECASE),
            re.compile(r'/Google\s*Drive/', re.IGNORECASE),
            re.compile(r'/Dropbox/', re.IGNORECASE),
            re.compile(r'/Box\s*Sync/', re.IGNORECASE),
            re.compile(r'/iCloud\s*Drive/', re.IGNORECASE),
            re.compile(r'/Nextcloud/', re.IGNORECASE),
            re.compile(r'/ownCloud/', re.IGNORECASE),
            re.compile(r'\.local/share/Insync/'),
        ]
        
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            exe_path = proc.get('exe', '')
            cwd = proc.get('cwd', '')
            
            check_paths = [cmdline, exe_path, cwd]
            
            for path in check_paths:
                if not path:
                    continue
                
                for pattern in sync_folder_patterns:
                    if pattern.search(path):
                        provider_match = self._identify_cloud_provider(path)
                        provider_name = provider_match['name'] if provider_match else 'Cloud Sync'
                        
                        evidence = self._create_evidence(
                            title=f"Execution from Cloud Sync Folder: {provider_name}",
                            description=f"Executable running from cloud sync folder. "
                                       f"Path: {path[:200]}",
                            severity=Severity.MEDIUM,
                            confidence=0.65,
                            attack_id=self.ATTACK_ID,
                            attack_tactic=self.ATTACK_TACTIC,
                            source_path=exe_path,
                            raw_data={
                                'pid': proc.get('pid'),
                                'cmdline': cmdline,
                                'exe': exe_path,
                                'cwd': cwd,
                                'user': proc.get('user', ''),
                                'cloud_provider': provider_name,
                                'execution_method': 'sync_folder',
                                'timestamp': datetime.now(timezone.utc).isoformat()
                            },
                            remediation="Verify this is legitimate software. Consider blocking "
                                       "execution from cloud sync folders via AppArmor/SELinux.",
                            evidence_details=EvidenceDetail(
                                pid=proc.get('pid', 0),
                                cmdline=proc.get('cmdline', '')[:300],
                                executable=proc.get('exe', ''),
                                file_path=proc.get('file_path', proc.get('path', '')),
                                remote_address=proc.get('remote_address', proc.get('ip', '')),
                                connection_state=proc.get('state', ''),
                                user=proc.get('user', proc.get('username', ''))
                            ),
                            remediation_commands=[
                        "Investigate user activity and lock account if compromised",
                        "Review user authentication logs",
                        "Check for unauthorized access from this user",
                        "Audit user permissions and group memberships"
                    ]
                        )
                        evidences.append(evidence)
                        break
        
        return evidences
