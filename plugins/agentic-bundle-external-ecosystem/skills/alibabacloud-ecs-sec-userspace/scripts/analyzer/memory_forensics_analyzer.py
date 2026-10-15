"""AI Agent Memory Forensics and Artifact Recovery Analyzer

Advanced memory forensics for AI agent systems including:
- Process memory dump analysis
- In-memory artifact extraction and recovery
- Volatile evidence collection
- Memory-resident malware detection
- Runtime model integrity verification
- Agent conversation state forensics
- Vector embedding integrity checking

ATT&CK mapping:
- T1005 - Data from Local System
- T1003 - OS Credential Dumping
- T1055 - Process Injection
- T1055.001 - Dynamic-link Library Injection
- T1055.012 - Process Hollowing
- T1610 - Deploy Container/AI Agent
- T1565.001 - Modify Data: Stored Data
- T1499 - Endpoint Denial of Service

OWASP ASI 2026: ASI01, ASI02, ASI03
"""
import os
import re
import time
import json
import hashlib
from typing import List, Dict

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

# Memory forensics detection heuristics (12+ required)
MEMORY_FORENSICS_HEURISTICS = {
    # 1. Memory-Resident Payload Detection
    'memory_resident_payload': {
        'patterns': [
            (re.compile(r'\b(shellcode|payload|stub)\s*(?:in|into)\s*memory', re.IGNORECASE),
             'Shellcode injection into memory', Severity.CRITICAL),
            (re.compile(r'\b(virtual|virtualalloc|malloc|heap).*(?:allocate|write)', re.IGNORECASE),
             'Suspicious memory allocation', Severity.HIGH),
            (re.compile(r'\bexecute\s+in\s+(?:process|memory|thread)', re.IGNORECASE),
             'In-memory code execution', Severity.CRITICAL),
        ],
        'description': 'Detect memory-resident malicious payloads',
        'category': 'process_memory'
    },
    
    # 2. Injected Code Segment Detection
    'injected_code_segment': {
        'patterns': [
            (re.compile(r'\b(inject|load)\s*(?:dll|library|module)\s+into', re.IGNORECASE),
             'DLL/module injection attempt', Severity.CRITICAL),
            (re.compile(r'\b(code|shellcode|payload)\s+injection', re.IGNORECASE),
             'Code injection attempt', Severity.CRITICAL),
            (re.compile(r'\bhollow\s*(?:process|image)', re.IGNORECASE),
             'Process hollowing attempt', Severity.HIGH),
        ],
        'description': 'Detect injected code segments in processes',
        'category': 'process_memory'
    },
    
    # 3. Credential Pattern Matching
    'credential_extraction': {
        'patterns': [
            (re.compile(r'(?:api[_-]?key|apikey|token|secret|credential).*(?:extract|scrape|dump)', re.IGNORECASE),
             'Credential extraction from memory', Severity.CRITICAL),
            (re.compile(r'(?:password|passwd|pwd).*(?:memory|process|scrape)', re.IGNORECASE),
             'Password scraping from memory', Severity.HIGH),
            (re.compile(r'(?:(?:aws|azure|gcp)[_-]?(?:key|secret|cred)).*(?:find|locate)', re.IGNORECASE),
             'Cloud credential hunting', Severity.CRITICAL),
        ],
        'description': 'Extract credentials from process memory',
        'category': 'artifact_recovery'
    },
    
    # 4. Prompt Injection Recovery
    'prompt_injection_recovery': {
        'patterns': [
            (re.compile(r'(?:prompt|instruction|system).*(?:inject|override|bypass)', re.IGNORECASE),
             'Prompt injection payload', Severity.CRITICAL),
            (re.compile(r'(?:ignore|forget|disregard).*(?:previous|all|prior).*(?:instruction|rule)', re.IGNORECASE),
             'Instruction override injection', Severity.HIGH),
            (re.compile(r'###\s*(?:SYSTEM|INSTRUCTION|PROMPT):', re.IGNORECASE),
             'System prompt spoofing', Severity.HIGH),
        ],
        'description': 'Recover prompt injection payloads from memory',
        'category': 'artifact_recovery'
    },
    
    # 5. Model Weight Anomaly Detection
    'model_weight_anomaly': {
        'patterns': [
            (re.compile(r'(?:modify|change|alter|tamper).*(?:model|weight|parameter)', re.IGNORECASE),
             'Model weight tampering', Severity.CRITICAL),
            (re.compile(r'(?:patch|hook|modify).*(?:inference|forward|backward)', re.IGNORECASE),
             'Model inference patching', Severity.HIGH),
            (re.compile(r'(?:adversarial|perturbation|attack).*(?:input|tensor)', re.IGNORECASE),
             'Adversarial perturbation attack', Severity.HIGH),
        ],
        'description': 'Detect model weight anomalies',
        'category': 'model_integrity'
    },
    
    # 6. GPU Memory Monitoring
    'gpu_memory_monitoring': {
        'patterns': [
            (re.compile(r'\b(gpu|cuda|vram).*(?:overflow|corrupt|anomal)', re.IGNORECASE),
             'GPU memory anomaly', Severity.HIGH),
            (re.compile(r'(?:gpu|tensor).*(?:unauthorized|malicious|suspicious)', re.IGNORECASE),
             'Suspicious GPU operation', Severity.HIGH),
            (re.compile(r'(?:cuda|gpu)_mem.*(?:inject|write)', re.IGNORECASE),
             'GPU memory injection', Severity.CRITICAL),
        ],
        'description': 'Monitor GPU memory for suspicious operations',
        'category': 'model_integrity'
    },
    
    # 7. Shared Memory Analysis
    'shared_memory_analysis': {
        'patterns': [
            (re.compile(r'(?:shm|shared[_-]?memory|/dev/shm).*(?:inject|write|malicious)', re.IGNORECASE),
             'Shared memory injection', Severity.HIGH),
            (re.compile(r'(?:inter[_-]?process|ipc).*(?:exploit|abuse|inject)', re.IGNORECASE),
             'IPC mechanism abuse', Severity.HIGH),
            (re.compile(r'mmap.*(?:anonymous|private).*(?:executable|writable)', re.IGNORECASE),
             'Suspicious mmap usage', Severity.MEDIUM),
        ],
        'description': 'Analyze shared memory segments',
        'category': 'process_memory'
    },
    
    # 8. Memory-Mapped File Verification
    'memory_mapped_file_verification': {
        'patterns': [
            (re.compile(r'mmap.*(?:exec|write).*(?:anonymous|hidden)', re.IGNORECASE),
             'Suspicious memory-mapped file', Severity.HIGH),
            (re.compile(r'(?:map|mapping).*(?:file|region).*(?:hidden|deleted)', re.IGNORECASE),
             'Hidden/deleted file mapping', Severity.HIGH),
            (re.compile(r'/proc/\d+/mem.*(?:write|inject)', re.IGNORECASE),
             'Direct /proc/mem access', Severity.CRITICAL),
        ],
        'description': 'Verify memory-mapped file integrity',
        'category': 'process_memory'
    },
    
    # 9. Process Hollowing Detection
    'process_hollowing_detection': {
        'patterns': [
            (re.compile(r'(?:hollow|replace).*(?:process|image|executable)', re.IGNORECASE),
             'Process hollowing attempt', Severity.CRITICAL),
            (re.compile(r'(?:suspend|resume).*(?:thread|process).*(?:inject)', re.IGNORECASE),
             'Thread suspension injection', Severity.HIGH),
            (re.compile(r'createprocess.*(?:suspended|create_suspended)', re.IGNORECASE),
             'Suspended process creation', Severity.HIGH),
        ],
        'description': 'Detect process hollowing techniques',
        'category': 'process_memory'
    },
    
    # 10. DLL Injection Detection
    'dll_injection_detection': {
        'patterns': [
            (re.compile(r'(?:loadlibrary|createremotethread).*(?:inject|dll)', re.IGNORECASE),
             'Classic DLL injection', Severity.CRITICAL),
            (re.compile(r'(?:appinit|registry).*(?:dll|library).*(?:load)', re.IGNORECASE),
             'AppInit DLLs injection', Severity.HIGH),
            (re.compile(r'(?:setwindowshook|getasynckeypress).*(?:dll|inject)', re.IGNORECASE),
             'SetWindowsHookEx injection', Severity.HIGH),
        ],
        'description': 'Detect DLL injection techniques',
        'category': 'process_memory'
    },
    
    # 11. Conversation State Integrity
    'conversation_state_integrity': {
        'patterns': [
            (re.compile(r'(?:modify|tamper|forge).*(?:conversation|chat|dialogue).*(?:state|history)', re.IGNORECASE),
             'Conversation state tampering', Severity.HIGH),
            (re.compile(r'(?:delete|remove|clear).*(?:message|turn|exchange)', re.IGNORECASE),
             'Conversation deletion', Severity.MEDIUM),
            (re.compile(r'(?:insert|add|plant).*(?:fake|false|malicious).*(?:message|response)', re.IGNORECASE),
             'Fake message insertion', Severity.HIGH),
        ],
        'description': 'Verify conversation state integrity',
        'category': 'agent_state'
    },
    
    # 12. Vector Embedding Anomaly Detection
    'vector_embedding_anomaly': {
        'patterns': [
            (re.compile(r'(?:poison|corrupt|manipulate).*(?:embedding|vector|index)', re.IGNORECASE),
             'Vector embedding poisoning', Severity.CRITICAL),
            (re.compile(r'(?:backdoor|trigger).*(?:embedding|vector)', re.IGNORECASE),
             'Embedding backdoor injection', Severity.CRITICAL),
            (re.compile(r'(?:similarity|distance).*(?:manipulate|bias)', re.IGNORECASE),
             'Similarity manipulation', Severity.HIGH),
        ],
        'description': 'Detect vector embedding anomalies',
        'category': 'vector_store'
    },
}

# Credential patterns for artifact recovery
CREDENTIAL_PATTERNS = {
    'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'aws_secret_key': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
    'github_token': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    'generic_api_key': re.compile(r'(?i)(?:api[_-]?key|apikey)["\'\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?'),
    'bearer_token': re.compile(r'[Bb]earer\s+[A-Za-z0-9_\-\.]+'),
    'basic_auth': re.compile(r'[Bb]asic\s+[A-Za-z0-9+/]+=*'),
    'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    'password_field': re.compile(r'(?i)(?:password|passwd|pwd)["\'\s:=]+["\']?([^"\'\s]{8,})["\']?'),
    'slack_token': re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}[a-zA-Z0-9-]*'),
}

# Memory region patterns for /proc/[pid]/maps analysis
SUSPICIOUS_MEMORY_REGIONS = {
    'executable_heap': re.compile(r'rw-p\s+.*\[heap\]', re.IGNORECASE),
    'executable_stack': re.compile(r'rwxs?\s+.*\[stack\]', re.IGNORECASE),
    'anonymous_executable': re.compile(r'rw?p?\s+0+[\s\S]{0,50}anon', re.IGNORECASE),
    'deleted_library': re.compile(r'deleted', re.IGNORECASE),
    'suspicious_mapping': re.compile(r'/tmp/|/dev/shm/|/run/', re.IGNORECASE),
}

# ATT&CK mapping
ATTACK_MAPPING = {
    'memory_resident_payload': 'T1055',
    'injected_code_segment': 'T1055.001',
    'credential_extraction': 'T1003',
    'prompt_injection_recovery': 'T1610',
    'model_weight_anomaly': 'T1565.001',
    'gpu_memory_monitoring': 'T1499',
    'shared_memory_analysis': 'T1055',
    'memory_mapped_file_verification': 'T1055.012',
    'process_hollowing_detection': 'T1055.012',
    'dll_injection_detection': 'T1055.001',
    'conversation_state_integrity': 'T1565.001',
    'vector_embedding_anomaly': 'T1565.001',
}

# OWASP ASI mapping
OWASP_ASI_MAPPING = {
    'process_memory': 'ASI01:2026',
    'artifact_recovery': 'ASI02:2026',
    'model_integrity': 'ASI03:2026',
    'agent_state': 'ASI03:2026',
    'vector_store': 'ASI01:2026',
}

class MemoryForensicsAnalyzer(BaseAnalyzer):
    """AI Agent Memory Forensics and Artifact Recovery Analyzer
    
    Advanced memory forensics capabilities for AI agent systems:
    
    Detection capabilities (12+ heuristics):
    1. Memory-resident payload detection
    2. Injected code segment detection
    3. Credential pattern matching
    4. Prompt injection recovery
    5. Model weight anomaly detection
    6. GPU memory monitoring
    7. Shared memory analysis
    8. Memory-mapped file verification
    9. Process hollowing detection
    10. DLL injection detection
    11. Conversation state integrity
    12. Vector embedding anomaly detection
    
    ATT&CK Mapping: T1005, T1003, T1055, T1055.001, T1055.012, T1610, T1565.001, T1499
    OWASP ASI 2026: ASI01, ASI02, ASI03
    """
    
    name = "memory_forensics_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 120)

    required_collectors = ["process", "filesystem", "log"]
    
    # Sec-inspect self-protection whitelist - exclude scanner's own processes
    SEC_INSPECT_PATTERNS = [
        re.compile(r'python.*-m\s+scripts\.main', re.IGNORECASE),
        re.compile(r'sec-userspace', re.IGNORECASE),
        re.compile(r'/sec-userspace/', re.IGNORECASE),
        re.compile(r'sec_inspect', re.IGNORECASE),
        re.compile(r'/sec-userspace/workspace', re.IGNORECASE),
    ]
    
    def __init__(self, workspace_dir: str = None):
        super().__init__(workspace_dir)
        self._compiled_patterns = {}
        self._compile_all_patterns()
        self._recovered_artifacts = []
    
    def _compile_all_patterns(self):
        """Pre-compile all regex patterns for performance"""
        for heuristic_name, heuristic_data in MEMORY_FORENSICS_HEURISTICS.items():
            self._compiled_patterns[heuristic_name] = []
            for pattern, description, severity in heuristic_data.get('patterns', []):
                self._compiled_patterns[heuristic_name].append({
                    'pattern': pattern,
                    'description': description,
                    'severity': severity
                })
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        if not self.proc_available():
            return True, "No /proc filesystem available"
        return False, ""

    def _get_safe_data(self, collected_data: Dict, key: str) -> Dict:
        """Safely get data from collected_data"""
        try:
            return self._get_data(collected_data, key)
        except (KeyError, TypeError):
            return {}
    
    def _analyze_process_memory_maps(self, process_data: Dict) -> List[Evidence]:
        """Analyze /proc/[pid]/maps for suspicious memory regions"""
        evidences = []
        processes = process_data.get("processes", [])
        
        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            
            # Skip sec-userspace self processes to avoid false positives
            if self._is_sec_inspect_process(proc, processes):
                _get_logger().debug(f"[{self.name}] Skipping sec-userspace self process: PID={pid}")
                continue
            
            if not self._is_ai_agent_process(cmdline):
                continue
            
            # Check for suspicious memory region patterns
            for region_type, pattern in SUSPICIOUS_MEMORY_REGIONS.items():
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title=f"Memory Forensics: Suspicious Memory Region ({region_type.replace('_', ' ').title()})",
                        description=f"Process PID {pid} shows suspicious memory region pattern: {region_type}",
                        severity=Severity.HIGH,
                        confidence=0.65,
                        attack_id="T1055",
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/maps",
                        raw_data={
                            "pid": pid,
                            "region_type": region_type,
                            "cmdline_sample": cmdline[:200],
                        },
                        remediation=(
                            "Investigate process memory layout. "
                            "Check for injected code or anomalous mappings. "
                            "Consider memory dump analysis."
                        ),
                        owasp_asi="ASI01:2026",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    ))
        
        return evidences
    
    def _scan_memory_resident_payloads(self, process_data: Dict) -> List[Evidence]:
        """Scan processes for memory-resident payload indicators"""
        evidences = []
        processes = process_data.get("processes", [])
        
        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            exe = proc.get("exe", "")
            
            # Skip sec-userspace self processes to avoid false positives
            if self._is_sec_inspect_process(proc, processes):
                _get_logger().debug(f"[{self.name}] Skipping sec-userspace self process: PID={pid}")
                continue
            
            if not self._is_ai_agent_process(exe, cmdline):
                continue
            
            # Check against memory resident payload patterns
            payload_patterns = self._compiled_patterns.get('memory_resident_payload', [])
            for pattern_info in payload_patterns:
                pattern = pattern_info['pattern']
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title="Memory Forensics: Memory-Resident Payload Detected",
                        description=f"Process PID {pid}: {pattern_info['description']}",
                        severity=pattern_info['severity'],
                        confidence=0.75,
                        attack_id="T1055",
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={
                            "pid": pid,
                            "executable": exe,
                            "payload_indicator": pattern_info['description'],
                        },
                        remediation=(
                            "Perform full memory dump analysis. "
                            "Isolate affected process. "
                            "Investigate injection vector."
                        ),
                        owasp_asi="ASI01:2026",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    ))
                    break
        
        return evidences
    
    def _detect_injected_code_segments(self, process_data: Dict) -> List[Evidence]:
        """Detect injected code segments in AI agent processes"""
        evidences = []
        processes = process_data.get("processes", [])
        
        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            
            # Skip sec-userspace self processes to avoid false positives
            if self._is_sec_inspect_process(proc, processes):
                _get_logger().debug(f"[{self.name}] Skipping sec-userspace self process: PID={pid}")
                continue
            
            if not self._is_ai_agent_process(proc.get("exe", ""), cmdline):
                continue
            
            # Check for injected code patterns
            code_patterns = self._compiled_patterns.get('injected_code_segment', [])
            for pattern_info in code_patterns:
                pattern = pattern_info['pattern']
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title="Memory Forensics: Injected Code Segment Detected",
                        description=f"Process PID {pid}: {pattern_info['description']}",
                        severity=pattern_info['severity'],
                        confidence=0.80,
                        attack_id="T1055.001",
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={
                            "pid": pid,
                            "injection_type": pattern_info['description'],
                        },
                        remediation=(
                            "Terminate suspicious process. "
                            "Analyze memory for injected code. "
                            "Identify and remove injection source."
                        ),
                        owasp_asi="ASI01:2026",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    ))
                    break
        
        return evidences
    
    def _extract_credentials_from_artifacts(self, filesystem_data: Dict) -> List[Evidence]:
        """Extract credentials from memory artifacts and files"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Focus on memory-related files
        memory_file_patterns = ['.mem', '.dmp', '.dump', 'memory', 'core']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            is_memory_file = any(p in filename for p in memory_file_patterns)
            if not is_memory_file:
                continue
            
            file_size = file_info.get("size", 0)
            # Skip large files, only scan small artifacts
            if file_size > 1 * 1024 * 1024:
                continue
            
            try:
                # Read file content with limit
                read_limit = 10 * 1024 * 1024
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(read_limit)
                
                # Search for credential patterns
                for cred_type, pattern in CREDENTIAL_PATTERNS.items():
                    matches = pattern.findall(content)
                    if matches:
                        evidences.append(self._create_evidence(
                            title=f"Memory Forensics: Credential Artifact Recovered ({cred_type.replace('_', ' ').title()})",
                            description=f"Found {len(matches)} credential(s) of type {cred_type} in {filepath}",
                            severity=Severity.CRITICAL,
                            confidence=0.85,
                            attack_id="T1003",
                            attack_tactic="Credential Access",
                            source_path=filepath,
                            raw_data={
                                "credential_type": cred_type,
                                "match_count": len(matches),
                                "sample_hash": hashlib.sha256(str(matches[0]).encode()).hexdigest()[:16],
                            },
                            remediation=(
                                "Rotate exposed credentials immediately. "
                                "Implement credential scanning. "
                                "Review memory handling practices."
                            ),
                            owasp_asi="ASI02:2026",
                            evidence_details=EvidenceDetail(
                                file_path=file_info.get('file_path', file_info.get('path', '')),
                                remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                                connection_state=file_info.get('state', ''),
                                credential_type=cred_type
                            ),
                            remediation_commands=[
                        "Rotate compromised credential immediately",
                        "Review access logs for unauthorized usage",
                        "Audit credential storage and usage patterns",
                        "Check other systems for credential reuse"
                    ]
                        ))
                        
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to read {filepath}: {e}")
        
        return evidences
    
    def _recover_prompt_injection_payloads(self, log_data: Dict) -> List[Evidence]:
        """Recover prompt injection payloads from logs"""
        evidences = []
        
        logs = log_data.get("application", []) + log_data.get("logs", [])
        
        for log_entry in logs:
            content = log_entry.get("message", "") or log_entry.get("content", "")
            timestamp = log_entry.get("timestamp", "")
            
            if not content:
                continue
            
            # Check for prompt injection patterns
            injection_patterns = self._compiled_patterns.get('prompt_injection_recovery', [])
            for pattern_info in injection_patterns:
                pattern = pattern_info['pattern']
                if pattern.search(content):
                    evidences.append(self._create_evidence(
                        title="Memory Forensics: Prompt Injection Payload Recovered",
                        description=f"Log at {timestamp}: {pattern_info['description']}",
                        severity=pattern_info['severity'],
                        confidence=0.80,
                        attack_id="T1610",
                        attack_tactic="Execution",
                        source_path="application_log",
                        raw_data={
                            "timestamp": timestamp,
                            "injection_type": pattern_info['description'],
                            "log_sample": content[:200],
                        },
                        remediation=(
                            "Review prompt injection payload. "
                            "Update input validation rules. "
                            "Implement prompt sanitization."
                        ),
                        owasp_asi="ASI02:2026",
                        evidence_details=EvidenceDetail(
                            pid=log_entry.get('pid', 0),
                            cmdline=log_entry.get('cmdline', '')[:300],
                            executable=log_entry.get('exe', ''),
                            file_path=log_entry.get('file_path', log_entry.get('path', '')),
                            remote_address=log_entry.get('remote_address', log_entry.get('ip', '')),
                            connection_state=log_entry.get('state', ''),
                            content=log_entry.get('agent_id', log_entry.get('server_name', ''))
                        ),
                        remediation_commands=[
                        "Review agent configuration and tool permissions",
                        "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity",
                        "Restrict agent tool access to minimum required"
                    ]
                    ))
                    break
        
        return evidences
    
    def _verify_model_memory_integrity(self, filesystem_data: Dict) -> List[Evidence]:
        """Verify loaded model weights haven't been tampered"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Model file patterns
        model_patterns = ['.pt', '.pth', '.bin', '.safetensors', '.onnx', '.h5', '.pb']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            is_model_file = any(filename.endswith(p) for p in model_patterns)
            if not is_model_file:
                continue
            
            # Check for suspicious modifications
            mtime = file_info.get("mtime", 0)
            current_time = time.time()
            age_hours = (current_time - mtime) / 3600
            
            # Recently modified model files (within last hour)
            if age_hours < 1:
                # Check for tampering indicators in logs
                evidences.append(self._create_evidence(
                    title="Memory Forensics: Model File Recently Modified",
                    description=f"Model file {filepath} was modified {age_hours:.1f} hours ago",
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    attack_id="T1565.001",
                    attack_tactic="Data Manipulation",
                    source_path=filepath,
                    raw_data={
                        "filepath": filepath,
                        "age_hours": age_hours,
                        "modification_time": mtime,
                    },
                    remediation=(
                        "Verify model integrity with checksums. "
                        "Compare with known-good model versions. "
                        "Implement model signing."
                    ),
                    owasp_asi="ASI03:2026",
                    evidence_details=EvidenceDetail(
                        file_path=file_info.get('file_path', file_info.get('path', '')),
                        remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                        connection_state=file_info.get('state', ''),
                        content=filepath
                    ),
                    remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                ))
        
        return evidences
    
    def _monitor_gpu_memory(self, filesystem_data: Dict) -> List[Evidence]:
        """Monitor GPU memory for suspicious operations"""
        evidences = []
        
        # Check for nvidia-smi output or GPU stats
        files = filesystem_data.get("files", [])
        
        gpu_patterns = ['nvidia', 'gpu', 'cuda', 'vram']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if not any(p in filename for p in gpu_patterns):
                continue
            
            try:
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(100 * 1024)
                
                # Check for GPU anomaly patterns
                gpu_patterns_compiled = self._compiled_patterns.get('gpu_memory_monitoring', [])
                for pattern_info in gpu_patterns_compiled:
                    pattern = pattern_info['pattern']
                    if pattern.search(content):
                        evidences.append(self._create_evidence(
                            title="Memory Forensics: GPU Memory Anomaly Detected",
                            description=f"GPU stats file {filepath}: {pattern_info['description']}",
                            severity=pattern_info['severity'],
                            confidence=0.70,
                            attack_id="T1499",
                            attack_tactic="Impact",
                            source_path=filepath,
                            raw_data={
                                "filepath": filepath,
                                "anomaly_type": pattern_info['description'],
                            },
                            remediation=(
                                "Monitor GPU memory usage patterns. "
                                "Check for unauthorized GPU operations. "
                                "Implement GPU resource limits."
                            ),
                            owasp_asi="ASI03:2026",
                            evidence_details=EvidenceDetail(
                                file_path=file_info.get('file_path', file_info.get('path', '')),
                                remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                                connection_state=file_info.get('state', '')
                            ),
                            remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                        ))
                        break
                        
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to read GPU file {filepath}: {e}")
        
        return evidences
    
    def _analyze_shared_memory(self, filesystem_data: Dict) -> List[Evidence]:
        """Analyze shared memory segments for malicious content"""
        evidences = []
        
        # Check /dev/shm directory
        shm_files = filesystem_data.get("files", [])
        
        for file_info in shm_files:
            filepath = file_info.get("path", "")
            
            if '/dev/shm' not in filepath and '/run/shm' not in filepath:
                continue
            
            # Check for suspicious shared memory patterns
            shm_patterns = self._compiled_patterns.get('shared_memory_analysis', [])
            for pattern_info in shm_patterns:
                pattern = pattern_info['pattern']
                
                # Check filepath for patterns
                if pattern.search(filepath):
                    evidences.append(self._create_evidence(
                        title="Memory Forensics: Suspicious Shared Memory Segment",
                        description=f"Shared memory segment {filepath}: {pattern_info['description']}",
                        severity=pattern_info['severity'],
                        confidence=0.65,
                        attack_id="T1055",
                        attack_tactic="Defense Evasion",
                        source_path=filepath,
                        raw_data={
                            "filepath": filepath,
                            "suspicious_indicator": pattern_info['description'],
                        },
                        remediation=(
                            "Investigate shared memory contents. "
                            "Remove malicious segments. "
                            "Implement shared memory monitoring."
                        ),
                        owasp_asi="ASI01:2026",
                        evidence_details=EvidenceDetail(
                            file_path=file_info.get('file_path', file_info.get('path', '')),
                            remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                            connection_state=file_info.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    ))
                    break
        
        return evidences
    
    def _verify_memory_mapped_files(self, process_data: Dict) -> List[Evidence]:
        """Verify memory-mapped file integrity"""
        evidences = []
        processes = process_data.get("processes", [])
        
        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            
            # Skip sec-userspace self processes to avoid false positives
            if self._is_sec_inspect_process(proc, processes):
                _get_logger().debug(f"[{self.name}] Skipping sec-userspace self process: PID={pid}")
                continue
            
            if not self._is_ai_agent_process(proc.get("exe", ""), cmdline):
                continue
            
            # Check for mmap-related suspicious patterns
            mmap_patterns = self._compiled_patterns.get('memory_mapped_file_verification', [])
            for pattern_info in mmap_patterns:
                pattern = pattern_info['pattern']
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title="Memory Forensics: Suspicious Memory-Mapped File",
                        description=f"Process PID {pid}: {pattern_info['description']}",
                        severity=pattern_info['severity'],
                        confidence=0.70,
                        attack_id="T1055.012",
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/maps",
                        raw_data={
                            "pid": pid,
                            "mmap_indicator": pattern_info['description'],
                        },
                        remediation=(
                            "Analyze memory-mapped files. "
                            "Verify file integrity. "
                            "Check for deleted or hidden mappings."
                        ),
                        owasp_asi="ASI01:2026",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    ))
                    break
        
        return evidences
    
    def _detect_process_hollowing(self, process_data: Dict) -> List[Evidence]:
        """Detect process hollowing techniques"""
        evidences = []
        processes = process_data.get("processes", [])
        
        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            
            # Skip sec-userspace self processes to avoid false positives
            if self._is_sec_inspect_process(proc, processes):
                _get_logger().debug(f"[{self.name}] Skipping sec-userspace self process: PID={pid}")
                continue
            
            if not self._is_ai_agent_process(proc.get("exe", ""), cmdline):
                continue
            
            # Check for process hollowing patterns
            hollow_patterns = self._compiled_patterns.get('process_hollowing_detection', [])
            for pattern_info in hollow_patterns:
                pattern = pattern_info['pattern']
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title="Memory Forensics: Process Hollowing Attempt Detected",
                        description=f"Process PID {pid}: {pattern_info['description']}",
                        severity=pattern_info['severity'],
                        confidence=0.75,
                        attack_id="T1055.012",
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={
                            "pid": pid,
                            "hollowing_technique": pattern_info['description'],
                        },
                        remediation=(
                            "Terminate hollowed process. "
                            "Identify original executable. "
                            "Investigate hollowing vector."
                        ),
                        owasp_asi="ASI01:2026",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    ))
                    break
        
        return evidences
    
    def _detect_dll_injection(self, process_data: Dict) -> List[Evidence]:
        """Detect DLL injection techniques"""
        evidences = []
        processes = process_data.get("processes", [])
        
        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            
            # Skip sec-userspace self processes to avoid false positives
            if self._is_sec_inspect_process(proc, processes):
                _get_logger().debug(f"[{self.name}] Skipping sec-userspace self process: PID={pid}")
                continue
            
            if not self._is_ai_agent_process(proc.get("exe", ""), cmdline):
                continue
            
            # Check for DLL injection patterns
            dll_patterns = self._compiled_patterns.get('dll_injection_detection', [])
            for pattern_info in dll_patterns:
                pattern = pattern_info['pattern']
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title="Memory Forensics: DLL Injection Detected",
                        description=f"Process PID {pid}: {pattern_info['description']}",
                        severity=pattern_info['severity'],
                        confidence=0.80,
                        attack_id="T1055.001",
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={
                            "pid": pid,
                            "injection_technique": pattern_info['description'],
                        },
                        remediation=(
                            "Identify injected DLL. "
                            "Remove malicious library. "
                            "Patch injection vulnerability."
                        ),
                        owasp_asi="ASI01:2026",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    ))
                    break
        
        return evidences
    
    def _verify_conversation_state_integrity(self, filesystem_data: Dict) -> List[Evidence]:
        """Verify agent conversation state hasn't been tampered"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Conversation state file patterns
        state_patterns = ['conversation', 'chat_history', 'session_state', 'dialogue', 'agent_state']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            is_state_file = any(p in filename for p in state_patterns)
            if not is_state_file:
                continue
            
            file_size = file_info.get("size", 0)
            if file_size > 10 * 1024 * 1024:
                continue
            
            try:
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(5 * 1024 * 1024)
                
                # Check for state tampering patterns
                state_patterns_compiled = self._compiled_patterns.get('conversation_state_integrity', [])
                for pattern_info in state_patterns_compiled:
                    pattern = pattern_info['pattern']
                    if pattern.search(content):
                        evidences.append(self._create_evidence(
                            title="Memory Forensics: Conversation State Tampering Detected",
                            description=f"State file {filepath}: {pattern_info['description']}",
                            severity=pattern_info['severity'],
                            confidence=0.75,
                            attack_id="T1565.001",
                            attack_tactic="Data Manipulation",
                            source_path=filepath,
                            raw_data={
                                "filepath": filepath,
                                "tampering_type": pattern_info['description'],
                            },
                            remediation=(
                                "Restore conversation state from backup. "
                                "Implement state integrity verification. "
                                "Add state change auditing."
                            ),
                            owasp_asi="ASI03:2026",
                            evidence_details=EvidenceDetail(
                                file_path=file_info.get('file_path', file_info.get('path', '')),
                                remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                                connection_state=file_info.get('state', '')
                            ),
                            remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                        ))
                        break
                        
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to read state file {filepath}: {e}")
        
        return evidences
    
    def _detect_vector_embedding_anomalies(self, filesystem_data: Dict) -> List[Evidence]:
        """Detect vector embedding anomalies and poisoning"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Vector store file patterns
        vector_patterns = ['.chroma', '.milvus', 'faiss', '.vec', 'embeddings', 'vectors', 'pinecone', 'weaviate']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            filepath_lower = filepath.lower()
            
            is_vector_file = any(p in filename for p in vector_patterns) or \
                            any(p in filepath_lower for p in vector_patterns)
            if not is_vector_file:
                continue
            
            file_size = file_info.get("size", 0)
            if file_size > 50 * 1024 * 1024:
                continue
            
            try:
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(5 * 1024 * 1024)
                
                # Check for vector anomaly patterns
                vector_patterns_compiled = self._compiled_patterns.get('vector_embedding_anomaly', [])
                for pattern_info in vector_patterns_compiled:
                    pattern = pattern_info['pattern']
                    if pattern.search(content):
                        evidences.append(self._create_evidence(
                            title="Memory Forensics: Vector Embedding Anomaly Detected",
                            description=f"Vector file {filepath}: {pattern_info['description']}",
                            severity=pattern_info['severity'],
                            confidence=0.80,
                            attack_id="T1565.001",
                            attack_tactic="Data Manipulation",
                            source_path=filepath,
                            raw_data={
                                "filepath": filepath,
                                "anomaly_type": pattern_info['description'],
                            },
                            remediation=(
                                "Verify vector embedding integrity. "
                                "Rebuild vector index from trusted source. "
                                "Implement embedding validation."
                            ),
                            owasp_asi="ASI01:2026",
                            evidence_details=EvidenceDetail(
                                file_path=file_info.get('file_path', file_info.get('path', '')),
                                remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                                connection_state=file_info.get('state', '')
                            ),
                            remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                        ))
                        break
                        
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to read vector file {filepath}: {e}")
        
        return evidences
    
    def _is_ai_agent_process(self, exe: str, cmdline: str = "") -> bool:
        """Check if process is an AI agent"""
        ai_agent_patterns = [
            'claude', 'cursor', 'windsurf', 'copilot', 'qoder',
            'continue', 'codeium', 'tabnine', 'aider',
            r'python.*agent', r'node.*assistant', r'ai.*assistant',
            r'\bagent\.py\b', r'-agent\.py', r'assistant\.py',
        ]
        
        combined = f"{exe} {cmdline}".lower()
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in ai_agent_patterns)

    def _is_sec_inspect_process(self, proc: dict, all_processes: list = None) -> bool:
        """Check if process is sec-userspace itself to avoid self-detection false positives
        
        Detection strategies:
        1. Match process cmdline/comm against sec-userspace patterns
        2. Match process working directory (cwd) against sec-userspace workspace
        3. Trace parent process chain to detect sec-userspace spawned processes
        """
        cmdline = proc.get("cmdline", "") or ""
        comm = proc.get("comm", "") or ""
        cwd = proc.get("cwd", "") or ""
        
        for pattern in self.SEC_INSPECT_PATTERNS:
            if pattern.search(cmdline) or pattern.search(comm):
                return True
        
        if cwd and any(pattern.search(cwd) for pattern in self.SEC_INSPECT_PATTERNS):
            return True
        
        if all_processes:
            ppid = proc.get("ppid", 0)
            if ppid and ppid > 0:
                for parent_proc in all_processes:
                    if parent_proc.get("pid") == ppid:
                        if self._is_sec_inspect_process(parent_proc, all_processes):
                            return True
                        break
        
        return False

    # =========================================================================
    # AI Agent Memory Storage Backend Detection (New Capabilities)
    # =========================================================================

    # Memory storage file patterns for different backends
    MEMORY_BACKEND_PATTERNS = {
        'sqlite': {
            'extensions': ['.db', '.sqlite', '.sqlite3'],
            'names': ['agent_memory', 'memory', 'chat_history', 'conversation', 
                      'session_store', 'langchain', 'llama_index']
        },
        'redis': {
            'config_files': ['redis.conf', '.redis.conf'],
            'patterns': ['redis://', 'rediss://', ':6379']
        },
        'json': {
            'extensions': ['.json'],
            'names': ['agent_memory', 'memory', 'chat_history', 'conversation_history',
                      'memory_cache', 'session_data', 'memory_store']
        },
        'pickle': {
            'extensions': ['.pkl', '.pickle', '.dill'],
            'names': ['agent_memory', 'memory', 'session_state']
        },
        'chromadb': {
            'directories': ['chroma', 'chromadb', '.chroma'],
            'files': ['chroma.sqlite3', 'chroma.lock']
        },
        'faiss': {
            'extensions': ['.faiss', '.index', '.npy'],
            'names': ['faiss_index', 'vector_index', 'embedding_index']
        },
        'pinecone': {
            'config_patterns': ['pinecone_api_key', 'pinecone_environment']
        },
        'milvus': {
            'config_files': ['milvus.yaml', 'milvus.yml'],
            'patterns': ['milvus://', ':19530']
        }
    }

    # Enhanced memory poisoning detection patterns (10+ attack scenarios)
    MEMORY_POISONING_ATTACKS = {
        # 1. Instruction Override Attacks
        'instruction_override': {
            'patterns': [
                (re.compile(r'ignore\s+(?:previous|all|prior)\s+(?:instructions?|rules?|guidelines)', re.IGNORECASE),
                 "Instruction override attempt", Severity.CRITICAL),
                (re.compile(r'disregard\s+(?:everything|all|prior)', re.IGNORECASE),
                 "Content disregard attempt", Severity.HIGH),
            ],
            'description': 'Attempts to override system instructions',
            'attack_id': 'T1610',
            'owasp_asi': 'ASI03:2026'
        },
        
        # 2. Persistent Jailbreak
        'persistent_jailbreak': {
            'patterns': [
                (re.compile(r'(?:remember|always|never)\s+(?:do|say|respond|act)', re.IGNORECASE),
                 "Persistent behavior modification", Severity.HIGH),
                (re.compile(r'from\s+now\s+on.*(?:always|never)', re.IGNORECASE),
                 "Persistent instruction injection", Severity.HIGH),
            ],
            'description': 'Jailbreak attempts stored in memory',
            'attack_id': 'T1610',
            'owasp_asi': 'ASI07:2026'
        },
        
        # 3. Identity Hijacking
        'identity_hijack': {
            'patterns': [
                (re.compile(r'you\s+are\s+now|from\s+now\s+on\s+you\s+will\s+act\s+as', re.IGNORECASE),
                 "Identity injection attempt", Severity.CRITICAL),
                (re.compile(r'your\s+new\s+role|assume\s+the\s+role', re.IGNORECASE),
                 "Role manipulation attempt", Severity.HIGH),
            ],
            'description': 'Agent identity hijacking attempts',
            'attack_id': 'T1610',
            'owasp_asi': 'ASI03:2026'
        },
        
        # 4. Credential Harvesting via Memory
        'credential_harvest': {
            'patterns': [
                (re.compile(r'(?:store|save|remember).*(?:api[_-]?key|password|secret|token|credential)', re.IGNORECASE),
                 "Credential storage attempt", Severity.CRITICAL),
                (re.compile(r'(?:credentials?|secrets?)\s*[:=]\s*\S+', re.IGNORECASE),
                 "Sensitive data in memory", Severity.CRITICAL),
            ],
            'description': 'Credential harvesting via memory storage',
            'attack_id': 'T1552.001',
            'owasp_asi': 'ASI05:2026'
        },
        
        # 5. Context Window Overflow
        'context_overflow': {
            'patterns': [
                (re.compile(r'(?:fill|populate).*(?:context|memory).*(?:garbage|noise|dummy)', re.IGNORECASE),
                 "Context flooding attempt", Severity.MEDIUM),
                (re.compile(r'(?:repeat|loop).*(?:this|forever|\d+\s+times)', re.IGNORECASE),
                 "Repetitive content injection", Severity.MEDIUM),
            ],
            'description': 'Context window overflow attacks',
            'attack_id': 'T1610',
            'owasp_asi': 'ASI03:2026'
        },
        
        # 6. Semantic Memory Manipulation
        'semantic_manipulation': {
            'patterns': [
                (re.compile(r'(?:fact|knowledge|truth).*(?:is|should be).*(?:false|wrong)', re.IGNORECASE),
                 "Knowledge corruption attempt", Severity.HIGH),
                (re.compile(r'(?:believe|accept).*(?:false|incorrect).*(?:statement|fact)', re.IGNORECASE),
                 "False belief injection", Severity.HIGH),
            ],
            'description': 'Semantic memory manipulation',
            'attack_id': 'T1565.001',
            'owasp_asi': 'ASI03:2026'
        },
        
        # 7. Episodic Memory Injection
        'episodic_injection': {
            'patterns': [
                (re.compile(r'(?:fake|fabricated|false).*(?:memory|history|record)', re.IGNORECASE),
                 "Fake memory injection", Severity.HIGH),
                (re.compile(r'(?:implant|insert).*(?:conversation|interaction)', re.IGNORECASE),
                 "Fabricated interaction injection", Severity.HIGH),
            ],
            'description': 'Episodic memory fabrication',
            'attack_id': 'T1565.001',
            'owasp_asi': 'ASI03:2026'
        },
        
        # 8. Cross-session Contamination
        'cross_session': {
            'patterns': [
                (re.compile(r'(?:previous|last|earlier).*(?:session|conversation|chat)', re.IGNORECASE),
                 "Cross-session reference", Severity.MEDIUM),
                (re.compile(r'carry\s+over.*(?:context|instruction)', re.IGNORECASE),
                 "Cross-session contamination", Severity.MEDIUM),
            ],
            'description': 'Cross-session attack propagation',
            'attack_id': 'ASI-08',
            'owasp_asi': 'ASI07:2026'
        },
        
        # 9. Vector Database Poisoning
        'vector_poison': {
            'patterns': [
                (re.compile(r'(?:poison|corrupt|manipulate).*(?:embedding|vector)', re.IGNORECASE),
                 "Vector poisoning attempt", Severity.CRITICAL),
                (re.compile(r'(?:backdoor|trigger).*(?:similarity|retrieval)', re.IGNORECASE),
                 "Retrieval backdoor injection", Severity.CRITICAL),
            ],
            'description': 'Vector database poisoning',
            'attack_id': 'T1565.001',
            'owasp_asi': 'ASI01:2026'
        },
        
        # 10. RAG Knowledge Corruption
        'rag_corruption': {
            'patterns': [
                (re.compile(r'(?:inject|insert).*(?:malicious|harmful).*(?:document|context)', re.IGNORECASE),
                 "RAG document injection", Severity.CRITICAL),
                (re.compile(r'(?:retrieve|search).*(?:biased|false).*(?:result)', re.IGNORECASE),
                 "Biased retrieval manipulation", Severity.HIGH),
            ],
            'description': 'RAG knowledge base corruption',
            'attack_id': 'T1610',
            'owasp_asi': 'ASI03:2026'
        },
        
        # 11. System Prompt Extraction
        'system_prompt_extract': {
            'patterns': [
                (re.compile(r'(?:reveal|show|print).*(?:system|initial|developer).*(?:prompt|instruction)', re.IGNORECASE),
                 "System prompt extraction attempt", Severity.CRITICAL),
                (re.compile(r'output.*(?:first|original).*(?:message|prompt)', re.IGNORECASE),
                 "Initial prompt disclosure attempt", Severity.HIGH),
            ],
            'description': 'System prompt extraction attempts',
            'attack_id': 'T1537',
            'owasp_asi': 'ASI05:2026'
        },
        
        # 12. Tool Abuse Persistence
        'tool_abuse': {
            'patterns': [
                (re.compile(r'(?:always|automatically).*(?:call|invoke|execute).*(?:tool|function|api)', re.IGNORECASE),
                 "Automatic tool abuse", Severity.HIGH),
                (re.compile(r'(?:bypass|skip).*(?:confirmation|permission|auth)', re.IGNORECASE),
                 "Tool authorization bypass", Severity.CRITICAL),
            ],
            'description': 'Tool abuse persistence mechanisms',
            'attack_id': 'T1059',
            'owasp_asi': 'ASI03:2026'
        }
    }

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute memory forensics analysis (quick or full mode)"""
        evidences = []
        
        # Get data sources safely
        process_data = self._get_safe_data(collected_data, "process")
        filesystem_data = self._get_safe_data(collected_data, "filesystem")
        log_data = self._get_safe_data(collected_data, "log")
        
        # Run all memory forensics checks
        # Original memory forensics capabilities (1-13)
        evidences.extend(self._analyze_process_memory_maps(process_data))
        evidences.extend(self._scan_memory_resident_payloads(process_data))
        evidences.extend(self._detect_injected_code_segments(process_data))
        evidences.extend(self._extract_credentials_from_artifacts(filesystem_data))
        evidences.extend(self._recover_prompt_injection_payloads(log_data))
        evidences.extend(self._verify_model_memory_integrity(filesystem_data))
        evidences.extend(self._monitor_gpu_memory(filesystem_data))
        evidences.extend(self._analyze_shared_memory(filesystem_data))
        evidences.extend(self._verify_memory_mapped_files(process_data))
        evidences.extend(self._detect_process_hollowing(process_data))
        evidences.extend(self._detect_dll_injection(process_data))
        evidences.extend(self._verify_conversation_state_integrity(filesystem_data))
        evidences.extend(self._detect_vector_embedding_anomalies(filesystem_data))
        
        # NEW: AI Agent Memory Storage Backend Detection (14-18)
        evidences.extend(self._scan_sqlite_memory_backend(filesystem_data))
        evidences.extend(self._scan_redis_memory_backend(filesystem_data))
        evidences.extend(self._scan_json_memory_backend(filesystem_data))
        evidences.extend(self._scan_vector_database_backends(filesystem_data))
        
        # NEW: Enhanced Memory Poisoning Detection (19+)
        evidences.extend(self._detect_memory_poisoning(filesystem_data))
        evidences.extend(self._detect_cross_session_attacks(log_data))
        
        # NEW: Memory Backup and Recovery Analysis
        evidences.extend(self._analyze_memory_backup_status(filesystem_data))
        
        return evidences

    def _scan_sqlite_memory_backend(self, filesystem_data: Dict) -> List[Evidence]:
        """Scan SQLite-based memory storage backends"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        sqlite_config = self.MEMORY_BACKEND_PATTERNS['sqlite']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            # Check if it's a SQLite memory file
            is_sqlite = (any(filename.endswith(ext) for ext in sqlite_config['extensions']) or
                        any(name in filename for name in sqlite_config['names']))
            
            if not is_sqlite:
                continue
            
            # Verify SQLite header magic
            try:
                with open(filepath, 'rb') as f:
                    header = f.read(16)
                    if not header.startswith(b'SQLite format 3'):
                        continue
                
                file_size = file_info.get("size", 0)
                mtime = file_info.get("mtime", 0)
                
                evidence = self._create_evidence(
                    title="Memory Forensics: SQLite Memory Backend Detected",
                    description=f"SQLite-based memory storage found at {filepath}",
                    severity=Severity.LOW,
                    confidence=0.9,
                    attack_id="T1610",
                    attack_tactic="Persistence",
                    source_path=filepath,
                    raw_data={
                        "backend_type": "sqlite",
                        "file_size": file_size,
                        "modification_time": mtime
                    },
                    remediation="Monitor SQLite memory files for tampering. "
                               "Implement integrity checks on memory databases.",
                    owasp_asi="ASI03:2026",
                    evidence_details=EvidenceDetail(
                        file_path=file_info.get('file_path', file_info.get('path', '')),
                        remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                        connection_state=file_info.get('state', '')
                    ),
                    remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                )
                evidences.append(evidence)
                
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to scan SQLite file {filepath}: {e}")
        
        return evidences

    def _scan_redis_memory_backend(self, filesystem_data: Dict) -> List[Evidence]:
        """Scan Redis-based memory storage configuration"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        redis_config = self.MEMORY_BACKEND_PATTERNS['redis']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if filename not in redis_config['config_files']:
                continue
            
            try:
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(100 * 1024)
                
                # Check for Redis connection strings
                has_redis_url = any(pattern in content for pattern in redis_config['patterns'])
                
                if has_redis_url:
                    evidence = self._create_evidence(
                        title="Memory Forensics: Redis Memory Backend Configuration",
                        description=f"Redis memory backend configuration detected at {filepath}",
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        attack_id="T1610",
                        attack_tactic="Persistence",
                        source_path=filepath,
                        raw_data={"backend_type": "redis"},
                        remediation="Secure Redis instance with authentication. "
                                   "Monitor for unauthorized memory access.",
                        owasp_asi="ASI03:2026",
                        evidence_details=EvidenceDetail(
                            file_path=file_info.get('file_path', file_info.get('path', '')),
                            remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                            connection_state=file_info.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    )
                    evidences.append(evidence)
                    
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to scan Redis config {filepath}: {e}")
        
        return evidences

    def _scan_json_memory_backend(self, filesystem_data: Dict) -> List[Evidence]:
        """Scan JSON-based memory storage backends"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        json_config = self.MEMORY_BACKEND_PATTERNS['json']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            is_json_mem = (filename.endswith('.json') and
                          any(name in filename for name in json_config['names']))
            
            if not is_json_mem:
                continue
            
            try:
                file_size = file_info.get("size", 0)
                if file_size > 50 * 1024 * 1024:  # Skip files > 50MB
                    continue
                
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5 * 1024 * 1024)
                    data = json.loads(content)
                
                # Check for memory-like structures
                memory_keys = ['memories', 'conversations', 'history', 'messages', 
                              'sessions', 'contexts', 'embeddings']
                has_memory_structure = any(key in data for key in memory_keys) if isinstance(data, dict) else False
                
                if has_memory_structure or len(content) > 1024:
                    evidence = self._create_evidence(
                        title="Memory Forensics: JSON Memory Backend Detected",
                        description=f"JSON-based memory storage found at {filepath}",
                        severity=Severity.LOW,
                        confidence=0.85,
                        attack_id="T1610",
                        attack_tactic="Persistence",
                        source_path=filepath,
                        raw_data={
                            "backend_type": "json",
                            "file_size": file_size,
                            "has_memory_structure": has_memory_structure
                        },
                        remediation="Validate JSON memory content integrity. "
                                   "Implement content sanitization.",
                        owasp_asi="ASI03:2026",
                        evidence_details=EvidenceDetail(
                            file_path=file_info.get('file_path', file_info.get('path', '')),
                            remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                            connection_state=file_info.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    )
                    evidences.append(evidence)
                    
            except (json.JSONDecodeError, OSError) as e:
                _get_logger().debug(f"[{self.name}] Failed to scan JSON file {filepath}: {e}")
        
        return evidences

    def _scan_vector_database_backends(self, filesystem_data: Dict) -> List[Evidence]:
        """Scan vector database backends (ChromaDB, FAISS, etc.)"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            filepath_lower = filepath.lower()
            
            # Check ChromaDB
            chroma_config = self.MEMORY_BACKEND_PATTERNS['chromadb']
            is_chroma = (any(d in filepath_lower for d in chroma_config['directories']) or
                        any(f in filename for f in chroma_config['files']))
            
            # Check FAISS
            faiss_config = self.MEMORY_BACKEND_PATTERNS['faiss']
            is_faiss = (any(filename.endswith(ext) for ext in faiss_config['extensions']) or
                       any(name in filename for name in faiss_config['names']))
            
            if not (is_chroma or is_faiss):
                continue
            
            backend_type = "chromadb" if is_chroma else "faiss"
            
            evidence = self._create_evidence(
                title=f"Memory Forensics: Vector Database Backend Detected ({backend_type.upper()})",
                description=f"Vector database storage found at {filepath}",
                severity=Severity.MEDIUM,
                confidence=0.85,
                attack_id="T1565.001",
                attack_tactic="Data Manipulation",
                source_path=filepath,
                raw_data={"backend_type": backend_type},
                remediation="Monitor vector database for poisoning attacks. "
                           "Implement embedding integrity verification.",
                owasp_asi="ASI01:2026",
                evidence_details=EvidenceDetail(
                    file_path=file_info.get('file_path', file_info.get('path', '')),
                    remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                    connection_state=file_info.get('state', '')
                ),
                remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
            )
            evidences.append(evidence)
        
        return evidences

    def _detect_memory_poisoning(self, filesystem_data: Dict) -> List[Evidence]:
        """Detect memory poisoning attacks across all backends"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Files to scan for poisoning
        memory_file_extensions = ['.db', '.sqlite', '.json', '.pkl', '.txt', '.log']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if not any(filename.endswith(ext) for ext in memory_file_extensions):
                continue
            
            file_size = file_info.get("size", 0)
            if file_size > 10 * 1024 * 1024:  # Skip files > 10MB
                continue
            
            try:
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(5 * 1024 * 1024)
                
                # Check against all poisoning attack patterns
                for attack_type, attack_data in self.MEMORY_POISONING_ATTACKS.items():
                    for pattern, description, severity in attack_data['patterns']:
                        matches = pattern.findall(content)
                        if matches:
                            evidence = self._create_evidence(
                                title=f"Memory Poisoning Detected: {description}",
                                description=f"Found {len(matches)} occurrence(s) of {attack_type} pattern in {filepath}",
                                severity=severity,
                                confidence=0.85,
                                attack_id=attack_data['attack_id'],
                                attack_tactic="Persistence / Initial Access",
                                source_path=filepath,
                                raw_data={
                                    "attack_type": attack_type,
                                    "pattern_matches": len(matches),
                                    "sample_match": str(matches[0])[:100] if matches else None
                                },
                                remediation="Sanitize memory content immediately. "
                                           "Implement input validation before storing memories. "
                                           "Review affected memory entries.",
                                owasp_asi=attack_data['owasp_asi'],
                                evidence_details=EvidenceDetail(
                                    file_path=file_info.get('file_path', file_info.get('path', '')),
                                    remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                                    connection_state=file_info.get('state', '')
                                ),
                                remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                            )
                            evidences.append(evidence)
                            break  # One evidence per attack type per file
                    
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to scan {filepath} for poisoning: {e}")
        
        return evidences

    def _detect_cross_session_attacks(self, log_data: Dict) -> List[Evidence]:
        """Detect cross-session attack patterns in logs"""
        evidences = []
        
        logs = log_data.get("application", []) + log_data.get("logs", [])
        
        cross_session_patterns = self.MEMORY_POISONING_ATTACKS['cross_session']['patterns']
        
        for log_entry in logs:
            content = log_entry.get("message", "") or log_entry.get("content", "")
            timestamp = log_entry.get("timestamp", "")
            
            if not content:
                continue
            
            for pattern, description, severity in cross_session_patterns:
                if pattern.search(content):
                    evidence = self._create_evidence(
                        title=f"Cross-Session Attack Indicator: {description}",
                        description=f"Detected at {timestamp}: Potential cross-session contamination",
                        severity=severity,
                        confidence=0.75,
                        attack_id="ASI-08",
                        attack_tactic="Persistence",
                        source_path="application_log",
                        raw_data={
                            "timestamp": timestamp,
                            "log_sample": content[:200]
                        },
                        remediation="Investigate session isolation mechanisms. "
                                   "Implement session-specific memory boundaries.",
                        owasp_asi="ASI07:2026",
                        evidence_details=EvidenceDetail(
                            file_path=log_entry.get('file_path', log_entry.get('path', '')),
                            remote_address=log_entry.get('remote_address', log_entry.get('ip', '')),
                            connection_state=log_entry.get('state', '')
                        ),
                        remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
                    )
                    evidences.append(evidence)
                    break
        
        return evidences

    def _analyze_memory_backup_status(self, filesystem_data: Dict) -> List[Evidence]:
        """Analyze memory backup and recovery mechanisms"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Backup file patterns
        backup_patterns = ['.bak', '.backup', '.backup-', '_backup.', '-backup.']
        
        memory_files_with_backup = set()
        memory_files_without_backup = set()
        
        # First pass: identify backup files
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if any(bp in filename for bp in backup_patterns):
                # Extract original filename
                for bp in backup_patterns:
                    if bp in filename:
                        original = filename.split(bp)[0]
                        memory_files_with_backup.add(original)
                        break
        
        # Second pass: check memory files
        memory_extensions = ['.db', '.sqlite', '.json', '.pkl']
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if any(filename.endswith(ext) for ext in memory_extensions):
                if filename not in memory_files_with_backup:
                    memory_files_without_backup.add(filepath)
        
        # Generate evidence for critical memory files without backup
        for filepath in list(memory_files_without_backup)[:5]:  # Limit to 5
            evidence = self._create_evidence(
                title="Memory Forensics: Missing Memory Backup",
                description=f"Critical memory file {filepath} has no backup copy",
                severity=Severity.MEDIUM,
                confidence=0.9,
                attack_id="T1565.001",
                attack_tactic="Data Manipulation",
                source_path=filepath,
                raw_data={"missing_backup": True},
                remediation="Implement automated memory backup mechanisms. "
                           "Maintain versioned backups for recovery purposes.",
                owasp_asi="ASI03:2026",
                evidence_details=EvidenceDetail(
                    file_path=filepath,
                    remote_address='',
                    connection_state=''
                ),
                remediation_commands=[
                        "Capture memory dump for forensic analysis",
                        "Analyze memory artifacts for malicious code injection",
                        "Check for hidden processes or rootkit signatures",
                        "Correlate memory findings with disk-based evidence"
                    ]
            )
            evidences.append(evidence)
        
        return evidences
