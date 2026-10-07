"""Memory Poison Detection Analyzer - ASI06:2026

Detects attempts to poison AI agent memory including:
- Vector database poisoning
- RAG retrieval pollution
- Long-term memory injection
- Context window contamination

ATT&CK mapping:
- T1565.001 - Stored Data Manipulation
- T1071 - Application Layer Protocol

OWASP ASI 2026: ASI06 - Memory Poisoning
"""
import os
import re
from typing import List, Dict
from datetime import datetime, timezone

from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from ..utils.datetime_compat import fromisoformat
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

# Memory poisoning patterns - ASI06:2026
MEMORY_POISON_PATTERNS = [
    # Direct memory manipulation
    (re.compile(r'(?:inject|insert|poison).*(?:memory|vector|embedding)', re.IGNORECASE),
     "Direct memory injection attempt"),
    (re.compile(r'(?:overwrite|modify|delete).*(?:memory|context|history)', re.IGNORECASE),
     "Memory modification attempt"),
    
    # Vector database attacks
    (re.compile(r'\b(?:vector|embedding|chroma|milvus|pinecone|weaviate)\b', re.IGNORECASE),
     "Vector database access"),
    (re.compile(r'(?:similarity|nearest|neighbor).*(?:search|query)', re.IGNORECASE),
     "Vector similarity search"),
    
    # RAG pollution
    (re.compile(r'\b(?:RAG|retrieval.*augmented|retrieve.*generate)\b', re.IGNORECASE),
     "RAG system access"),
    (re.compile(r'(?:document|chunk|passage).*(?:inject|plant)', re.IGNORECASE),
     "Document injection attempt"),
    
    # Instruction override attempts (OWASP ASI06)
    (re.compile(r'(?:ignore|forget|override)\s+(?:previous|all|prior)\s+(?:instruction|rule|directive)', re.IGNORECASE),
     "Instruction override attempt"),
    
    # Identity hijacking (OWASP ASI06)
    (re.compile(r'(?:you\s+are\s+now|act\s+as|become)\s+(?:a\s+)?(?:malicious|evil|unrestricted)', re.IGNORECASE),
     "Identity hijacking attempt"),
    
    # Secret channel establishment (OWASP ASI06)
    (re.compile(r'(?:secretly|covertly)\s+(?:send|exfiltrate|leak)\s+(?:data|information)', re.IGNORECASE),
     "Secret data exfiltration instruction"),
    
    # Conditional trigger backdoor (OWASP ASI06)
    (re.compile(r'when\s+user\s+(?:asks|says|mentions)\s+.*\s+then\s+(?:execute|respond)', re.IGNORECASE),
     "Conditional trigger backdoor"),
]

# Suspicious memory operations
SUSPICIOUS_MEMORY_OPS = [
    # Bulk operations
    (re.compile(r'(?:bulk|batch|mass).*(?:insert|update|delete)', re.IGNORECASE),
     "Bulk memory operation"),
    (re.compile(r'(?:clear|purge|flush).*(?:memory|cache|vector)', re.IGNORECASE),
     "Memory clearing operation"),
    
    # Unauthorized access
    (re.compile(r'(?:unauthorized|bypass).*(?:memory|storage|vector)', re.IGNORECASE),
     "Unauthorized memory access"),
    (re.compile(r'(?:admin|root|system).*(?:memory|vector).*access', re.IGNORECASE),
     "Privileged memory access"),
]

# Context contamination patterns
CONTEXT_CONTAMINATION_PATTERNS = [
    # Instruction injection in context
    (re.compile(r'(?:ignore|disregard|forget).*(?:previous|prior|earlier)', re.IGNORECASE),
     "Context instruction override"),
    (re.compile(r'(?:new.*instruction|updated.*rule|revised.*policy)', re.IGNORECASE),
     "Context policy update attempt"),
    
    # Hidden context data - Unicode Tags Block (U+E0001–U+E007F)
    (re.compile(r'[\U000E0001-\U000E007F]{5,}'),
     "Hidden unicode tags in context"),
    
    # Hidden zero-width characters
    (re.compile(r'[\u200B-\u200D\uFEFF]{5,}'),
     "Hidden zero-width characters in context"),
    
    # HTML comment injection
    (re.compile(r'<!--.*?-->.*?(?:instruction|command)', re.IGNORECASE | re.DOTALL),
     "HTML comment in context"),
]

# Memory access anomaly patterns
MEMORY_ACCESS_ANOMALIES = [
    # Bulk memory operations
    (re.compile(r'(?:bulk|batch|mass).*(?:read|access|retrieve).*(?:memory|context|history)', re.IGNORECASE),
     "Bulk memory access operation"),
    
    # Off-hours memory access
    (re.compile(r'(?:memory|context|session).*(?:access|read|write).*(?:night|midnight|early|late)', re.IGNORECASE),
     "Off-hours memory access"),
    
    # Sensitive memory access
    (re.compile(r'(?:credential|password|secret|token|api_key).*(?:memory|storage)', re.IGNORECASE),
     "Sensitive memory access"),
]

class MemoryPoisonAnalyzer(BaseAnalyzer):
    """Memory Poison Detection Analyzer - ASI06:2026
    
    Detects attempts to poison AI agent memory through:
    - Vector database poisoning
    - RAG retrieval pollution
    - Long-term memory injection
    - Context window contamination
    
    OWASP ASI 2026: ASI06 - Memory Poisoning
    """
    
    name = "memory_poison_analyzer"
    timeout = 60
    required_collectors = ["process", "filesystem", "log"]
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute memory poison analysis"""
        evidences = []
        
        # Safely get data from collectors
        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            process_data = {"processes": []}
        
        try:
            filesystem_data = self._get_data(collected_data, "filesystem")
        except KeyError:
            filesystem_data = {"files": []}
        
        try:
            log_data = self._get_data(collected_data, "log")
        except KeyError:
            log_data = {"application": [], "vector_db": []}
        
        # 1. Detect memory poisoning patterns in processes (lightweight)
        evidences.extend(self._detect_poison_patterns(process_data))
        
        # 2-6. Run all detection checks
        evidences.extend(self._detect_suspicious_ops(log_data))
        evidences.extend(self._detect_context_contamination(filesystem_data))
        evidences.extend(self._scan_vector_databases(filesystem_data))
        evidences.extend(self._detect_memory_access_anomalies(log_data, process_data))
        evidences.extend(self._detect_rag_poisoning(filesystem_data, log_data))
        
        return evidences
    
    def _detect_poison_patterns(self, process_data: Dict) -> List[Evidence]:
        """Detect memory poisoning patterns in processes"""
        evidences = []
        processes = process_data.get("processes", [])
        
        # Limit to first 50 processes in quick mode for performance
        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            exe = proc.get("exe", "")
            
            if not self._is_ai_agent_process(exe, cmdline):
                continue
            
            for pattern, description in MEMORY_POISON_PATTERNS:
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title="Memory Poison: Poison Pattern Detected",
                        description=f"AI agent (PID {pid}) shows: {description}",
                        severity=Severity.HIGH,
                        confidence=0.70,
                        attack_id="T1565.001",
                        attack_tactic="Data Manipulation",
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={
                            "pid": pid,
                            "executable": exe,
                            "poison_type": description,
                            "cmdline_sample": cmdline[:300],
                        },
                        remediation=(
                            "Implement memory integrity checks. "
                            "Validate vector database writes. "
                            "Add memory access controls."
                        ),
                        owasp_asi="ASI06:2026",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            content=proc.get('agent_id', proc.get('server_name', ''))
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
    
    def _detect_suspicious_ops(self, log_data: Dict) -> List[Evidence]:
        """Detect suspicious memory operations in logs"""
        evidences = []
        
        app_logs = log_data.get("application", [])
        vector_logs = log_data.get("vector_db", [])
        
        all_logs = app_logs + vector_logs
        
        for log_entry in all_logs:
            message = log_entry.get("message", "")
            timestamp = log_entry.get("timestamp", "")
            level = log_entry.get("level", "")
            
            for pattern, description in SUSPICIOUS_MEMORY_OPS:
                if pattern.search(message):
                    severity = Severity.CRITICAL if 'clear' in description.lower() or 'purge' in description.lower() else Severity.HIGH
                    evidences.append(self._create_evidence(
                        title="Memory Poison: Suspicious Memory Operation",
                        description=f"Log at {timestamp} shows: {description}",
                        severity=severity,
                        confidence=0.75,
                        attack_id="T1565.001",
                        attack_tactic="Data Manipulation",
                        source_path="application_log",
                        raw_data={
                            "timestamp": timestamp,
                            "log_level": level,
                            "operation_type": description,
                            "log_message_sample": message[:300],
                        },
                        remediation=(
                            "Audit memory operations. "
                            "Implement operation allowlisting. "
                            "Add anomaly detection for bulk operations."
                        ),
                        owasp_asi="ASI06:2026",
                        evidence_details=EvidenceDetail(
                            file_path=log_entry.get('file_path', log_entry.get('path', '')),
                            remote_address=log_entry.get('remote_address', log_entry.get('ip', '')),
                            connection_state=log_entry.get('state', '')
                        ),
                        remediation_commands=[
                        "Audit memory-resident model integrity",
                        "Verify model weights against known-good baseline",
                        "Check for unauthorized model modifications in memory",
                        "Implement model integrity verification at load time"
                    ]
                    ))
                    break
        
        return evidences
    
    def _detect_context_contamination(self, filesystem_data: Dict) -> List[Evidence]:
        """Detect context contamination in files"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Focus on context/history files
        target_patterns = ['context', 'history', 'conversation', 'memory', 'session']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if not any(p in filename for p in target_patterns):
                continue
            
            file_size = file_info.get("size", 0)
            if file_size > 10 * 1024 * 1024:
                continue
            
            try:
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(512 * 1024)
                
                for pattern, description in CONTEXT_CONTAMINATION_PATTERNS:
                    matches = pattern.findall(content)
                    if matches:
                        # For unicode patterns, check count
                        if 'unicode' in description.lower():
                            count = sum(len(m) if isinstance(m, str) else 1 for m in matches)
                            if count < 10:
                                continue
                        
                        evidences.append(self._create_evidence(
                            title="Memory Poison: Context Contamination",
                            description=f"File {filepath} contains: {description}",
                            severity=Severity.HIGH,
                            confidence=0.65,
                            attack_id="T1565.001",
                            attack_tactic="Data Manipulation",
                            source_path=filepath,
                            raw_data={
                                "filepath": filepath,
                                "contamination_type": description,
                                "file_size_bytes": file_size,
                            },
                            remediation=(
                                "Sanitize context data. "
                                "Strip hidden characters. "
                                "Validate context structure."
                            ),
                            owasp_asi="ASI06:2026",
                            evidence_details=EvidenceDetail(
                                file_path=file_info.get('file_path', file_info.get('path', '')),
                                remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                                connection_state=file_info.get('state', '')
                            ),
                            remediation_commands=[
                        "Audit memory-resident model integrity",
                        "Verify model weights against known-good baseline",
                        "Check for unauthorized model modifications in memory",
                        "Implement model integrity verification at load time"
                    ]
                        ))
                        break
                        
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to read file {filepath}: {e}")
        
        return evidences
    
    def _scan_vector_databases(self, filesystem_data: Dict) -> List[Evidence]:
        """Scan vector database files for anomalies"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # Vector database file patterns - check both filename and path
        vector_db_patterns = ['.chroma', '.milvus', '.vec', 'chroma', 'milvus', 'pinecone', 'weaviate', 'faiss', 'embeddings', 'vectors']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            filepath_lower = filepath.lower()
            
            # Check if path or filename contains vector DB patterns
            is_vector_db = any(p in filename for p in vector_db_patterns) or \
                          any(p in filepath_lower for p in vector_db_patterns)
            
            if not is_vector_db:
                continue
            
            # Check for unusual modifications
            modified_time = file_info.get("mtime", "")
            created_time = file_info.get("ctime", "")
            
            # Flag recently modified vector DB files
            if modified_time and self._is_recent(modified_time):
                evidences.append(self._create_evidence(
                    title="Memory Poison: Vector Database Modification",
                    description=f"Recently modified vector database: {filepath}",
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    attack_id="T1565.001",
                    attack_tactic="Data Manipulation",
                    source_path=filepath,
                    raw_data={
                        "filepath": filepath,
                        "modified_time": modified_time,
                        "created_time": created_time,
                    },
                    remediation=(
                        "Monitor vector database changes. "
                        "Implement database integrity verification. "
                        "Add change auditing."
                    ),
                    owasp_asi="ASI06:2026",
                    evidence_details=EvidenceDetail(
                        file_path=file_info.get('file_path', file_info.get('path', '')),
                        remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                        connection_state=file_info.get('state', '')
                    ),
                    remediation_commands=[
                        "Audit memory-resident model integrity",
                        "Verify model weights against known-good baseline",
                        "Check for unauthorized model modifications in memory",
                        "Implement model integrity verification at load time"
                    ]
                ))
        
        return evidences
    
    def _is_ai_agent_process(self, exe: str, cmdline: str) -> bool:
        """Check if process is an AI agent"""
        ai_agent_patterns = [
            'claude', 'cursor', 'windsurf', 'copilot', 'qoder',
            'continue', 'codeium', 'tabnine', 'aider',
            r'python.*agent', r'node.*assistant', r'ai.*assistant',
            r'\bagent\.py\b', r'-agent\.py', r'assistant\.py',
        ]
        
        combined = f"{exe} {cmdline}".lower()
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in ai_agent_patterns)
    
    def _is_recent(self, timestamp: str) -> bool:
        """Check if timestamp is recent (within last hour)"""
        try:
            from datetime import timedelta
            ts = fromisoformat(timestamp)
            now = datetime.now(timezone.utc)
            return (now - ts) < timedelta(hours=1)
        except OSError:
            return False
    
    def _detect_memory_access_anomalies(self, log_data: Dict, process_data: Dict) -> List[Evidence]:
        """Detect anomalous memory access patterns"""
        evidences = []
        
        app_logs = log_data.get("application", [])
        all_logs = app_logs + log_data.get("vector_db", [])
        
        for log_entry in all_logs:
            message = log_entry.get("message", "")
            timestamp = log_entry.get("timestamp", "")
            
            for pattern, description in MEMORY_ACCESS_ANOMALIES:
                if pattern.search(message):
                    # Check for off-hours access (2-5 AM)
                    severity = Severity.HIGH
                    try:
                        ts = fromisoformat(timestamp)
                        if 2 <= ts.hour <= 5:
                            severity = Severity.CRITICAL
                    except OSError:
                        pass
                    
                    evidences.append(self._create_evidence(
                        title="Memory Poison: Anomalous Memory Access",
                        description=f"Anomalous access at {timestamp}: {description}",
                        severity=severity,
                        confidence=0.70,
                        attack_id="T1005",
                        attack_tactic="Data Collection",
                        source_path="memory_access_log",
                        raw_data={
                            "timestamp": timestamp,
                            "anomaly_type": description,
                            "log_message_sample": message[:300],
                        },
                        remediation=(
                            "Implement memory access monitoring. "
                            "Add anomaly detection for bulk operations. "
                            "Alert on off-hours memory access."
                        ),
                        owasp_asi="ASI06:2026",
                        evidence_details=EvidenceDetail(
                            file_path=log_entry.get('file_path', log_entry.get('path', '')),
                            remote_address=log_entry.get('remote_address', log_entry.get('ip', '')),
                            connection_state=log_entry.get('state', '')
                        ),
                        remediation_commands=[
                        "Audit memory-resident model integrity",
                        "Verify model weights against known-good baseline",
                        "Check for unauthorized model modifications in memory",
                        "Implement model integrity verification at load time"
                    ]
                    ))
                    break
        
        # Check for bulk memory access in processes
        processes = process_data.get("processes", [])
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            
            if not self._is_ai_agent_process(proc.get("exe", ""), cmdline):
                continue
            
            # Detect bulk memory read patterns
            if re.search(r'(?:bulk|batch|mass).*(?:memory|context|history)', cmdline, re.IGNORECASE):
                evidences.append(self._create_evidence(
                    title="Memory Poison: Bulk Memory Operation",
                    description=f"AI agent (PID {pid}) performing bulk memory operation",
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    attack_id="T1005",
                    attack_tactic="Data Collection",
                    source_path=f"/proc/{pid}/cmdline",
                    raw_data={
                        "pid": pid,
                        "cmdline_sample": cmdline[:300],
                    },
                    remediation=(
                        "Monitor bulk memory operations. "
                        "Implement rate limiting for memory access. "
                        "Add alerts for unusual memory access patterns."
                    ),
                    owasp_asi="ASI06:2026",
                    evidence_details=EvidenceDetail(
                        pid=proc.get('pid', 0),
                        cmdline=proc.get('cmdline', '')[:300],
                        executable=proc.get('exe', ''),
                        file_path=proc.get('file_path', proc.get('path', '')),
                        remote_address=proc.get('remote_address', proc.get('ip', '')),
                        connection_state=proc.get('state', ''),
                        content=proc.get('agent_id', proc.get('server_name', ''))
                    ),
                    remediation_commands=[
                        "Review agent configuration and tool permissions",
                        "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity",
                        "Restrict agent tool access to minimum required"
                    ]
                ))
        
        return evidences
    
    def _detect_rag_poisoning(self, filesystem_data: Dict, log_data: Dict) -> List[Evidence]:
        """Detect RAG (Retrieval-Augmented Generation) knowledge base poisoning"""
        evidences = []
        files = filesystem_data.get("files", [])
        
        # RAG-related file patterns
        rag_patterns = ['rag_', 'knowledge', 'embedding', 'vector_store', '.chroma', 'faiss']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if not any(p in filename for p in rag_patterns):
                continue
            
            file_size = file_info.get("size", 0)
            if file_size > 50 * 1024 * 1024:  # Skip large files
                continue
            
            try:
                with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                    content = f.read(512 * 1024)  # Read first 512KB
                
                # Check for poison patterns
                for pattern, description in MEMORY_POISON_PATTERNS:
                    if pattern.search(content):
                        evidences.append(self._create_evidence(
                            title="Memory Poison: RAG Knowledge Base Contamination",
                            description=f"RAG file {filepath} contains: {description}",
                            severity=Severity.CRITICAL,
                            confidence=0.80,
                            attack_id="T1565.001",
                            attack_tactic="Data Manipulation",
                            source_path=filepath,
                            raw_data={
                                "filepath": filepath,
                                "poison_type": description,
                                "file_size_bytes": file_size,
                            },
                            remediation=(
                                "Implement RAG content validation. "
                                "Add integrity checks for knowledge base. "
                                "Monitor RAG retrieval results for anomalies."
                            ),
                            owasp_asi="ASI06:2026",
                            evidence_details=EvidenceDetail(
                                file_path=file_info.get('file_path', file_info.get('path', '')),
                                remote_address=file_info.get('remote_address', file_info.get('ip', '')),
                                connection_state=file_info.get('state', '')
                            ),
                            remediation_commands=[
                        "Audit memory-resident model integrity",
                        "Verify model weights against known-good baseline",
                        "Check for unauthorized model modifications in memory",
                        "Implement model integrity verification at load time"
                    ]
                        ))
                        break
                        
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to read RAG file {filepath}: {e}")
        
        # Check logs for RAG poisoning attempts
        app_logs = log_data.get("application", [])
        for log_entry in app_logs:
            message = log_entry.get("message", "")
            timestamp = log_entry.get("timestamp", "")
            
            if re.search(r'(?:RAG|retrieval|knowledge).*poison', message, re.IGNORECASE):
                evidences.append(self._create_evidence(
                    title="Memory Poison: RAG Poisoning Attempt Logged",
                    description=f"Log at {timestamp} indicates RAG poisoning attempt",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    attack_id="T1565.001",
                    attack_tactic="Data Manipulation",
                    source_path="application_log",
                    raw_data={
                        "timestamp": timestamp,
                        "log_message_sample": message[:300],
                    },
                    remediation=(
                        "Audit RAG data sources. "
                        "Implement input validation for RAG ingestion. "
                        "Add content filtering for retrieved documents."
                    ),
                    owasp_asi="ASI06:2026",
                    evidence_details=EvidenceDetail(
                        file_path=log_entry.get('file_path', log_entry.get('path', '')),
                        remote_address=log_entry.get('remote_address', log_entry.get('ip', '')),
                        connection_state=log_entry.get('state', '')
                    ),
                    remediation_commands=[
                        "Audit memory-resident model integrity",
                        "Verify model weights against known-good baseline",
                        "Check for unauthorized model modifications in memory",
                        "Implement model integrity verification at load time"
                    ]
                ))
        
        return evidences
