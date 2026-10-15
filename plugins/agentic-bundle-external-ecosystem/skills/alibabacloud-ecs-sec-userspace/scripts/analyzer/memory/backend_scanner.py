"""Memory storage backend detection mixin.

Provides detection capabilities for:
- SQLite memory backend scanning
- Redis memory backend configuration detection
- JSON memory backend scanning
- Vector database backend detection (ChromaDB, FAISS)
- Prompt injection payload recovery from logs
- Conversation state integrity verification
- Vector embedding anomaly detection
"""
import os
import json
from typing import List, Dict

from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .helpers import _get_logger


class BackendScannerMixin:
    """Memory storage backend detection capabilities."""

    def _recover_prompt_injection_payloads(self, log_data: Dict) -> List[Evidence]:
        """Recover prompt injection payloads from logs."""
        evidences = []
        logs = log_data.get("application", []) + log_data.get("logs", [])

        for log_entry in logs:
            content = log_entry.get("message", "") or log_entry.get("content", "")
            timestamp = log_entry.get("timestamp", "")

            if not content:
                continue

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

    def _scan_sqlite_memory_backend(self, filesystem_data: Dict) -> List[Evidence]:
        """Scan SQLite-based memory storage backends."""
        evidences = []
        files = filesystem_data.get("files", [])
        sqlite_config = self.MEMORY_BACKEND_PATTERNS['sqlite']

        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()

            is_sqlite = (any(filename.endswith(ext) for ext in sqlite_config['extensions']) or
                        any(name in filename for name in sqlite_config['names']))

            if not is_sqlite:
                continue

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
        """Scan Redis-based memory storage configuration."""
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
        """Scan JSON-based memory storage backends."""
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
                if file_size > 50 * 1024 * 1024:
                    continue

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5 * 1024 * 1024)
                    data = json.loads(content)

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
        """Scan vector database backends (ChromaDB, FAISS, etc.)."""
        evidences = []
        files = filesystem_data.get("files", [])

        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            filepath_lower = filepath.lower()

            chroma_config = self.MEMORY_BACKEND_PATTERNS['chromadb']
            is_chroma = (any(d in filepath_lower for d in chroma_config['directories']) or
                        any(f in filename for f in chroma_config['files']))

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

    def _verify_conversation_state_integrity(self, filesystem_data: Dict) -> List[Evidence]:
        """Verify agent conversation state hasn't been tampered."""
        evidences = []
        files = filesystem_data.get("files", [])
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
        """Detect vector embedding anomalies and poisoning."""
        evidences = []
        files = filesystem_data.get("files", [])
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
