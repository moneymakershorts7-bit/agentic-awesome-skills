"""RWX memory area scanning and credential extraction mixin.

Provides detection capabilities for:
- Credential pattern extraction from memory artifacts
- Model weight integrity verification
- GPU memory anomaly monitoring
- Shared memory segment analysis
- Memory-mapped file verification
"""
import os
import time
import hashlib
from typing import List, Dict

from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .helpers import _get_logger
from .constants import CREDENTIAL_PATTERNS


class RWXScannerMixin:
    """RWX memory area scanning and credential extraction."""

    def _extract_credentials_from_artifacts(self, filesystem_data: Dict) -> List[Evidence]:
        """Extract credentials from memory artifacts and files."""
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
            if file_size > 100 * 1024 * 1024:  # Skip files > 100MB
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

    def _verify_model_memory_integrity(self, filesystem_data: Dict) -> List[Evidence]:
        """Verify loaded model weights haven't been tampered."""
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
        """Monitor GPU memory for suspicious operations."""
        evidences = []
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
        """Analyze shared memory segments for malicious content."""
        evidences = []
        shm_files = filesystem_data.get("files", [])

        for file_info in shm_files:
            filepath = file_info.get("path", "")

            if '/dev/shm' not in filepath and '/run/shm' not in filepath:
                continue

            shm_patterns = self._compiled_patterns.get('shared_memory_analysis', [])
            for pattern_info in shm_patterns:
                pattern = pattern_info['pattern']

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
        """Verify memory-mapped file integrity."""
        evidences = []
        processes = process_data.get("processes", [])

        for proc in processes:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")

            if self._is_sec_inspect_process(proc, processes):
                _get_logger().debug(f"[{self.name}] Skipping sec-userspace self process: PID={pid}")
                continue

            if not self._is_ai_agent_process(proc.get("exe", ""), cmdline):
                continue

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
