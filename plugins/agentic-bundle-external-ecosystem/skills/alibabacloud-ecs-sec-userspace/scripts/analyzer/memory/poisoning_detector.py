"""Memory poisoning and cross-session attack detection mixin.

Provides detection capabilities for:
- Memory poisoning attack detection across all backends
- Cross-session attack pattern detection in logs
- Memory backup and recovery analysis
"""
import os
from typing import List, Dict

from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .helpers import _get_logger


class PoisoningDetectorMixin:
    """Memory poisoning and cross-session attack detection."""

    def _detect_memory_poisoning(self, filesystem_data: Dict) -> List[Evidence]:
        """Detect memory poisoning attacks across all backends."""
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
        """Detect cross-session attack patterns in logs."""
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
        """Analyze memory backup and recovery mechanisms."""
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
                    remote_address="",
                    connection_state=""
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
