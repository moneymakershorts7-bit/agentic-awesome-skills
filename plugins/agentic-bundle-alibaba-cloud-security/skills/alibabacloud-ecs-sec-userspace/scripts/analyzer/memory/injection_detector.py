"""Memory injection detection mixin.

Provides detection capabilities for:
- Memory-resident payload scanning
- Injected code segment detection
- Process memory maps analysis
"""
import re
from typing import List, Dict

from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .helpers import _get_logger
from .constants import (
    SUSPICIOUS_MEMORY_REGIONS,
    AI_AGENT_PATTERNS,
)


class InjectionDetectorMixin:
    """Memory injection detection capabilities."""

    def _is_ai_agent_process(self, exe: str, cmdline: str = "") -> bool:
        """Check if process is an AI agent."""
        combined = f"{exe} {cmdline}".lower()
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in AI_AGENT_PATTERNS)

    def _analyze_process_memory_maps(self, process_data: Dict) -> List[Evidence]:
        """Analyze /proc/[pid]/maps for suspicious memory regions."""
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
        """Scan processes for memory-resident payload indicators."""
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
        """Detect injected code segments in AI agent processes."""
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
