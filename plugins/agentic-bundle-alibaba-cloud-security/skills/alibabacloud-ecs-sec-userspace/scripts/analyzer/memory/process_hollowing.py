"""Process hollowing and DLL injection detection mixin.

Provides detection capabilities for:
- Process hollowing technique detection
- DLL injection pattern matching
- Suspicious process creation analysis
"""
from typing import List, Dict

from ...reporter.evidence import Evidence, EvidenceDetail
from .helpers import _get_logger


class ProcessHollowingMixin:
    """Process hollowing and DLL injection detection capabilities."""

    def _detect_process_hollowing(self, process_data: Dict) -> List[Evidence]:
        """Detect process hollowing techniques."""
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
        """Detect DLL injection techniques."""
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
