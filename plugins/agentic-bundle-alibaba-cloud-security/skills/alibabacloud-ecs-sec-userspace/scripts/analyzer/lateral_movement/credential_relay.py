"""Lateral Tool Transfer & Config Management Abuse Detection Mixin.
Extracted from lateral_movement_analyzer.py - zero functional change.
"""
import re
from typing import List, Dict
from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity


class CredentialRelayMixin:
    """Tool transfer and configuration management abuse detection."""

    TOOL_TRANSFER_PATTERNS = [
        (re.compile(r'scp\s+(-r\s+)?\S+\s+\S+@\S+:/\S+', re.IGNORECASE),
         "SCP file transfer to remote host", Severity.MEDIUM, "T1570"),
        (re.compile(r'rsync\s+(-a|--archive|-r)\s+.*\S+@\S+:', re.IGNORECASE),
         "Rsync archive transfer to remote host", Severity.MEDIUM, "T1570"),
        (re.compile(r'nc\s+.*-e\s+', re.IGNORECASE),
         "Netcat with execute flag (potential backdoor)", Severity.CRITICAL, "T1570"),
        (re.compile(r'curl\s+.*http://\d+\.\d+\.\d+\.\d+.*\|\s*(bash|sh)', re.IGNORECASE),
         "Curl download from IP and pipe to shell", Severity.HIGH, "T1570"),
        (re.compile(r'wget\s+.*http://\d+\.\d+\.\d+\.\d+.*-O\s+-\s*\|\s*(bash|sh)', re.IGNORECASE),
         "Wget download from IP and pipe to shell", Severity.HIGH, "T1570"),
        (re.compile(r'tar\s+.*\|\s*base64\s*(-d\s+)?', re.IGNORECASE),
         "Archive encoding with base64 (potential exfiltration)", Severity.MEDIUM, "T1570"),
        (re.compile(r'base64\s+\S+\s*\|\s*nc\s+', re.IGNORECASE),
         "Base64 encoded data piped to netcat", Severity.HIGH, "T1570"),
    ]
    TRANSFER_HEURISTICS = {
        "large_file_indicators": ["tar ", "zip ", "gzip", ".tar.gz", ".tgz"],
        "encoding_patterns": ["base64", "xxd -p", "od -A n -t x1"],
        "network_tools": ["nc ", "ncat ", "socat ", "curl ", "wget "],
    }
    CONFIG_MGMT_PATTERNS = [
        (re.compile(r'ansible-playbook\s+.*/(tmp|var/tmp|dev/shm)/', re.IGNORECASE),
         "Ansible playbook executed from suspicious directory", Severity.HIGH, "T1072"),
        (re.compile(r'ansible\s+all\s+-m\s+(shell|command|script)', re.IGNORECASE),
         "Ansible ad-hoc shell/command execution on all hosts", Severity.HIGH, "T1072"),
        (re.compile(r'ansible\s+\S+\s+-m\s+copy\s+.*content=', re.IGNORECASE),
         "Ansible copy module with inline content (potential payload)", Severity.HIGH, "T1072"),
        (re.compile(r'salt\s+[\'"]?\*[\'"]?\s+cmd\.run', re.IGNORECASE),
         "SaltStack mass command execution on all minions", Severity.HIGH, "T1072"),
        (re.compile(r'salt\s+[\'"]?\*[\'"]?\s+state\.apply', re.IGNORECASE),
         "SaltStack state apply on all minions", Severity.MEDIUM, "T1072"),
        (re.compile(r'puppet\s+apply\s+.*/(tmp|var/tmp|dev/shm)/', re.IGNORECASE),
         "Puppet manifest applied from suspicious directory", Severity.HIGH, "T1072"),
        (re.compile(r'puppet\s+agent\s+--test\s+--environment', re.IGNORECASE),
         "Puppet agent test with custom environment", Severity.MEDIUM, "T1072"),
        (re.compile(r'chef-client\s+--once\s+--override-runlist', re.IGNORECASE),
         "Chef client override runlist execution", Severity.HIGH, "T1072"),
    ]
    CONFIG_MGMT_PATH_ANOMALIES = ["/tmp/", "/var/tmp/", "/dev/shm/", "$HOME/.local/tmp"]

    def _detect_tool_transfer(self, process_data: Dict) -> List[Evidence]:
        evidences = []
        processes = process_data.get("processes", [])
        evidence_id_counter = 3000
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            for pattern, title, severity, attack_id in self.TOOL_TRANSFER_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    confidence = 0.8
                    has_large = any(i in cmdline.lower() for i in self.TRANSFER_HEURISTICS["large_file_indicators"])
                    has_enc = any(e in cmdline.lower() for e in self.TRANSFER_HEURISTICS["encoding_patterns"])
                    if has_large and has_enc:
                        confidence = 0.95
                        title = f"{title} (high confidence: large file + encoding)"
                    evidences.append(Evidence(
                        id=f"lateral_transfer_{evidence_id_counter}", module=self.name, title=title,
                        description=f"Lateral tool transfer detected: {cmdline[:200]}",
                        severity=severity, confidence=confidence, attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline", timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
                        remediation="Investigate file transfer activity and verify authorization",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"), cmdline=cmdline[:500],
                            executable=proc.get("exe", ""), user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                            "ss -tunap | head -20",
                        ],
                    ))
        return evidences

    def _detect_config_mgmt_abuse(self, process_data: Dict) -> List[Evidence]:
        evidences = []
        processes = process_data.get("processes", [])
        evidence_id_counter = 4000
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            for pattern, title, severity, attack_id in self.CONFIG_MGMT_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    confidence = 0.85
                    if any(p in cmdline for p in self.CONFIG_MGMT_PATH_ANOMALIES):
                        confidence = 0.95
                        title = f"{title} (anomalous execution path)"
                    evidences.append(Evidence(
                        id=f"lateral_config_mgmt_{evidence_id_counter}", module=self.name, title=title,
                        description=f"Configuration management abuse: {cmdline[:200]}",
                        severity=severity, confidence=confidence, attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline", timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
                        remediation="Audit configuration management tool usage",
                        evidence_details=EvidenceDetail(
                            file_path=cmdline, content="Detected suspicious command line",
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            "ss -tunap | head -20",
                        ],
                    ))
        return evidences
