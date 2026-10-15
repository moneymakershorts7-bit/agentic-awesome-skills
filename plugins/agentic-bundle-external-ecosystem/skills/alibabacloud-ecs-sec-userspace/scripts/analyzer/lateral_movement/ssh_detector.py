"""SSH Lateral Movement Detection Mixin.

Provides SSH abuse, key theft, config tampering, hijacking, and session
anomaly detection for the LateralMovementAnalyzer.

Extracted from lateral_movement_analyzer.py - zero functional change.
"""
import re
from typing import List, Dict
from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity


class SSHDetectorMixin:
    """Mixin providing SSH lateral movement detection capabilities."""

    # SSH abuse detection patterns
    SSH_TUNNEL_PATTERNS = [
        (re.compile(r'ssh\s+.*-L\s+\d+:', re.IGNORECASE),
         "SSH local port forwarding detected", Severity.HIGH, "T1021.004"),
        (re.compile(r'ssh\s+.*-R\s+\d+:', re.IGNORECASE),
         "SSH remote port forwarding detected", Severity.HIGH, "T1021.004"),
        (re.compile(r'ssh\s+.*-D\s+\d+', re.IGNORECASE),
         "SSH dynamic SOCKS proxy detected", Severity.HIGH, "T1021.004"),
        (re.compile(r'ssh\s+.*-w\s+\d+:\d+', re.IGNORECASE),
         "SSH tunnel device forwarding detected", Severity.MEDIUM, "T1021.004"),
        (re.compile(r'LocalForward|RemoteForward|DynamicForward', re.IGNORECASE),
         "SSH config port forwarding detected", Severity.MEDIUM, "T1021.004"),
    ]

    SSH_KEY_THEFT_PATTERNS = [
        (re.compile(r'cat\s+.*\.ssh/id_.*\s*>\s*/dev/null', re.IGNORECASE),
         "SSH private key read attempt", Severity.CRITICAL, "T1021.004"),
        (re.compile(r'scp\s+.*\.ssh/id_', re.IGNORECASE),
         "SSH private key transfer via scp", Severity.CRITICAL, "T1021.004"),
        (re.compile(r'rsync\s+.*\.ssh/', re.IGNORECASE),
         "SSH directory sync (potential key exfiltration)", Severity.HIGH, "T1570"),
        (re.compile(r'find\s+.*-name\s+["\']?id_rsa', re.IGNORECASE),
         "SSH key search command", Severity.MEDIUM, "T1021.004"),
        (re.compile(r'authorized_keys', re.IGNORECASE),
         "SSH authorized_keys file access", Severity.MEDIUM, "T1078"),
    ]

    SSH_BRUTEFORCE_INDICATORS = [
        (re.compile(r'Failed password for .* from \S+ port \d+', re.IGNORECASE),
         "SSH failed password attempt", Severity.MEDIUM, "T1021.004"),
        (re.compile(r'Invalid user .* from \S+', re.IGNORECASE),
         "SSH invalid user attempt", Severity.MEDIUM, "T1021.004"),
        (re.compile(r'max auth attempts', re.IGNORECASE),
         "SSH max auth attempts reached", Severity.MEDIUM, "T1021.004"),
        (re.compile(r'Connection closed by authenticating user', re.IGNORECASE),
         "SSH authentication failure", Severity.LOW, "T1021.004"),
    ]

    SSH_CONFIG_TAMPERING = [
        (re.compile(r'PermitRootLogin\s+yes', re.IGNORECASE),
         "SSH root login enabled in config", Severity.HIGH, "T1078"),
        (re.compile(r'PasswordAuthentication\s+yes', re.IGNORECASE),
         "SSH password authentication enabled", Severity.MEDIUM, "T1078"),
        (re.compile(r'PermitEmptyPasswords\s+yes', re.IGNORECASE),
         "SSH empty passwords permitted", Severity.CRITICAL, "T1078"),
        (re.compile(r'AuthorizedKeysFile\s+.*\|', re.IGNORECASE),
         "SSH authorized keys pipe to command", Severity.CRITICAL, "T1078"),
    ]

    # SSH Hijacking Detection (T1563.001)
    SSH_HIJACK_PATTERNS = [
        (re.compile(r'SSH_AUTH_SOCK=/tmp/ssh-.+/agent\.\d+', re.IGNORECASE),
         "SSH agent socket from /tmp (potential theft)", Severity.HIGH, "T1563.001"),
        (re.compile(r'ssh-askpass|ssh-agent\s+-k', re.IGNORECASE),
         "SSH agent manipulation detected", Severity.MEDIUM, "T1563.001"),
        (re.compile(r'ControlMaster\s*=\s*auto|ControlPath\s*=', re.IGNORECASE),
         "SSH connection multiplexing enabled", Severity.MEDIUM, "T1563.001"),
        (re.compile(r'/proc/\d+/environ.*SSH_AUTH_SOCK', re.IGNORECASE),
         "SSH environment variable access across processes", Severity.HIGH, "T1563.001"),
    ]

    SSH_SESSION_ANOMALIES = [
        (re.compile(r'pts/\d+.*sshd.*mismatch', re.IGNORECASE),
         "SSH session parent process mismatch", Severity.CRITICAL, "T1021.004"),
        (re.compile(r'Accepted\s+(publickey|password).*from\s+\S+\s+port\s+\d+', re.IGNORECASE),
         "SSH authentication success with unusual source", Severity.LOW, "T1021.004"),
    ]

    def _detect_ssh_abuse(self, process_data: Dict, filesystem_data: Dict) -> List[Evidence]:
        """Detect SSH abuse patterns"""
        evidences = []
        processes = process_data.get("processes", [])
        files = filesystem_data.get("scanned_paths", [])

        evidence_id_counter = 0

        # Check SSH tunnel patterns
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue

            for pattern, title, severity, attack_id in self.SSH_TUNNEL_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_ssh_tunnel_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"SSH tunnel detected in process: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.85,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review SSH tunnel usage and verify it is authorized",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"),
                            cmdline=cmdline[:500],
                            executable=proc.get("exe", ""),
                            user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"cat /proc/{proc.get('pid', 'PID')}/net/tcp 2>/dev/null | head -20",
                            "ss -tunap | grep -i ssh",
                            "auditctl -w /usr/bin/ssh -p x -k ssh_tunnel",
                        ],
                    ))

        # Check SSH key theft patterns
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue

            for pattern, title, severity, attack_id in self.SSH_KEY_THEFT_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_ssh_key_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Potential SSH key theft: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.8,
                        attack_id=attack_id,
                        attack_tactic="Credential Access",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Audit SSH key access and implement proper key management",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"),
                            cmdline=cmdline[:500],
                            executable=proc.get("exe", ""),
                            user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                            "ss -tunap | head -20",
                        ],
                    ))

        # Check SSH config tampering
        for file_path in files:
            if "sshd_config" in file_path or "ssh_config" in file_path:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for pattern, title, severity, attack_id in self.SSH_CONFIG_TAMPERING:
                            if pattern.search(content):
                                evidence_id_counter += 1
                                evidences.append(Evidence(
                                    id=f"lateral_ssh_config_{evidence_id_counter}",
                                    module=self.name,
                                    title=title,
                                    description=f"Insecure SSH config in {file_path}: {pattern.pattern}",
                                    severity=severity,
                                    confidence=0.9,
                                    attack_id=attack_id,
                                    attack_tactic="Persistence",
                                    source_path=file_path,
                                    timestamp="",
                                    raw_data={"file": file_path},
                                    remediation="Harden SSH configuration according to security best practices",
                                    evidence_details=EvidenceDetail(
                                        file_path=file_path,
                                        content=f"Insecure SSH config pattern: {pattern.pattern}",
                                    ),
                                    remediation_commands=[
                                        f"cp {file_path} {file_path}.bak.$(date +%Y%m%d)",
                                        f"grep -n 'PermitRootLogin\\|PasswordAuthentication\\|PermitEmptyPasswords' {file_path}",
                                        f"sshd -t -f {file_path} 2>&1",
                                        "systemctl restart sshd",
                                    ],
                                ))
                except OSError:
                    pass

        return evidences

    def _detect_ssh_hijacking(self, process_data: Dict, filesystem_data: Dict) -> List[Evidence]:
        """Detect SSH session hijacking and agent socket theft (T1563.001)"""
        evidences = []
        processes = process_data.get("processes", [])
        files = filesystem_data.get("scanned_paths", [])

        evidence_id_counter = 1000

        for proc in processes:
            cmdline = proc.get("cmdline", "")
            environ = proc.get("environ", "")
            if not cmdline and not environ:
                continue

            combined_text = f"{cmdline} {environ}"
            for pattern, title, severity, attack_id in self.SSH_HIJACK_PATTERNS:
                if pattern.search(combined_text):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_ssh_hijack_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"SSH hijacking indicator in process {proc.get('pid', 'unknown')}: {cmdline[:150]}",
                        severity=severity,
                        confidence=0.85,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
                        remediation="Verify SSH session integrity and check for unauthorized agent socket access",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"),
                            cmdline=cmdline[:500],
                            executable=proc.get("exe", ""),
                            user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                            "ss -tunap | head -20",
                        ],
                    ))

            for pattern, title, severity, attack_id in self.SSH_SESSION_ANOMALIES:
                if pattern.search(combined_text):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_ssh_session_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"SSH session anomaly detected: {cmdline[:150]}",
                        severity=severity,
                        confidence=0.75,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Investigate SSH session for signs of hijacking",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"),
                            cmdline=cmdline[:500],
                            executable=proc.get("exe", ""),
                            user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                            "ss -tunap | head -20",
                        ],
                    ))

        ssh_socket_dirs = ["/tmp/ssh-", "/var/run/sshd/"]
        for file_path in files:
            for socket_dir in ssh_socket_dirs:
                if socket_dir in file_path and "agent" in file_path.lower():
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_ssh_socket_{evidence_id_counter}",
                        module=self.name,
                        title="SSH Agent Socket File Detected",
                        description=f"SSH agent socket found at {file_path}",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        attack_id="T1563.001",
                        attack_tactic="Lateral Movement",
                        source_path=file_path,
                        timestamp="",
                        raw_data={"file": file_path},
                        remediation="Monitor SSH socket access and verify ownership",
                        evidence_details=EvidenceDetail(
                            file_path=file_path,
                            content="Detected suspicious file access",
                        ),
                        remediation_commands=[
                            "ls -la {file_path}",
                            "stat {file_path}",
                            "cat {file_path} 2>/dev/null | head -20",
                        ],
                    ))

        return evidences
