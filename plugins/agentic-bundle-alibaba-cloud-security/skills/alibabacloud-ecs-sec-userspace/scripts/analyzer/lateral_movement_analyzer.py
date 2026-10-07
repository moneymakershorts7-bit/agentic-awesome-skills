"""Lateral Movement Detection Analyzer

Detects lateral movement attacks in Linux environments, including:
- SSH abuse (tunnels, key theft, bruteforce, session hijacking)
- Cloud service lateral movement (AWS SSM, Azure CLI, GCP gcloud)
- Remote service tunneling (frp, ngrok, reverse proxies)
- Container escape and lateral movement
- Network scanning and enumeration
- Remote execution tools abuse
- Configuration management abuse (Ansible, SaltStack, Puppet)
- Lateral tool transfer (scp, rsync, nc abuse)
- Temporal correlation for multi-stage campaign detection

ATT&CK Mapping:
- T1021 - Remote Services
- T1021.004 - SSH
- T1021.007 - Cloud Services
- T1572 - Protocol Tunneling
- T1570 - Lateral Tool Transfer
- T1072 - Software Deployment Tools
- T1563.001 - SSH Hijacking
- T1046 - Network Service Scanning
- T1078 - Valid Accounts
"""
import os
import re
from typing import List, Dict
from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
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

class LateralMovementAnalyzer(BaseAnalyzer):
    """Lateral Movement Detection Analyzer"""

    name = "lateral_movement_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    required_collectors = ["process", "network"]  # filesystem only for full mode
    quick_collectors = ["process"]  # quick mode only needs process data
    estimated_time = 1.0  # Optimized from higher value

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

    # Remote service tunnel tools
    TUNNEL_TOOL_PROCESSES = {
        "frpc": ("frp client process", Severity.HIGH, "T1572"),
        "frps": ("frp server process", Severity.HIGH, "T1572"),
        "ngrok": ("ngrok tunnel tool", Severity.HIGH, "T1572"),
        "gost": ("GO simple tunnel tool", Severity.HIGH, "T1572"),
        "regeorg": ("reGeorg tunnel script", Severity.CRITICAL, "T1572"),
        "stowaway": ("Stowaway tunnel tool", Severity.HIGH, "T1572"),
        "chisel": ("Chisel TCP tunnel", Severity.HIGH, "T1572"),
        "ligolo": ("Ligolo-ng tunnel tool", Severity.CRITICAL, "T1572"),
        "earthworm": ("Earthworm tunnel tool", Severity.HIGH, "T1572"),
        "termite": ("Termite tunnel framework", Severity.HIGH, "T1572"),
    }

    REVERSE_PROXY_PATTERNS = [
        (re.compile(r'.*proxy\.config\.json', re.IGNORECASE),
         "Proxy configuration file", Severity.MEDIUM, "T1572"),
        (re.compile(r'listen\s+.*socks', re.IGNORECASE),
         "SOCKS proxy listener", Severity.HIGH, "T1572"),
        (re.compile(r'upstream\s+.*https?://', re.IGNORECASE),
         "HTTP upstream proxy", Severity.MEDIUM, "T1572"),
    ]

    # Container escape patterns
    CONTAINER_ESCAPE_INDICATORS = [
        (re.compile(r'/var/run/docker\.sock'),
         "Docker socket access (escape possible)", Severity.CRITICAL, "T1611"),
        (re.compile(r'/var/run/containerd/containerd\.sock'),
         "Containerd socket access", Severity.HIGH, "T1611"),
        (re.compile(r'--privileged\s*(true)?', re.IGNORECASE),
         "Privileged container flag", Severity.CRITICAL, "T1611"),
        (re.compile(r'--cap-add\s+SYS_ADMIN', re.IGNORECASE),
         "SYS_ADMIN capability added", Severity.CRITICAL, "T1611"),
        (re.compile(r'--cap-add\s+ALL', re.IGNORECASE),
         "All capabilities added", Severity.CRITICAL, "T1611"),
        (re.compile(r'--pid=host', re.IGNORECASE),
         "Host PID namespace sharing", Severity.HIGH, "T1611"),
        (re.compile(r'--net=host|--network=host', re.IGNORECASE),
         "Host network namespace sharing", Severity.HIGH, "T1611"),
        (re.compile(r'--volume=/:/|:/mnt/host|/host:', re.IGNORECASE),
         "Host root filesystem mount", Severity.CRITICAL, "T1611"),
        (re.compile(r'/proc/\d+/root'),
         "Process root filesystem access", Severity.HIGH, "T1611"),
        (re.compile(r'nsenter\s+--target\s+\d+', re.IGNORECASE),
         "Namespace enter command", Severity.HIGH, "T1611"),
    ]

    K8S_LATERAL_MOVEMENT_PATTERNS = [
        (re.compile(r'kubectl\s+exec\s+-n\s+\S+\s+\S+\s+--', re.IGNORECASE),
         "Kubectl exec in namespace", Severity.MEDIUM, "T1021"),
        (re.compile(r'kubectl\s+run\s+.*--image=', re.IGNORECASE),
         "Kubectl run with image", Severity.MEDIUM, "T1021"),
        (re.compile(r'kubectl\s+apply\s+-f\s+.*\.yaml', re.IGNORECASE),
         "Kubectl apply manifest", Severity.LOW, "T1021"),
        (re.compile(r'kubectl\s+auth\s+can-i', re.IGNORECASE),
         "Kubernetes permission enumeration", Severity.MEDIUM, "T1069"),
        (re.compile(r'kubectl\s+get\s+(secrets|serviceaccounts)', re.IGNORECASE),
         "Kubernetes secrets/serviceaccounts enumeration", Severity.HIGH, "T1069"),
    ]

    # Network scanning indicators
    NETWORK_SCAN_TOOLS = {
        "nmap": ("Nmap network scanner", Severity.HIGH, "T1046"),
        "masscan": ("Masscan port scanner", Severity.HIGH, "T1046"),
        "zmap": ("ZMap network scanner", Severity.HIGH, "T1046"),
        "rustscan": ("RustScan port scanner", Severity.MEDIUM, "T1046"),
        "naabu": ("Naabu port scanner", Severity.MEDIUM, "T1046"),
        "nuclei": ("Nuclei vulnerability scanner", Severity.MEDIUM, "T1595"),
        "dirb": ("Dirb directory brute-forcer", Severity.MEDIUM, "T1595"),
        "gobuster": ("Gobuster directory/DNS brute-forcer", Severity.MEDIUM, "T1595"),
        "ffuf": ("Fuzz Faster U Fool web fuzzer", Severity.MEDIUM, "T1595"),
    }

    PORT_SCAN_PATTERNS = [
        (re.compile(r'-[pP]\s*\d+-?\d*'),
         "Port specification in command", Severity.MEDIUM, "T1046"),
        (re.compile(r'-s[Sv]\s+', re.IGNORECASE),
         "TCP SYN scan flag", Severity.HIGH, "T1046"),
        (re.compile(r'-A\s+', re.IGNORECASE),
         "Aggressive scan mode", Severity.HIGH, "T1046"),
        (re.compile(r'--open', re.IGNORECASE),
         "Open ports only filter", Severity.MEDIUM, "T1046"),
        (re.compile(r'-Pn|--disable-arp-ping', re.IGNORECASE),
         "No ping scan (stealth)", Severity.MEDIUM, "T1046"),
    ]

    HOST_DISCOVERY_PATTERNS = [
        (re.compile(r'-sn|-sL', re.IGNORECASE),
         "Ping scan / list scan", Severity.MEDIUM, "T1046"),
        (re.compile(r'\d+\.\d+\.\d+\.\d+/\d+'),
         "CIDR notation subnet scan", Severity.MEDIUM, "T1046"),
        (re.compile(r'for\s+i\s+in\s+\d+\.\d+\.\d+\.\d+', re.IGNORECASE),
         "Loop over IP addresses", Severity.MEDIUM, "T1046"),
    ]

    # Legitimate processes that should not trigger host discovery alerts
    # Even if their cmdline matches scanning patterns (e.g., dev scripts)
    LEGITIMATE_HOST_DISCOVERY_PROCESSES = {
        'bash', 'sh', 'zsh', 'dash', 'fish',  # Shell processes
        'python', 'python3', 'python2',  # Python interpreters
        'node', 'nodejs',  # Node.js
        'java',  # Java runtime
        'perl', 'ruby', 'php',  # Other interpreters
    }

    # Remote execution tools
    REMOTE_EXEC_PATTERNS = [
        (re.compile(r'ssh\s+\S+@\S+\s+[\'"]?[\w]+', re.IGNORECASE),
         "SSH remote command execution", Severity.MEDIUM, "T1021.004"),
        (re.compile(r'ssh\s+\S+@\S+\s.*$', re.IGNORECASE),
         "SSH remote connection with command", Severity.MEDIUM, "T1021.004"),
        (re.compile(r'scp\s+.*\s+\S+@\S+:', re.IGNORECASE),
         "SCP file transfer to remote", Severity.MEDIUM, "T1570"),
        (re.compile(r'rsync\s+.*\s+\S+@\S+:', re.IGNORECASE),
         "Rsync to remote host", Severity.MEDIUM, "T1570"),
        (re.compile(r'ansible\s+.*-m\s+(shell|command|script)', re.IGNORECASE),
         "Ansible shell/command execution", Severity.HIGH, "T1021"),
        (re.compile(r'salt\s+.*cmd\.run', re.IGNORECASE),
         "SaltStack command execution", Severity.HIGH, "T1021"),
        (re.compile(r'fabric\s+.*run\(.*\)', re.IGNORECASE),
         "Fabric remote execution", Severity.MEDIUM, "T1021"),
    ]

    K8S_REMOTE_EXEC_PATTERNS = [
        (re.compile(r'kubectl\s+exec\s+\S+\s+--\s+\S+', re.IGNORECASE),
         "Kubectl exec command in pod", Severity.MEDIUM, "T1021"),
        (re.compile(r'kubectl\s+cp\s+.*\s+\S+:\S+', re.IGNORECASE),
         "Kubectl copy files to/from pod", Severity.MEDIUM, "T1570"),
        (re.compile(r'kubectl\s+replace\s+--force', re.IGNORECASE),
         "Kubectl force replace resource", Severity.HIGH, "T1021"),
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

    # Cloud Service Lateral Movement (T1021.007)
    CLOUD_LATERAL_PATTERNS = [
        (re.compile(r'aws\s+ssm\s+start-session\s+--target\s+i-', re.IGNORECASE),
         "AWS SSM Session Manager lateral movement", Severity.HIGH, "T1021.007"),
        (re.compile(r'aws\s+ssm\s+send-command\s+--instance-ids', re.IGNORECASE),
         "AWS SSM Send Command execution", Severity.HIGH, "T1021.007"),
        (re.compile(r'az\s+vm\s+run-command\s+invoke', re.IGNORECASE),
         "Azure VM run-command invocation", Severity.HIGH, "T1021.007"),
        (re.compile(r'gcloud\s+compute\s+ssh\s+\S+@\S+', re.IGNORECASE),
         "GCP gcloud SSH remote access", Severity.MEDIUM, "T1021.007"),
        (re.compile(r'gcloud\s+compute\s+os-login\s+', re.IGNORECASE),
         "GCP OS Login API usage", Severity.MEDIUM, "T1021.007"),
        (re.compile(r'aws\s+ec2-instance-connect\s+send-ssh-public-key', re.IGNORECASE),
         "AWS EC2 Instance Connect key injection", Severity.HIGH, "T1021.007"),
        (re.compile(r'az\s+role\s+assignment\s+create\s+--assignee', re.IGNORECASE),
         "Azure RBAC role assignment for lateral movement", Severity.CRITICAL, "T1530"),
        (re.compile(r'aws\s+iam\s+put-role-policy.*--policy-document', re.IGNORECASE),
         "AWS IAM policy modification for privilege escalation", Severity.CRITICAL, "T1530"),
    ]

    CLOUD_ENUMERATION_PATTERNS = [
        (re.compile(r'aws\s+ec2\s+describe-instances\s+--all', re.IGNORECASE),
         "AWS EC2 instance enumeration across all regions", Severity.MEDIUM, "T1613"),
        (re.compile(r'aws\s+sts\s+get-caller-identity', re.IGNORECASE),
         "AWS STS identity enumeration", Severity.LOW, "T1069"),
        (re.compile(r'az\s+account\s+list', re.IGNORECASE),
         "Azure account enumeration", Severity.LOW, "T1069"),
        (re.compile(r'gcloud\s+projects\s+list', re.IGNORECASE),
         "GCP project enumeration", Severity.LOW, "T1069"),
    ]

    # Lateral Tool Transfer Detection (T1570)
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
    }

    # Configuration Management Abuse (T1072)
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

    CONFIG_MGMT_PATH_ANOMALIES = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "$HOME/.local/tmp",
    ]

    def should_skip(self) -> tuple:
        """Lateral movement detection runs in quick mode with lightweight process checks"""
        return False, ""

    def _is_legitimate_process_for_detection(self, proc: Dict) -> bool:
        """Check if a process is a known legitimate process that should skip certain detections.
        
        This is used to prevent false positives for common shell processes and interpreters
        that may execute scripts with patterns resembling scanning/discovery commands.
        
        Args:
            proc: Process dict with 'comm' field
            
        Returns:
            True if the process is known legitimate and should skip host discovery alerts
        """
        comm = proc.get("comm", "").lower()
        if not comm:
            return False
        
        # Get base name (handle paths like /usr/bin/bash)
        base_name = os.path.basename(comm)
        
        return base_name in self.LEGITIMATE_HOST_DISCOVERY_PROCESSES
    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze collected data for lateral movement indicators"""
        evidences = []
        
        from ..utils.fp_tracker import get_tracker
        tracker = get_tracker()
        tracker.record_detection('lateral_movement_analyzer', 1)
        
        try:
            # Quick mode: lightweight process-only check
            
            # Full mode: comprehensive analysis
            process_data = self._get_data(collected_data, "process")
            network_data = self._get_data(collected_data, "network")
            filesystem_data = self._get_data(collected_data, "filesystem") or {}

            if not process_data or not network_data:
                return evidences
            
            # SSH abuse detection (existing + enhanced)
            evidences.extend(self._detect_ssh_abuse(process_data, filesystem_data))
            
            # SSH hijacking detection (NEW - T1563.001)
            evidences.extend(self._detect_ssh_hijacking(process_data, filesystem_data))
            
            # Cloud service lateral movement detection (NEW - T1021.007)
            evidences.extend(self._detect_cloud_lateral_movement(process_data))
            
            # Remote service tunnel detection
            evidences.extend(self._detect_tunnel_tools(process_data, network_data))
            
            # Lateral tool transfer detection (NEW - T1570)
            evidences.extend(self._detect_tool_transfer(process_data))
            
            # Configuration management abuse detection (NEW - T1072)
            evidences.extend(self._detect_config_mgmt_abuse(process_data))
            
            # Container escape detection
            evidences.extend(self._detect_container_escape(process_data, filesystem_data))
            
            # Network scanning detection
            evidences.extend(self._detect_network_scanning(process_data))
            
            # Remote execution detection
            evidences.extend(self._detect_remote_execution(process_data))
            
            # Temporal correlation for multi-stage campaigns (NEW)
            evidences.extend(self._run_temporal_correlation(collected_data))
            
        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().warning(f"Lateral movement analysis error: {e}")
        
        return evidences

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
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
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

    def _detect_tunnel_tools(self, process_data: Dict, network_data: Dict) -> List[Evidence]:
        """Detect remote service tunnel tools"""
        evidences = []
        processes = process_data.get("processes", [])

        evidence_id_counter = 0
        
        # Check for tunnel tool processes
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            
            # Check process name
            if comm.lower() in self.TUNNEL_TOOL_PROCESSES:
                desc, severity, attack_id = self.TUNNEL_TOOL_PROCESSES[comm.lower()]
                evidence_id_counter += 1
                evidences.append(Evidence(
                    id=f"lateral_tunnel_tool_{evidence_id_counter}",
                    module=self.name,
                    title=f"Tunnel tool detected: {comm}",
                    description=f"{desc} - Process: {cmdline[:200]}",
                    severity=severity,
                    confidence=0.9,
                    attack_id=attack_id,
                    attack_tactic="Command and Control",
                    source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                    timestamp="",
                    raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "comm": comm},
                    remediation="Investigate tunnel tool usage and verify authorization",
                    evidence_details=EvidenceDetail(
                        pid=proc.get("pid"),
                        cmdline=cmdline[:500],
                        executable=proc.get("exe", ""),
                        user=proc.get("user", ""),
                        parent_pid=proc.get("ppid"),
                    ),
                    remediation_commands=[
                        f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                        f"kill -9 {proc.get('pid', 'PID')}",
                        f"netstat -tunap | grep {proc.get('pid', 'PID')}",
                        f"find / -name '{comm}' -type f 2>/dev/null",
                    ],
                ))
            else:
                # Check cmdline for tunnel tools
                for tool_name, (desc, severity, attack_id) in self.TUNNEL_TOOL_PROCESSES.items():
                    if tool_name in cmdline.lower():
                        evidence_id_counter += 1
                        evidences.append(Evidence(
                            id=f"lateral_tunnel_cmd_{evidence_id_counter}",
                            module=self.name,
                            title=f"Tunnel tool in command: {tool_name}",
                            description=f"{desc} - Command: {cmdline[:200]}",
                            severity=severity,
                            confidence=0.85,
                            attack_id=attack_id,
                            attack_tactic="Command and Control",
                            source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                            timestamp="",
                            raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                            remediation="Investigate tunnel tool usage and verify authorization",
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
                        break
        
        # Check reverse proxy patterns
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
                
            for pattern, title, severity, attack_id in self.REVERSE_PROXY_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_reverse_proxy_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Reverse proxy pattern: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.75,
                        attack_id=attack_id,
                        attack_tactic="Command and Control",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review proxy configuration and verify legitimacy",
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
        
        return evidences

    def _detect_container_escape(self, process_data: Dict, filesystem_data: Dict) -> List[Evidence]:
        """Detect container escape and lateral movement"""
        evidences = []
        processes = process_data.get("processes", [])
        files = filesystem_data.get("scanned_paths", [])
        
        evidence_id_counter = 0
        
        # Check container escape indicators
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
                
            for pattern, title, severity, attack_id in self.CONTAINER_ESCAPE_INDICATORS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_container_escape_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Container escape indicator: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.85,
                        attack_id=attack_id,
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review container security configuration and remove privileged options",
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
        
        # Check K8s lateral movement
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
                
            for pattern, title, severity, attack_id in self.K8S_LATERAL_MOVEMENT_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_k8s_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"K8s lateral movement: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.8,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Audit kubectl commands and review RBAC permissions",
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
        
        # Check Docker socket access
        docker_socket_paths = ["/var/run/docker.sock", "/var/run/containerd/containerd.sock"]
        for file_path in files:
            for socket_path in docker_socket_paths:
                if socket_path in file_path:
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_docker_socket_{evidence_id_counter}",
                        module=self.name,
                        title="Sensitive container socket accessed",
                        description=f"Access to {socket_path} detected",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        attack_id="T1611",
                        attack_tactic="Defense Evasion",
                        source_path=file_path,
                        timestamp="",
                        raw_data={"file": file_path},
                        remediation="Restrict Docker socket access to trusted users only",
                        evidence_details=EvidenceDetail(
                            file_path=file_path,
                            content=f"Container socket access: {socket_path}",
                        ),
                        remediation_commands=[
                            f"ls -la {file_path}",
                            f"stat {file_path}",
                            f"cat {file_path} 2>/dev/null | head -20",
                        ],
                    ))
        
        return evidences

    def _detect_network_scanning(self, process_data: Dict) -> List[Evidence]:
        """Detect network scanning activity"""
        evidences = []
        processes = process_data.get("processes", [])
        
        evidence_id_counter = 0
        
        # Check for scanning tools
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            
            # Check process name
            if comm.lower() in self.NETWORK_SCAN_TOOLS:
                desc, severity, attack_id = self.NETWORK_SCAN_TOOLS[comm.lower()]
                evidence_id_counter += 1
                evidences.append(Evidence(
                    id=f"lateral_scan_tool_{evidence_id_counter}",
                    module=self.name,
                    title=f"Network scanning tool: {comm}",
                    description=f"{desc} - Process: {cmdline[:200]}",
                    severity=severity,
                    confidence=0.9,
                    attack_id=attack_id,
                    attack_tactic="Discovery",
                    source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                    timestamp="",
                    raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "comm": comm},
                    remediation="Investigate scanning activity and verify authorization",
                    evidence_details=EvidenceDetail(
                        pid=proc.get("pid"),
                        cmdline=cmdline[:500],
                        executable=proc.get("exe", ""),
                        user=proc.get("user", ""),
                        parent_pid=proc.get("ppid"),
                    ),
                    remediation_commands=[
                        f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                        f"kill -9 {proc.get('pid', 'PID')}",
                        f"netstat -tunap | grep {proc.get('pid', 'PID')}",
                        f"find / -name '{comm}' -type f 2>/dev/null",
                    ],
                ))
            else:
                # Check cmdline for scanning tools
                for tool_name, (desc, severity, attack_id) in self.NETWORK_SCAN_TOOLS.items():
                    if tool_name in cmdline.lower():
                        evidence_id_counter += 1
                        evidences.append(Evidence(
                            id=f"lateral_scan_cmd_{evidence_id_counter}",
                            module=self.name,
                            title=f"Scanning tool in command: {tool_name}",
                            description=f"{desc} - Command: {cmdline[:200]}",
                            severity=severity,
                            confidence=0.85,
                            attack_id=attack_id,
                            attack_tactic="Discovery",
                            source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                            timestamp="",
                            raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                            remediation="Investigate scanning activity and verify authorization",
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
                        break
        
        # Check port scan patterns
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
                
            for pattern, title, severity, attack_id in self.PORT_SCAN_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_port_scan_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Port scan pattern: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.75,
                        attack_id=attack_id,
                        attack_tactic="Discovery",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review scanning activity and ensure it is authorized",
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
        
        # Check host discovery patterns
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            
            # Skip legitimate processes like bash/python that may run scripts with IP loops
            if self._is_legitimate_process_for_detection(proc):
                continue
                
            for pattern, title, severity, attack_id in self.HOST_DISCOVERY_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_host_disc_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Host discovery pattern: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.7,
                        attack_id=attack_id,
                        attack_tactic="Discovery",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review network discovery activity",
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
        
        return evidences

    def _detect_remote_execution(self, process_data: Dict) -> List[Evidence]:
        """Detect remote execution tool abuse"""
        evidences = []
        processes = process_data.get("processes", [])
        
        evidence_id_counter = 0
        
        # Check remote execution patterns
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
                
            # Standard remote execution
            for pattern, title, severity, attack_id in self.REMOTE_EXEC_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_remote_exec_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Remote execution: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.8,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Audit remote command execution and verify authorization",
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
                    break
            
            # K8s specific remote execution
            for pattern, title, severity, attack_id in self.K8S_REMOTE_EXEC_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_k8s_exec_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"K8s remote execution: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.8,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Audit kubectl commands and review RBAC permissions",
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
                    break
        
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
                            content=f"SSH agent socket: {file_path}",
                        ),
                        remediation_commands=[
                            f"ls -la {file_path}",
                            f"stat {file_path}",
                            f"cat {file_path} 2>/dev/null | head -20",
                        ],
                    ))
        
        return evidences

    def _detect_cloud_lateral_movement(self, process_data: Dict) -> List[Evidence]:
        """Detect cloud service lateral movement (T1021.007)"""
        evidences = []
        processes = process_data.get("processes", [])
        
        evidence_id_counter = 2000
        
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            
            for pattern, title, severity, attack_id in self.CLOUD_LATERAL_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_cloud_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Cloud lateral movement detected: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.9,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
                        remediation="Audit cloud CLI usage and verify authorization for cross-instance operations",
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
            
            for pattern, title, severity, attack_id in self.CLOUD_ENUMERATION_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_cloud_enum_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Cloud enumeration activity: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.75,
                        attack_id=attack_id,
                        attack_tactic="Discovery",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review cloud API calls for reconnaissance activity",
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
        
        return evidences

    def _detect_tool_transfer(self, process_data: Dict) -> List[Evidence]:
        """Detect lateral tool transfer via scp, rsync, nc (T1570)"""
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
                    has_large_file = any(ind in cmdline.lower() for ind in self.TRANSFER_HEURISTICS["large_file_indicators"])
                    has_encoding = any(enc in cmdline.lower() for enc in self.TRANSFER_HEURISTICS["encoding_patterns"])
                    
                    if has_large_file and has_encoding:
                        confidence = 0.95
                        title = f"{title} (high confidence: large file + encoding)"
                    
                    evidences.append(Evidence(
                        id=f"lateral_transfer_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Lateral tool transfer detected: {cmdline[:200]}",
                        severity=severity,
                        confidence=confidence,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
                        remediation="Investigate file transfer activity and verify authorization",
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
        
        return evidences

    def _detect_config_mgmt_abuse(self, process_data: Dict) -> List[Evidence]:
        """Detect configuration management tool abuse (T1072)"""
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
                    has_anomalous_path = any(path in cmdline for path in self.CONFIG_MGMT_PATH_ANOMALIES)
                    if has_anomalous_path:
                        confidence = 0.95
                        title = f"{title} (anomalous execution path)"
                    
                    evidences.append(Evidence(
                        id=f"lateral_config_mgmt_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Configuration management abuse: {cmdline[:200]}",
                        severity=severity,
                        confidence=confidence,
                        attack_id=attack_id,
                        attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
                        remediation="Audit configuration management tool usage and verify playbook/manifest integrity",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"),
                            cmdline=cmdline[:500],
                            executable=proc.get("exe", ""),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            "ss -tunap | head -20",
                        ],
                    ))
        
        return evidences

    def _run_temporal_correlation(self, collected_data: Dict) -> List[Evidence]:
        """Run temporal correlation engine for multi-stage campaign detection"""
        try:
            from .lateral_movement_correlator import LateralMovementCorrelator
            
            correlator = LateralMovementCorrelator(workspace_dir=self.workspace_dir)
            return correlator.analyze(collected_data)
        except (ImportError, OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().warning(f"Temporal correlation error: {e}")
            return []
