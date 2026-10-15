"""Remote Access Trojan Detection Analyzer"""
import os
import re
from typing import List
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer

def _is_private_ip(ip: str) -> bool:
    """Check if IP is private using standard library."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except (ValueError, TypeError):
        return False


class RatAnalyzer(BaseAnalyzer):
    """Remote Access Trojan (RAT) Detection Analyzer

    Detection capabilities:
    1. Known RAT family signature detection (process name + file path + port)
    2. C2 communication behavior signature detection (anomalous protocol ports, IRC connections)
    3. Process behavior anomaly combination detection (multi-dimensional correlation analysis)
    """
    name = "rat_analyzer"
    timeout = 30
    estimated_time = 1.0
    analyzer_type = BaseAnalyzer.CRITICAL
    required_collectors = ["process", "network"]

    # Known RAT family signature library
    # {family: {"process_names": [...], "ports": [...], "file_patterns": [...], "severity": ...}}
    RAT_FAMILIES = {
        "Cobalt Strike Beacon": {
            "process_names": ["beacon", "artifact"],
            "file_patterns": [".cobaltstrike", ".beacon", "cobaltstrike"],
            "ports": [50050],
            "severity": Severity.CRITICAL,
            "attack_id": "T1219",
        },
        "Meterpreter": {
            "process_names": ["meterpreter", "metsvc"],
            "file_patterns": [".msf", "meterpreter"],
            "ports": [4444, 4445],
            "severity": Severity.CRITICAL,
            "attack_id": "T1219",
        },
        "Linux.Mirai": {
            "process_names": [".mirai", "dvrhelper"],
            "file_patterns": [".mirai"],
            "ports": [23, 48101],
            "severity": Severity.CRITICAL,
            "attack_id": "T1583.005",
        },
        "Linux.Tsunami": {
            "process_names": ["tsunami", "kaiten"],
            "file_patterns": [".tsunami"],
            "ports": [6667],
            "severity": Severity.CRITICAL,
            "attack_id": "T1583.005",
        },
        "Rekoobe": {
            "process_names": [],
            "file_patterns": [".rekoobe"],
            "ports": [],
            "severity": Severity.CRITICAL,
            "attack_id": "T1219",
        },
        "RotaJakiro": {
            "process_names": ["systemd-daemon"],
            "file_patterns": [".X11-unix/.X0"],
            "ports": [],
            "severity": Severity.CRITICAL,
            "attack_id": "T1219",
        },
    }

    # IRC ports (commonly used for botnet C2)
    IRC_PORTS = {6667, 6668, 6669, 6697, 7000, 7070}


    # Common shell process names
    SHELL_PROCESSES = {"bash", "sh", "zsh", "ksh", "csh", "tcsh", "dash", "fish"}

    # Known tunnel/proxy tools
    TUNNEL_TOOLS = {"socat", "nc", "netcat", "ncat", "dnscat", "iodine", "ptunnel", "sslh"}

    # RAT command line signature patterns
    RAT_CMDLINE_PATTERNS = [
        (re.compile(r'import\s+socket.*connect', re.DOTALL), "Python RAT", Severity.HIGH),
        (re.compile(r"require\s+'socket'.*TCPSocket", re.DOTALL), "Ruby RAT", Severity.HIGH),
        (re.compile(r'Socket\s*\(\s*AF_INET'), "C Socket RAT", Severity.HIGH),
    ]

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute remote access trojan detection"""
        evidences = []

        process_data = self._get_data(collected_data, "process")
        network_data = self._get_data(collected_data, "network")

        if not process_data:
            return evidences

        # Quick mode: only check known RAT process names and C2 ports

        processes = process_data.get("processes", [])

        # 1. Known RAT family signature detection
        evidences.extend(self._detect_known_rats(processes))

        # 2. C2 communication behavior signature detection
        if network_data:
            evidences.extend(self._detect_c2_behavior(network_data, processes))

        # 3. Process behavior anomaly combination detection
        if network_data:
            evidences.extend(self._detect_behavior_combinations(processes, network_data))

        return evidences
    def _detect_known_rats(self, processes: list) -> List[Evidence]:
        """Detect known RAT families"""
        evidences = []
        detected_families = set()

        for proc in processes:
            comm = proc.get("comm", "").lower()
            exe = proc.get("exe", "").lower()
            pid = proc.get("pid", 0)

            for family, traits in self.RAT_FAMILIES.items():
                if family in detected_families:
                    continue

                # Process name match
                name_match = comm in [n.lower() for n in traits["process_names"]]

                # File path match
                file_match = any(
                    pat.lower() in exe for pat in traits["file_patterns"]
                ) if exe else False

                if name_match or file_match:
                    detected_families.add(family)
                    evidences.append(self._create_evidence(
                        severity=traits["severity"],
                        attack_id=traits["attack_id"],
                        title=f"已知RAT检测: {family}",
                        description=f"检测到已知远控木马 {family}: 进程 '{proc.get('comm', '')}' "
                                    f"(PID {pid})"
                                    f"{', 文件路径匹配' if file_match else ''}"
                                    f"{', 进程名匹配' if name_match else ''}",
                        confidence=0.9,
                        raw_data={
                            "pid": pid,
                            "comm": proc.get("comm", ""),
                            "exe": proc.get("exe", ""),
                            "cmdline": proc.get("cmdline", "")[:500],
                            "rat_family": family,
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))

        # Check filesystem for RAT files
        for family, traits in self.RAT_FAMILIES.items():
            if family in detected_families:
                continue
            for file_pat in traits["file_patterns"]:
                for check_dir in ["/tmp", "/var/tmp", "/dev/shm"]:
                    check_path = os.path.join(check_dir, file_pat)
                    if os.path.exists(check_path):
                        detected_families.add(family)
                        evidences.append(self._create_evidence(
                            severity=traits["severity"],
                            attack_id=traits["attack_id"],
                            title=f"RAT文件检测: {family}",
                            description=f"在可疑路径发现 {family} 相关文件: {check_path}",
                            confidence=0.85,
                            source_path=check_path,
                            raw_data={
                                "path": check_path,
                                "rat_family": family,
                            },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Terminate remote access trojan processes immediately",
                        "Block C2 communication endpoints in firewall",
                        "Audit system for persistence mechanisms and backdoors",
                        "Perform full malware scan and forensic analysis"
                    ]))
                        break

        return evidences

    # Process classification sets
    WEB_PROCESSES = {
        "curl", "wget", "apt", "apt-get", "yum", "pip", "pip3",
        "npm", "node", "python", "python3", "java",
        "nginx", "apache2", "httpd",
        "firefox", "chrome", "chromium",
        "git", "docker", "containerd",
    }

    DNS_PROCESSES = {"systemd-resolve", "dnsmasq", "named", "unbound", "coredns"}

    REVERSE_SHELL_PROCESSES = {
        "bash", "sh", "zsh", "ksh", "csh", "tcsh", "dash", "ash",
        "nc", "netcat", "ncat",
        "python", "python3", "python2", "ruby", "perl", "php",
        "socat", "dnscat", "iodine", "httpstool", "chisel",
    }

    REVERSE_SHELL_PORTS = {4444, 4445, 5555, 6666, 1337, 31337, 12345, 54321}

    SUSPICIOUS_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/root"]

    def _is_outbound_connection(self, conn: dict) -> bool:
        """Check if a connection is outbound (not private IP)."""
        remote_ip = conn.get("remote_ip", "")
        if _is_private_ip(remote_ip) or remote_ip in ("0.0.0.0", "::"):
            return False
        state = conn.get("state", "")
        proto = conn.get("proto", "")
        return proto == "udp" or state in ("ESTABLISHED", "SYN_SENT")

    def _is_suspicious_path(self, exe: str) -> bool:
        """Check if executable path is suspicious."""
        if not exe:
            return False
        return any(exe.startswith(p) for p in self.SUSPICIOUS_PATHS)

    def _classify_process_type(self, proc_comm: str) -> tuple:
        """Classify process type for reverse shell detection.

        Returns:
            (process_type, attack_id, title_prefix, severity, confidence)
            process_type: 'shell', 'script', 'tunnel', or None
        """
        shell_map = [
            (self.SHELL_PROCESSES, 'shell', "T1059.004", "反弹 Shell 检测", Severity.CRITICAL, 0.9),
            (["python", "perl", "ruby", "php", "node"], 'script', "T1059.006", "脚本反弹 Shell 检测", Severity.CRITICAL, 0.85),
            (self.TUNNEL_TOOLS, 'tunnel', "T1572", "隧道工具检测", Severity.HIGH, 0.7),
        ]

        for items, ptype, attack_id, title, severity, confidence in shell_map:
            if any(item in proc_comm for item in items):
                return ptype, attack_id, title, severity, confidence

        return None, "T1059", "可疑反弹 Shell 检测", Severity.HIGH, 0.7

    def _classify_reverse_shell_process(self, proc_comm: str, cmdline: str) -> tuple:
        """Classify process for reverse shell detection.

        Returns:
            (is_match, attack_id, title_prefix, severity_level, confidence)
        """
        has_socket_connect = "socket" in cmdline and "connect" in cmdline
        ptype, attack_id, title_prefix, severity, confidence = self._classify_process_type(proc_comm)

        if ptype is not None:
            return True, attack_id, title_prefix, severity, confidence

        if has_socket_connect:
            return True, attack_id, title_prefix, severity, confidence

        return False, "", "", Severity.MEDIUM, 0.0

    def _check_irc_connection(self, conn: dict, reported_pids: set, pid_map: dict) -> List[Evidence]:
        """Check for IRC port connections (commonly used for botnet C2)."""
        evidences = []
        remote_port = conn.get("remote_port", 0)

        if remote_port not in self.IRC_PORTS:
            return evidences

        pid = conn.get("pid", 0)
        key = f"irc:{pid}"
        if key in reported_pids:
            return evidences

        reported_pids.add(key)
        process_name = conn.get("process_name", "")

        evidences.append(self._create_evidence(
            severity=Severity.HIGH,
            attack_id="T1071.001",
            title=f"IRC连接检测: {process_name} -> 端口 {remote_port}",
            description=f"进程 {process_name} (PID {pid}) 连接到IRC端口 "
                        f"{remote_port}，可能为IRC botnet C2通信",
            confidence=0.75,
            raw_data={
                "pid": pid,
                "process_name": process_name,
                "remote_ip": conn.get("remote_ip", ""),
                "remote_port": remote_port,
            },
            evidence_details=EvidenceDetail(pid=pid),
            remediation_commands=[
                "Review process execution chain",
                "Scan system for additional indicators"
            ]))

        return evidences

    def _check_reverse_shell(self, conn: dict, reported_pids: set, pid_map: dict) -> List[Evidence]:
        """Check for reverse shell connections."""
        evidences = []
        remote_port = conn.get("remote_port", 0)

        if remote_port not in self.REVERSE_SHELL_PORTS:
            return evidences

        pid = conn.get("pid", 0)
        key = f"reverse_shell:{pid}"
        if key in reported_pids:
            return evidences

        process_name = conn.get("process_name", "")
        proc_info = pid_map.get(pid, {})
        proc_comm = proc_info.get("comm", "").lower() if proc_info else process_name.lower()
        cmdline = proc_info.get("cmdline", "").lower() if proc_info else ""

        is_match, attack_id, title_prefix, severity_level, confidence = \
            self._classify_reverse_shell_process(proc_comm, cmdline)

        if not is_match:
            return evidences

        reported_pids.add(key)

        # Determine process type for evidence description
        ptype, _, _, _, _ = self._classify_process_type(proc_comm)
        has_socket = "socket" in cmdline and "connect" in cmdline
        type_desc = {
            'shell': 'Shell',
            'script': '脚本语言',
            'tunnel': '隧道工具',
        }.get(ptype, '可疑' if has_socket else '可疑')

        evidences.append(self._create_evidence(
            severity=severity_level,
            attack_id=attack_id,
            title=f"{title_prefix}: {process_name} -> 端口 {remote_port}",
            description=f"{type_desc}进程 {process_name} (PID {pid}) "
                        f"连接到常见反弹 Shell 端口 {remote_port}，可能为远控木马通信",
            confidence=confidence,
            raw_data={
                "pid": pid,
                "process_name": process_name,
                "remote_ip": conn.get("remote_ip", ""),
                "remote_port": remote_port,
                "is_shell": ptype == 'shell',
                "is_script_lang": ptype == 'script',
                "has_socket_connect": has_socket,
            },
            evidence_details=EvidenceDetail(pid=pid),
            remediation_commands=[
                "Review process execution chain",
                "Scan system for additional indicators"
            ]))

        return evidences

    def _check_http_suspect(self, conn: dict, reported_pids: set, pid_map: dict) -> List[Evidence]:
        """Check for non-web processes using HTTP/HTTPS ports from suspicious paths."""
        evidences = []
        remote_port = conn.get("remote_port", 0)

        if remote_port not in (80, 443):
            return evidences

        pid = conn.get("pid", 0)
        process_name = conn.get("process_name", "")

        if not process_name or process_name.lower() in self.WEB_PROCESSES:
            return evidences

        proc_info = pid_map.get(pid, {})
        exe = proc_info.get("exe", "")

        if not self._is_suspicious_path(exe):
            return evidences

        key = f"http_suspect:{pid}"
        if key in reported_pids:
            return evidences

        reported_pids.add(key)

        evidences.append(self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1071.001",
            title=f"可疑HTTP外联: {process_name}",
            description=f"非Web进程 {process_name} (PID {pid}) 从可疑路径 "
                        f"{exe} 发起HTTP连接",
            confidence=0.6,
            raw_data={
                "pid": pid,
                "process_name": process_name,
                "exe": exe,
                "remote_port": remote_port,
            },
            evidence_details=EvidenceDetail(pid=pid),
            remediation_commands=[
                "Review process execution chain",
                "Scan system for additional indicators"
            ]))

        return evidences

    def _check_dns_suspect(self, conn: dict, reported_pids: set, pid_map: dict) -> List[Evidence]:
        """Check for non-DNS processes using DNS port 53."""
        evidences = []
        remote_port = conn.get("remote_port", 0)

        if remote_port != 53:
            return evidences

        pid = conn.get("pid", 0)
        process_name = conn.get("process_name", "")

        if not process_name or process_name.lower() in self.DNS_PROCESSES:
            return evidences

        key = f"dns_suspect:{pid}"
        if key in reported_pids:
            return evidences

        reported_pids.add(key)

        evidences.append(self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1071.004",
            title=f"可疑DNS连接: {process_name}",
            description=f"非DNS进程 {process_name} (PID {pid}) 连接到DNS端口53，"
                        f"可能为DNS隧道",
            confidence=0.5,
            raw_data={
                "pid": pid,
                "process_name": process_name,
                "remote_ip": conn.get("remote_ip", ""),
            },
            evidence_details=EvidenceDetail(pid=pid),
            remediation_commands=[
                "Review process execution chain",
                "Scan system for additional indicators"
            ]))

        return evidences

    def _detect_c2_behavior(self, network_data: dict, processes: list) -> List[Evidence]:
        """Detect C2 communication behavior signatures."""
        evidences = []

        # Build PID to process info mapping
        pid_map = {p.get("pid"): p for p in processes}

        # Collect outbound connections
        outbound_conns = []
        for conn_list_key in ["tcp_connections", "tcp6_connections", "udp_connections", "udp6_connections"]:
            for conn in network_data.get(conn_list_key, []):
                if self._is_outbound_connection(conn):
                    outbound_conns.append(conn)

        reported_pids = set()

        for conn in outbound_conns:
            evidences.extend(self._check_irc_connection(conn, reported_pids, pid_map))
            evidences.extend(self._check_reverse_shell(conn, reported_pids, pid_map))
            evidences.extend(self._check_http_suspect(conn, reported_pids, pid_map))
            evidences.extend(self._check_dns_suspect(conn, reported_pids, pid_map))

        return evidences

    def _detect_behavior_combinations(self, processes: list, network_data: dict) -> List[Evidence]:
        """Detect process behavior anomaly combinations"""
        evidences = []

        # Collect PIDs with external connections
        outbound_pids = set()
        for conn_list_key in ["tcp_connections", "tcp6_connections"]:
            for conn in network_data.get(conn_list_key, []):
                state = conn.get("state", "")
                if state not in ("ESTABLISHED", "SYN_SENT"):
                    continue
                remote_ip = conn.get("remote_ip", "")
                if not _is_private_ip(remote_ip) and remote_ip not in ("0.0.0.0", "::"):
                    pid = conn.get("pid", 0)
                    if pid:
                        outbound_pids.add(pid)

        reported_pids = set()

        for proc in processes:
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            exe = proc.get("exe", "")
            cmdline = proc.get("cmdline", "")
            uid = proc.get("uid", -1)

            has_outbound = pid in outbound_pids
            if not has_outbound:
                continue
            if pid in reported_pids:
                continue

            # Combination 1: deleted binary + outbound connection = CRITICAL
            if exe and "(deleted)" in exe:
                reported_pids.add(pid)
                evidences.append(self._create_evidence(
                    severity=Severity.CRITICAL,
                    attack_id="T1071",
                    title=f"已删除二进制外联: {comm} (PID {pid})",
                    description=f"已删除二进制的进程 '{comm}' (PID {pid}) 具有外部网络连接，"
                                f"高度疑似远控木马",
                    confidence=0.9,
                    raw_data={
                        "pid": pid, "comm": comm, "exe": exe,
                        "behavior": "deleted_binary+outbound",
                    },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                continue

            # Combination 2: hidden path running + outbound connection = HIGH
            suspicious_paths = ["/tmp", "/var/tmp", "/dev/shm"]
            if exe and any(exe.startswith(p) for p in suspicious_paths):
                # Further check: whether started from hidden file
                basename = os.path.basename(exe) if exe else ""
                if basename.startswith("."):
                    reported_pids.add(pid)
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1071",
                        title=f"隐藏路径进程外联: {comm} (PID {pid})",
                        description=f"从隐藏路径启动的进程 '{comm}' ({exe}) 具有外部网络连接",
                        confidence=0.8,
                        raw_data={
                            "pid": pid, "comm": comm, "exe": exe,
                            "behavior": "hidden_path+outbound",
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                    continue

            # Combination 3: short process name (1-2 chars) + outbound connection + root = HIGH
            if len(comm) <= 2 and uid == 0 and cmdline:
                reported_pids.add(pid)
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1071",
                    title=f"可疑短名进程外联: '{comm}' (PID {pid})",
                    description=f"极短进程名 '{comm}' (PID {pid}) 以root权限运行且具有外部连接",
                    confidence=0.7,
                    raw_data={
                        "pid": pid, "comm": comm, "exe": exe,
                        "uid": uid,
                        "behavior": "short_name+root+outbound",
                    },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))

        return evidences
