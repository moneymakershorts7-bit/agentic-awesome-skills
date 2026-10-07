"""Cryptomining Detection Analyzer"""
import re
import threading
from typing import List
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer

_ioc_loader_cache = None
_ioc_loader_lock = threading.Lock()

def _get_ioc_loader():
    """Lazy import IoCLoader to get mining port and private IP check functions."""
    global _ioc_loader_cache
    if _ioc_loader_cache is None:
        with _ioc_loader_lock:
            if _ioc_loader_cache is None:
                from ..threat_intel.ioc_loader import get_loader
                _ioc_loader_cache = get_loader()
    return _ioc_loader_cache


def _is_mining_port(port: int) -> bool:
    """Check if port is a mining port using IoCLoader."""
    loader = _get_ioc_loader()
    return loader.lookup_mining_port(port)


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private using standard library + IoCLoader cloud metadata check."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Check cloud metadata IPs (from IoCLoader)
        loader = _get_ioc_loader()
        if loader.is_cloud_metadata_ip(ip):
            return True
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except (ValueError, TypeError):
        return False


class MiningAnalyzer(BaseAnalyzer):
    """Cryptomining Detection Analyzer

    Detection capabilities:
    1. High CPU usage process detection
    2. Known miner process name detection
    3. Mining command-line argument signature detection
    4. Mining pool connection detection
    5. Cryptocurrency wallet address detection
    """
    name = "mining_analyzer"
    estimated_time = 1.0  # Reduced for quick mode (known miner check only)
    analyzer_type = BaseAnalyzer.CRITICAL
    required_collectors = ["process", "network"]

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    # High CPU threshold
    @property
    def HIGH_CPU_THRESHOLD(self):
        return self._get_config("thresholds.high_cpu_threshold", 80.0)

    @property
    def MIN_RUNTIME_SECONDS(self):
        return self._get_config("thresholds.min_runtime_seconds", 300)

    # Legitimate high CPU process whitelist
    CPU_WHITELIST = {
        "gcc", "g++", "cc1", "cc1plus", "make", "cmake",
        "python3", "python", "java", "javac", "node",
        "npm", "cargo", "rustc", "go", "clang",
        "mysqld", "postgres", "redis-server", "mongod",
        "nginx", "apache2", "httpd",
        "dockerd", "containerd",
        "xorg", "gnome-shell", "kwin",
        "stress", "stress-ng",  # Testing tools
        "ffmpeg", "handbrake",  # Video encoding
    }

    # Desktop environment services whitelist (file indexing, search, etc.)
    DESKTOP_SERVICES_WHITELIST = {
        # GNOME Desktop services
        "tracker-miner-fs",      # GNOME file indexing service
        "tracker-miner-f",       # GNOME file indexer (legacy)
        "tracker-extract",       # GNOME metadata extractor
        "tracker",               # Tracker daemon
        "gnome-shell",           # GNOME shell
        "mutter",                # GNOME window manager
        "nautilus",              # GNOME file manager
        "gnome-terminal-",       # GNOME terminal
        # KDE Plasma services
        "baloo_file",            # KDE file indexing
        "baloo_file_extractor",  # KDE file extractor
        "krunner",               # KDE run dialog
        "plasmashell",           # KDE plasma shell
        "dolphin",               # KDE file manager
        # Common system services
        "find",                  # System search tool
        "locate",                # File database lookup
        "updatedb",              # Update file database
        "mlocate-db",            # Mlocate database
    }

    # Known miner program names (exact match)
    KNOWN_MINERS = {
        "xmrig": ("XMRig", Severity.CRITICAL),
        "xmr-stak": ("XMR-Stak", Severity.CRITICAL),
        "minerd": ("CPUMiner", Severity.CRITICAL),
        "minergate": ("MinerGate", Severity.CRITICAL),
        "cpuminer": ("CPUMiner", Severity.CRITICAL),
        "ccminer": ("CCMiner", Severity.CRITICAL),
        "ethminer": ("Ethminer", Severity.CRITICAL),
        "cgminer": ("CGMiner", Severity.CRITICAL),
        "bfgminer": ("BFGMiner", Severity.CRITICAL),
        "sgminer": ("SGMiner", Severity.CRITICAL),
        "nbminer": ("NBMiner", Severity.CRITICAL),
        "phoenixminer": ("PhoenixMiner", Severity.CRITICAL),
        "lolminer": ("LOLMiner", Severity.CRITICAL),
        "gminer": ("GMiner", Severity.CRITICAL),
        "t-rex": ("T-Rex", Severity.CRITICAL),
        # Common variants
        "kdevtmpfsi": ("Kdevtmpfsi挖矿变种", Severity.CRITICAL),
        "kinsing": ("Kinsing挖矿木马", Severity.CRITICAL),
        "sysrv": ("Sysrv挖矿蠕虫", Severity.CRITICAL),
        "dbused": ("Mining disguised process", Severity.HIGH),
        "solrd": ("Mining disguised process", Severity.HIGH),
    }

    # Miner process name fuzzy match patterns
    MINER_NAME_PATTERNS = [
        re.compile(r'miner', re.IGNORECASE),
        re.compile(r'\.sysupdate$'),
        re.compile(r'\.networkservice$'),
    ]

    # Mining command-line argument signatures
    MINING_CMDLINE_PATTERNS = [
        (re.compile(r'--algo\s', re.IGNORECASE), "Mining algorithm argument"),
        (re.compile(r'-a\s+cryptonight', re.IGNORECASE), "CryptoNight算法"),
        (re.compile(r'stratum\+tcp://', re.IGNORECASE), "Stratum矿池协议"),
        (re.compile(r'stratum\+ssl://', re.IGNORECASE), "Stratum SSL矿池协议"),
        (re.compile(r'--donate-level', re.IGNORECASE), "Mining donation argument"),
        (re.compile(r'-o\s+pool\.', re.IGNORECASE), "Pool connection argument"),
        (re.compile(r'--url\s+.*pool', re.IGNORECASE), "矿池URL参数"),
        (re.compile(r'--coin\s', re.IGNORECASE), "Coin type argument"),
        (re.compile(r'--randomx', re.IGNORECASE), "RandomX算法"),
    ]

    # Cryptocurrency wallet address regex
    WALLET_PATTERNS = [
        # Monero (XMR) - 95 characters, starts with 4
        (re.compile(r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}'), "Monero(XMR)"),
        # Bitcoin (BTC) - starts with 1/3
        (re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'), "Bitcoin(BTC)"),
        # Bitcoin Bech32
        (re.compile(r'bc1[a-z0-9]{39,59}'), "Bitcoin(BTC-Bech32)"),
        # Ethereum (ETH) - starts with 0x, 42 characters
        (re.compile(r'0x[0-9a-fA-F]{40}'), "Ethereum(ETH)"),
    ]
    
    # Processes that should be excluded from wallet detection
    WALLET_DETECTION_EXCLUSIONS = {
        'containerd-shim',    # Container runtime (hash strings in args)
        'containerd',         # Container daemon
        'dockerd',            # Docker daemon
        'runc',               # OCI runtime
        'kubelet',            # Kubernetes agent
        'kube-proxy',         # Kubernetes proxy
        'python3',            # Python (often has hash-like args)
        'python',             # Python 2
        'node',               # Node.js
        'java',               # Java
    }

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute cryptomining detection analysis"""
        evidences = []

        process_data = self._get_data(collected_data, "process")
        network_data = self._get_data(collected_data, "network")

        if not process_data:
            return evidences

        # Quick mode: only check known miner names and mining cmdline

        processes = process_data.get("processes", [])

        # 1. Known miner process name detection
        evidences.extend(self._detect_known_miners(processes))

        # 2. Miner command-line argument detection
        evidences.extend(self._detect_mining_cmdline(processes))

        # 3. High CPU usage process detection
        evidences.extend(self._detect_high_cpu(processes))

        # 4. Mining pool connection detection
        if network_data:
            evidences.extend(self._detect_mining_connections(network_data))

        # 5. Wallet address detection
        evidences.extend(self._detect_wallet_addresses(processes))

        return evidences
    def _detect_known_miners(self, processes: list) -> List[Evidence]:
        """Detect known miner program names"""
        evidences = []
        for proc in processes:
            comm = proc.get("comm", "").lower()
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")

            # Exact match
            if comm in self.KNOWN_MINERS:
                miner_name, severity = self.KNOWN_MINERS[comm]
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1496",
                    title=f"挖矿程序检测: {miner_name}",
                    description=f"检测到已知挖矿程序 {miner_name} 进程 '{proc.get('comm', '')}' "
                                f"(PID {pid})",
                    confidence=0.95,
                    raw_data={
                        "pid": pid,
                        "comm": proc.get("comm", ""),
                        "cmdline": cmdline,
                        "miner_family": miner_name,
                        "cpu_percent": proc.get("cpu_percent", 0),
                    },
                    evidence_details=EvidenceDetail(
                        pid=pid,
                        cmdline=cmdline[:500] if cmdline else None,
                        executable=proc.get("exe", "") if proc.get("exe") else None,
                        user=str(proc.get("uid", "")) if proc.get("uid") else None,
                        parent_pid=proc.get("ppid", 0),
                    ),
                    remediation_commands=[
                        f"kill -9 {pid}",
                        f"cat /proc/{pid}/cmdline | tr '\\0' ' '",
                        f"ls -la /proc/{pid}/exe 2>/dev/null",
                        "Check for other mining processes and remove them"
                    ]
                ))
                continue

            # Fuzzy match
            for pattern in self.MINER_NAME_PATTERNS:
                if pattern.search(comm):
                    # Exclude legitimate processes (CPU whitelist)
                    if comm in self.CPU_WHITELIST:
                        continue
                    # Exclude desktop environment services
                    if comm in self.DESKTOP_SERVICES_WHITELIST:
                        continue
                    # Additional check: verify mining indicators
                    if not self._verify_mining_indicators(proc):
                        continue
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1496",
                        title=f"疑似挖矿进程名: {proc.get('comm', '')}",
                        description=f"进程名 '{proc.get('comm', '')}' (PID {pid}) 匹配挖矿特征pattern",
                        confidence=0.5,
                        raw_data={
                            "pid": pid,
                            "comm": proc.get("comm", ""),
                            "cmdline": cmdline,
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=cmdline[:500] if cmdline else None,
                            executable=proc.get("exe", "") if proc.get("exe") else None,
                        ),
                        remediation_commands=[
                            f"cat /proc/{pid}/cmdline | tr '\\0' ' '",
                            f"ls -la /proc/{pid}/exe 2>/dev/null",
                            "Verify process legitimacy"
                        ]
                    ))
                    break

        return evidences

    def _verify_mining_indicators(self, proc: dict) -> bool:
        """Verify if a process has multiple mining indicators
        
        Returns True if at least 2 indicators are present:
        1. High CPU usage (>80%)
        2. Suspicious executable location (/tmp, /var/tmp, etc.)
        3. Mining-related command-line arguments
        
        This reduces false positives from legitimate processes like tracker-miner-fs
        """
        indicators = 0
        
        # 1. High CPU usage
        cpu_percent = proc.get("cpu_percent", 0)
        if cpu_percent > self.HIGH_CPU_THRESHOLD:
            indicators += 1
        
        # 2. Suspicious location
        exe_path = proc.get("exe", "") or proc.get("cwd", "")
        if self._is_suspicious_location(exe_path):
            indicators += 1
        
        # 3. Mining command-line arguments
        cmdline = proc.get("cmdline", "")
        if cmdline:
            for pattern, _ in self.MINING_CMDLINE_PATTERNS:
                if pattern.search(cmdline):
                    indicators += 1
                    break
        
        # Need at least 2 indicators to flag as mining
        return indicators >= 2

    def _is_suspicious_location(self, path: str) -> bool:
        """Check if the executable path is suspicious"""
        if not path:
            return False
        suspicious_prefixes = [
            "/tmp/", "/var/tmp/", "/dev/shm/",
            "/.cache/", "/.local/tmp/",
        ]
        return any(path.startswith(prefix) for prefix in suspicious_prefixes)

    def _detect_mining_cmdline(self, processes: list) -> List[Evidence]:
        """Detect mining parameters in command lines"""
        evidences = []
        reported_pids = set()

        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            pid = proc.get("pid", 0)
            if pid in reported_pids:
                continue

            matched_patterns = []
            for pattern, desc in self.MINING_CMDLINE_PATTERNS:
                if pattern.search(cmdline):
                    matched_patterns.append(desc)

            if matched_patterns:
                reported_pids.add(pid)
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1496",
                    title=f"挖矿命令行参数: {proc.get('comm', '')}",
                    description=f"进程 '{proc.get('comm', '')}' (PID {pid}) 命令行包含挖矿特征: "
                                f"{', '.join(matched_patterns)}",
                    confidence=0.85,
                    raw_data={
                        "pid": pid,
                        "comm": proc.get("comm", ""),
                        "cmdline": cmdline[:500],
                        "matched_patterns": matched_patterns,
                    },
                    evidence_details=EvidenceDetail(
                        pid=pid,
                        cmdline=cmdline[:500] if cmdline else None,
                        executable=proc.get("exe", "") if proc.get("exe") else None,
                    ),
                    remediation_commands=[
                        f"kill -9 {pid}",
                        f"cat /proc/{pid}/cmdline | tr '\\0' ' '",
                        "Check for mining pool connections",
                        "Remove mining software"
                    ]
                ))

        return evidences

    def _detect_high_cpu(self, processes: list) -> List[Evidence]:
        """Detect high CPU usage processes"""
        evidences = []

        for proc in processes:
            cpu_percent = proc.get("cpu_percent", 0)
            # Handle None and non-numeric values
            if cpu_percent is None:
                cpu_percent = 0
            elif isinstance(cpu_percent, str):
                try:
                    cpu_percent = float(cpu_percent)
                except (ValueError, TypeError):
                    cpu_percent = 0
            runtime = proc.get("runtime_seconds", 0)
            if runtime is None:
                runtime = 0
            comm = proc.get("comm", "")
            pid = proc.get("pid", 0)

            if cpu_percent < self.HIGH_CPU_THRESHOLD:
                continue
            if runtime < self.MIN_RUNTIME_SECONDS:
                continue
            # Whitelist exclusion
            if comm.lower() in self.CPU_WHITELIST:
                continue
            # Kernel thread exclusion
            if not proc.get("cmdline", ""):
                continue

            evidences.append(self._create_evidence(
                severity=Severity.HIGH,
                attack_id="T1496",
                title=f"高CPU占用进程: {comm} ({cpu_percent:.1f}%)",
                description=f"进程 '{comm}' (PID {pid}) CPU占用 {cpu_percent:.1f}%，"
                            f"running {runtime:.0f} seconds, suspected mining",
                confidence=0.7,
                raw_data={
                    "pid": pid,
                    "comm": comm,
                    "cmdline": proc.get("cmdline", "")[:500],
                    "cpu_percent": cpu_percent,
                    "runtime_seconds": runtime,
                    "mem_rss_kb": proc.get("mem_rss_kb", 0),
                },
                evidence_details=EvidenceDetail(
                    pid=pid,
                    cmdline=proc.get("cmdline", "")[:500] if proc.get("cmdline") else None,
                    executable=proc.get("exe", "") if proc.get("exe") else None,
                    user=str(proc.get("uid", "")) if proc.get("uid") else None,
                    parent_pid=proc.get("ppid", 0),
                ),
                remediation_commands=[
                    f"cat /proc/{pid}/cmdline | tr '\\0' ' '",
                    f"ls -la /proc/{pid}/exe 2>/dev/null",
                    "Check process origin and authorization",
                    "Monitor CPU usage over time"
                ]
            ))

        return evidences

    def _detect_mining_connections(self, network_data: dict) -> List[Evidence]:
        """Detect mining pool port connections"""
        evidences = []
        reported = set()

        for conn_list_key in ["tcp_connections", "tcp6_connections"]:
            for conn in network_data.get(conn_list_key, []):
                state = conn.get("state", "")
                if state not in ("ESTABLISHED", "SYN_SENT"):
                    continue

                remote_ip = conn.get("remote_ip") or ""
                remote_port = conn.get("remote_port") or 0

                if _is_private_ip(remote_ip) or remote_ip in ("0.0.0.0", "::"):
                    continue

                if _is_mining_port(remote_port):
                    key = f"{remote_ip}:{remote_port}"
                    if key not in reported:
                        reported.add(key)
                        process_name = conn.get("process_name", "unknown")
                        pid = conn.get("pid", 0)
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1496",
                            title=f"矿池端口连接: {remote_ip}:{remote_port}",
                            description=f"Process {process_name} (PID {pid}) connected to common mining pool port "
                                        f"{remote_port}",
                            confidence=0.75,
                            raw_data={
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "process_name": process_name,
                                "pid": pid,
                            },
                            evidence_details=EvidenceDetail(
                                pid=pid,
                                executable=process_name if process_name != "unknown" else None,
                            ),
                            remediation_commands=[
                                f"kill -9 {pid}" if pid > 0 else "Identify and stop the mining process",
                                f"netstat -tunap | grep {remote_port}",
                                "Block mining pool IP at firewall",
                                "Scan for mining software and remove it"
                            ]
                        ))

        return evidences

    def _detect_wallet_addresses(self, processes: list) -> List[Evidence]:
        """Detect cryptocurrency wallet addresses in process command lines"""
        evidences = []
        reported_pids = set()

        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline or len(cmdline) < 30:
                continue
            pid = proc.get("pid", 0)
            if pid in reported_pids:
                continue
            
            # Skip container runtime and other excluded processes
            comm = proc.get("comm", "")
            if comm.lower() in self.WALLET_DETECTION_EXCLUSIONS:
                continue

            for pattern, coin_name in self.WALLET_PATTERNS:
                match = pattern.search(cmdline)
                if match:
                    # Validate that this looks like a real wallet address
                    # and not just a hash or ID string
                    if not self._is_likely_wallet_address(match.group(0), cmdline):
                        continue
                    
                    reported_pids.add(pid)
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1496",
                        title=f"加密货币钱包地址: {coin_name}",
                        description=f"进程 '{proc.get('comm', '')}' (PID {pid}) 命令行包含"
                                    f"{coin_name} wallet address",
                        confidence=0.8,
                        raw_data={
                            "pid": pid,
                            "comm": proc.get("comm", ""),
                            "wallet_type": coin_name,
                            "wallet_address": match.group(0)[:20] + "...",
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=cmdline[:500] if cmdline else None,
                            executable=proc.get("exe", "") if proc.get("exe") else None,
                        ),
                        remediation_commands=[
                            f"kill -9 {pid}",
                            f"cat /proc/{pid}/cmdline | tr '\\0' ' '",
                            "Check for mining software",
                            "Audit process command lines for credentials"
                        ]
                    ))
                    break

        return evidences
    
    def _is_likely_wallet_address(self, matched: str, cmdline: str) -> bool:
        """Validate that a match is likely a wallet address, not a hash/ID
        
        Returns False for common false positives:
        - Container runtime arguments (hashes, IDs)
        - File paths
        - URLs
        - Environment variables
        """
        # Check if the match is part of a larger hash-like string
        # Container runtimes often have long hex/base58 strings
        if len(matched) < 30:
            return False  # Too short to be a wallet address
        
        # Check if it's in a file path or URL context
        match_start = cmdline.find(matched)
        if match_start > 0:
            context_before = cmdline[max(0, match_start - 10):match_start]
            # Exclude if preceded by path separators or URL schemes
            if any(context_before.endswith(prefix) for prefix in ['/', '--', '://']):
                return False
        
        return True
