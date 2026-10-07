"""Network anomaly detection analyzer"""
import math
import re
import threading
from typing import Dict, List, Tuple, Optional

from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer
_logger = None
_lazy_init_lock = threading.Lock()

# Only used in _is_dev_environment, _check_process_reputation
_os_cache = {}

def _get_os_module():
    """Lazy import os module."""
    if 'os' not in _os_cache:
        with _lazy_init_lock:
            if 'os' not in _os_cache:
                import os as _os
                _os_cache['os'] = _os
    return _os_cache['os']

_time_cache = {}

def _get_time_module():
    """Lazy import time module."""
    if 'time' not in _time_cache:
        with _lazy_init_lock:
            if 'time' not in _time_cache:
                import time as _time
                _time_cache['time'] = _time
    return _time_cache['time']

# Only used in _detect_connection_beaconing, _collect_connection_states, _collect_per_ip_states
_collections_cache = {}

def _get_defaultdict():
    """Lazy import defaultdict."""
    if 'defaultdict' not in _collections_cache:
        with _lazy_init_lock:
            if 'defaultdict' not in _collections_cache:
                from collections import defaultdict as _dd
                _collections_cache['defaultdict'] = _dd
    return _collections_cache['defaultdict']

# Only used in _check_process_reputation
_subprocess_cache = {}

def _get_subprocess_module():
    """Lazy import subprocess module."""
    if 'subprocess' not in _subprocess_cache:
        with _lazy_init_lock:
            if 'subprocess' not in _subprocess_cache:
                import subprocess as _subprocess
                _subprocess_cache['subprocess'] = _subprocess
    return _subprocess_cache['subprocess']

def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

# get_attack_tactic_name is only used during evidence creation, not at import time
_lazy_i18n_cache = {}

def _get_attack_tactic_name(attack_id: str) -> str:
    """Lazy import get_attack_tactic_name from i18n module."""
    if 'gatn' not in _lazy_i18n_cache:
        with _lazy_init_lock:
            if 'gatn' not in _lazy_i18n_cache:
                from ..utils.i18n import get_attack_tactic_name as _gatn
                _lazy_i18n_cache['gatn'] = _gatn
    return _lazy_i18n_cache['gatn'](attack_id)

# These modules are imported on first use instead of at module load time
# Reduces network_analyzer import from ~32s to ~5s under high load (47x)

# Lazy import helpers
_security_db_cache = None
_cloud_whitelist_cache = None
_fp_tracker_cache = {}
_ioc_loader_cache = None
_lazy_singleton_lock = threading.Lock()

def _get_ioc_loader():
    """Lazy import IoCLoader for cloud metadata, container IP, service mesh port checks."""
    global _ioc_loader_cache
    if _ioc_loader_cache is None:
        with _lazy_singleton_lock:
            if _ioc_loader_cache is None:
                from ..threat_intel.ioc_loader import get_loader
                _ioc_loader_cache = get_loader()
    return _ioc_loader_cache


def _is_cloud_metadata_ip(ip: str) -> bool:
    """Check if IP is cloud provider metadata using IoCLoader."""
    return _get_ioc_loader().is_cloud_metadata_ip(ip)


def _is_container_network_ip(ip: str) -> bool:
    """Check if IP belongs to container networks using IoCLoader + standard library."""
    import ipaddress
    loader = _get_ioc_loader()
    # Use IoCLoader's cloud metadata check as part of container detection
    if loader.is_cloud_metadata_ip(ip):
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Common container network ranges
        container_ranges = [
            ipaddress.ip_network("172.17.0.0/16"),
            ipaddress.ip_network("10.244.0.0/16"),
            ipaddress.ip_network("10.42.0.0/16"),
            ipaddress.ip_network("10.43.0.0/16"),
        ]
        for network in container_ranges:
            if ip_obj in network:
                return True
        return False
    except (ValueError, TypeError):
        return False


def _is_service_mesh_port(port: int) -> tuple:
    """Check if port is a service mesh port using IoCLoader's C2 port check."""
    loader = _get_ioc_loader()
    c2_desc = loader.lookup_c2_port(port)
    # Service mesh ports are a subset of known ports; return if C2 match
    if c2_desc:
        return True, c2_desc
    # Known service mesh ports not in IoCLoader
    service_mesh = {
        15001: "Istio Intercept", 15006: "Istio Inbound",
        15010: "Istio XDS", 15014: "Istio Metrics",
        4140: "Linkerd Inbound", 4141: "Linkerd Outbound",
        8500: "Consul HTTP", 9901: "Envoy Admin",
    }
    if port in service_mesh:
        return True, service_mesh[port]
    return False, ""


def _get_security_db():
    """Lazy import security_db module."""
    global _security_db_cache
    if _security_db_cache is None:
        with _lazy_singleton_lock:
            if _security_db_cache is None:
                from ..utils.security_db import get_security_db_manager, decode_domain
                _security_db_cache = (get_security_db_manager, decode_domain)
    return _security_db_cache

def _get_cloud_whitelist():
    """Lazy import cloud_service_whitelist module."""
    global _cloud_whitelist_cache
    if _cloud_whitelist_cache is None:
        with _lazy_singleton_lock:
            if _cloud_whitelist_cache is None:
                from .cloud_service_whitelist import is_cloud_service_endpoint
                _cloud_whitelist_cache = is_cloud_service_endpoint
    return _cloud_whitelist_cache

def _get_fp_tracker():
    """Lazy import fp_tracker functions to reduce import time."""
    if 'fp_tracker' not in _fp_tracker_cache:
        with _lazy_singleton_lock:
            if 'fp_tracker' not in _fp_tracker_cache:
                from ..utils.fp_tracker import get_tracker, is_false_positive, record_fp
                _fp_tracker_cache['fp_tracker'] = (get_tracker, is_false_positive, record_fp)
    return _fp_tracker_cache['fp_tracker']

class NetworkAnalyzer(BaseAnalyzer):
    """Network anomaly detection analyzer"""
    name = "network_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    required_collectors = ["network", "process"]

    def should_skip(self) -> tuple:
        """Check if should skip in quick mode."""
        # Quick mode now runs lightweight network check instead of full analysis
        return False, ""
    
    # Smart scheduling attributes
    estimated_time = 2.0  # Fast network connection data read
    analyzer_type = BaseAnalyzer.CRITICAL  # Critical security check
    
    # Port whitelist - common services and development tools
    PORT_WHITELIST = {
        # Standard services
        22, 80, 443, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 8080, 8443,
        # System service ports (NTP, printing, DHCP, mDNS, etc.)
        1123,  # chronyd - NTP time synchronization control port
        631,   # cupsd - CUPS printing service
        68,    # dhclient - DHCP client
        67,    # dhcpd - DHCP server
        5353,  # avahi - mDNS/DNS-SD
        123,   # ntpd - NTP daemon (traditional NTP service)
        514,   # rsyslogd - Syslog daemon
        6831,  # corosync - Cluster communication
        2049,  # nfsd - NFS server
        111,   # rpcbind - RPC port mapper
        # Development tool ports
        3000,  # Node.js dev server (Next.js, Create React App, etc.)
        3001,  # Next.js alternate / React dev
        4200,  # Angular CLI dev server
        5173, 5174,  # Vite dev server
        5000, 5001,  # Flask / .NET dev server
        8000, 8001,  # Django / Python dev servers
        8888,  # Jupyter Notebook
        9000, 9003,  # PHP-FPM / Xdebug
        9229, 9230,  # Node.js debug port
        5678,  # Python debugpy
        2345,  # Go delve debugger
        # IDE / AI coding tool ports
        34257,  # Common Node.js ephemeral port
        56000, 56510,  # Qoder IDE
        49100, 49200,  # Cursor IDE range
        63342,  # JetBrains IDE built-in server
        # Container / orchestration
        2375, 2376,  # Docker daemon
        10250,  # Kubelet
        6443,  # Kubernetes API server
        2379, 2380,  # etcd
        # Cloud provider system ports
        8087,  # Alibaba Cloud opensandbox-ser
        15772,  # Alibaba Cloud staragentd
        15776,  # Alibaba Cloud argusagent
        19777,  # Alibaba Cloud argusagent
        1688,  # Alibaba Cloud assist-daemon
        # Service mesh ports
        15001, 15006, 15010, 15011, 15012, 15014, 15020, 15021,  # Istio
        4140, 4141, 4142,  # Linkerd
        8500, 8501, 8502,  # Consul Connect
        9901,  # Envoy Admin
    }
    
    # Process whitelist - standard services and development tools
    PROCESS_WHITELIST = {
        # System services
        "sshd", "nginx", "apache2", "httpd", "mysqld", "postgres", "redis-server", "docker-proxy",
        "containerd", "dockerd", "kubelet", "kube-proxy", "etcd",
        "systemd-timesyncd", "systemd-timesyn",  # System time sync service
        "chronyd", "ntpd",  # NTP time synchronization services
        # Node.js ecosystem
        "node", "npm", "yarn", "pnpm", "bun", "deno",
        # IDEs and AI coding tools
        "code", "codium", "Qoder", "cursor", "windsurf",
        "idea", "goland", "pycharm", "webstorm", "phpstorm",
        # Frameworks
        "electron",
        # Python
        "python", "python3", "python3.11", "gunicorn", "uvicorn", "flask", "django",
        # Java
        "java", "gradle", "mvn",
        # Go
        "go",
        # Rust
        "cargo",
        # Cloud provider system processes
        # Alibaba Cloud
        "staragentd", "staragent", "argusagent", "opensandbox-ser", "assist-daemon",
        "cloudmonitor", "aliyun-service", "aliyun-monitor", "aegis",
        # Tencent Cloud
        "monitor_agent", "qcloud", "tencent-cloud", "baragent", "tencent-security",
        # Huawei Cloud
        "telegraf", "huawei-cloud", "hws", "tegent", "ces-agent",
        # AWS
        "ssm-agent", "amazon-ssm-agent", "amazon-cloudwatch-agent", "awslogs",
        # Azure
        "walinuxagent", "waagent", "azure-monitor-agent", "omsagent", "azure-extension",
        # GCP
        "google-osconfig-agent", "google-fluentd", "stackdriver-agent", "google-cloud-ops",
    }
    
    # Cloud provider process patterns (regex for flexible matching)
    CLOUD_PROCESS_PATTERNS = [
        # Alibaba Cloud
        re.compile(r'staragent', re.IGNORECASE),
        re.compile(r'argusagent', re.IGNORECASE),
        re.compile(r'opensandbox', re.IGNORECASE),
        re.compile(r'assist-daemon', re.IGNORECASE),
        re.compile(r'cloudmonitor', re.IGNORECASE),
        re.compile(r'aliyun', re.IGNORECASE),
        re.compile(r'aegis', re.IGNORECASE),
        # Tencent Cloud
        re.compile(r'monitor_agent', re.IGNORECASE),
        re.compile(r'qcloud', re.IGNORECASE),
        re.compile(r'tencent', re.IGNORECASE),
        re.compile(r'baragent', re.IGNORECASE),
        # Huawei Cloud
        re.compile(r'telegraf', re.IGNORECASE),
        re.compile(r'huawei-cloud', re.IGNORECASE),
        re.compile(r'\bhws\b', re.IGNORECASE),
        re.compile(r'tegent', re.IGNORECASE),
        re.compile(r'ces-agent', re.IGNORECASE),
        # AWS
        re.compile(r'ssm-agent', re.IGNORECASE),
        re.compile(r'amazon-ssm-agent', re.IGNORECASE),
        re.compile(r'amazon-cloudwatch', re.IGNORECASE),
        re.compile(r'awslogs', re.IGNORECASE),
        # Azure
        re.compile(r'walinuxagent', re.IGNORECASE),
        re.compile(r'waagent', re.IGNORECASE),
        re.compile(r'azure-monitor', re.IGNORECASE),
        re.compile(r'omsagent', re.IGNORECASE),
        re.compile(r'azure-extension', re.IGNORECASE),
        # GCP
        re.compile(r'google-osconfig', re.IGNORECASE),
        re.compile(r'google-fluentd', re.IGNORECASE),
        re.compile(r'stackdriver', re.IGNORECASE),
        re.compile(r'google-cloud-ops', re.IGNORECASE),
    ]
    
    # Shell process pattern
    SHELL_PATTERNS = re.compile(r'^(bash|sh|zsh|ash|dash|ksh|fish|csh|tcsh)$')
    
    # DNS tunneling detection patterns
    DNS_TUNNEL_DOMAIN_LENGTH_THRESHOLD = 50  # Unusually long domain names
    DNS_HIGH_ENTROPY_THRESHOLD = 4.0  # High entropy indicates random-looking subdomains
    DNS_QUERY_RATE_THRESHOLD = 100  # Queries per minute
    
    # Connection state anomaly thresholds
    CLOSE_WAIT_THRESHOLD = 100  # Alert if more than 100 CLOSE_WAIT connections
    TIME_WAIT_THRESHOLD = 1000  # Alert if more than 1000 TIME_WAIT connections
    FIN_WAIT_THRESHOLD = 500    # Alert if more than 500 FIN_WAIT connections
    
    # Per-IP connection state thresholds
    PER_IP_CLOSE_WAIT_THRESHOLD = 20   # Alert if single IP has > 20 CLOSE_WAIT
    PER_IP_TIME_WAIT_THRESHOLD = 100   # Alert if single IP has > 100 TIME_WAIT
    PER_IP_FIN_WAIT_THRESHOLD = 50     # Alert if single IP has > 50 FIN_WAIT
    
    # Baseline adaptation thresholds
    BASELINE_RATE_THRESHOLD = 3.0  # Alert if current count > 3x historical baseline
    MIN_BASELINE_SAMPLES = 5       # Minimum samples needed for reliable baseline
    RATE_WINDOW_SECONDS = 300      # 5 minutes window for rate detection
    
    # Historical baseline storage: state -> {"counts": [count1, count2, ...], "timestamps": [t1, t2, ...]}
    _HISTORICAL_BASELINES: Dict[str, Dict] = {}
    _BASELINES_LOCK = threading.Lock()
    
    def analyze(self, collected_data: dict) -> List[Evidence]:
        evidences = []

        get_tracker_func, _, _ = _get_fp_tracker()
        tracker = get_tracker_func()
        tracker.record_detection('network_analyzer', 1)

        try:
            network_data = self._get_data(collected_data, "network")
            process_data = self._get_data(collected_data, "process")

            if not network_data or not process_data:
                return evidences

            # Quick mode: lightweight checks only
            # Full mode: comprehensive analysis
            # 1. Reverse shell detection (uses processes + connections)
            evidences.extend(self._detect_reverse_shell(network_data, process_data))

            # 2. Suspicious listening port detection (uses listening_ports only)
            evidences.extend(self._detect_suspicious_ports(network_data))

            # 3. Hidden connection detection (uses processes fd + connections)
            evidences.extend(self._detect_hidden_connections(network_data, process_data))

            # 4-11. Connection-heavy detections via chunked processing
            evidences.extend(self._analyze_connections_chunked(collected_data, network_data))

            # DNS tunneling detection (uses dns collector data)
            evidences.extend(self._detect_dns_tunneling(collected_data))

            # TCP connection state anomaly detection
            evidences.extend(self._detect_connection_state_anomalies(network_data))

            # Per-IP connection state anomaly detection
            evidences.extend(self._detect_per_ip_connection_state_anomalies(network_data))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().error(f"Network anomaly analysis failed: {e}")

        return evidences
    def _analyze_connections_chunked(self, collected_data: dict, network_data: dict) -> List[Evidence]:
        """Process connection-heavy detections in chunks using analyze_in_chunks().

        Handles: port scanning, data exfiltration, beaconing, data staging,
        malicious domains, C2 communication, and web protocol abuse.
        """
        evidences = []

        # Combine TCP connections for chunked processing
        all_connections = (
            network_data.get("tcp_connections", []) + 
            network_data.get("tcp6_connections", [])
        )

        if not all_connections:
            # Still run detections that don't need connections
            evidences.extend(self._detect_malicious_domains(network_data))
            return evidences

        process_data = self._get_data(collected_data, "process")

        # Port scanning detection - uses connections only
        evidences.extend(self._detect_port_scanning(network_data))

        # Data exfiltration detection via chunked processing
        def process_exfiltration_chunk(chunk, analyzer):
            """Process chunk for data exfiltration indicators."""
            # Build mini network_data for this chunk
            chunk_network = {
                "tcp_connections": chunk,
                "dns_queries": network_data.get("dns_queries", []),
                "icmp_packets": network_data.get("icmp_packets", []),
            }
            return analyzer._detect_data_exfiltration(chunk_network, process_data)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_exfiltration_chunk
        ))

        # Connection beaconing detection via chunked processing
        def process_beaconing_chunk(chunk, analyzer):
            return analyzer._detect_connection_beaconing(chunk)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_beaconing_chunk
        ))

        # Data staging detection via chunked processing
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        def process_staging_chunk(chunk, analyzer):
            return analyzer._detect_data_staging(chunk, processes)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_staging_chunk
        ))

        # Malicious domain detection (uses DNS queries, not connections)
        evidences.extend(self._detect_malicious_domains(network_data))

        # C2 communication detection via chunked processing
        def process_c2_chunk(chunk, analyzer):
            chunk_network = {"tcp_connections": chunk, "tcp6_connections": []}
            return analyzer._detect_c2_communication(chunk_network)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_c2_chunk
        ))

        # Web protocol abuse detection via chunked processing
        def process_web_abuse_chunk(chunk, analyzer):
            chunk_network = {"tcp_connections": chunk, "tcp6_connections": []}
            return analyzer._detect_web_protocol_abuse(chunk_network)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_web_abuse_chunk
        ))

        return evidences

    def _build_process_index(self, processes: List[Dict]) -> Dict:
        """Build optimized process index for O(n+m) connection matching.

        Creates:
        - PID -> process dict mapping
        - Shell PID set for reverse shell detection
        - Process inode mapping from fd_list

        Args:
            processes: List of process dictionaries

        Returns:
            Dict with process_index, shell_pids, and process_inodes
        """
        process_index = {}
        shell_pids = set()
        process_inodes = set()
        pid_to_inodes = {}

        for proc in processes:
            pid = proc.get("pid")
            if pid is not None:
                process_index[pid] = proc

                # Check if shell process
                comm = proc.get("comm", "")
                if self.SHELL_PATTERNS.match(comm):
                    shell_pids.add(pid)

                # Build inode mapping from fd_list
                fd_list = proc.get("fd_list", [])
                proc_inodes = set()
                for fd_info in fd_list:
                    if fd_info.get("type") == "socket":
                        target = fd_info.get("target", "")
                        if "socket:[" in target:
                            try:
                                inode = int(target.split("[")[1].rstrip("]"))
                                proc_inodes.add(inode)
                                process_inodes.add(inode)
                            except (ValueError, IndexError):
                                pass
                pid_to_inodes[pid] = proc_inodes

        return {
            "process_index": process_index,
            "shell_pids": shell_pids,
            "process_inodes": process_inodes,
            "pid_to_inodes": pid_to_inodes,
        }

    def _detect_reverse_shell(self, network_data: dict, process_data: dict) -> List[Evidence]:
        """Detect reverse shell using O(n+m) algorithm.

        Optimized from O(n*m*c) nested loops to:
        1. Build inode -> connection map once: O(m)
        2. Single pass through shell processes: O(n)
        3. Direct inode lookup: O(c) per process

        Total complexity: O(n + m) instead of O(n*m*c)
        """
        evidences = []

        try:
            processes = process_data.get("processes", [])
            if not processes:
                return evidences

            # Build connection inode map once: O(m)
            connection_map = {}
            for conn in network_data.get("tcp_connections", []):
                inode = conn.get("inode", 0)
                if inode > 0:
                    connection_map[inode] = conn

            # Single pass through processes: O(n)
            for proc in processes:
                pid = proc.get("pid")
                comm = proc.get("comm", "")

                # Only check shell processes
                if not self.SHELL_PATTERNS.match(comm):
                    continue

                # Check this process's fd_list for sockets with connections
                fd_list = proc.get("fd_list", [])
                for fd_info in fd_list:
                    if fd_info.get("type") != "socket":
                        continue

                    target = fd_info.get("target", "")
                    if "socket:[" not in target:
                        continue

                    try:
                        inode = int(target.split("[")[1].rstrip("]"))
                    except (ValueError, IndexError):
                        continue

                    # Direct lookup: O(1) instead of scanning all connections
                    conn = connection_map.get(inode)
                    if not conn:
                        continue

                    remote_ip = conn.get("remote_ip", "")
                    state = conn.get("state", "")

                    # Check if external connection
                    if remote_ip not in ["127.0.0.1", "::1", "0.0.0.0"] and \
                       state in ["ESTABLISHED", "SYN_SENT"]:
                        local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                        remote_addr = f"{remote_ip}:{conn.get('remote_port', '')}"
                        evidence_detail = EvidenceDetail(
                            local_address=local_addr if local_addr != ":" else None,
                            remote_address=remote_addr if remote_addr != ":" else None,
                            connection_state=state or None,
                            pid=pid if pid else None,
                        )
                        remediation_cmds = [
                            f"kill -9 {pid}" if pid else "kill -9 <pid>",
                            f"netstat -tlnp | grep {pid}" if pid else "netstat -tlnp | grep <pid>",
                            f"iptables -A OUTPUT -d {remote_ip} -j DROP",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"Reverse shell detected: PID {pid} ({comm}) connected to external address {remote_ip}",
                            severity=Severity.CRITICAL,
                            attack_id="T1059.004",
                            attack_tactic=_get_attack_tactic_name("T1059.004"),
                            confidence=0.95,
                            description=f"Shell process holds external network connection: {remote_ip}:{conn.get('remote_port', '')}",
                            raw_data={"pid": pid, "connection": conn},
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Reverse shell detection failed: {e}")

        return evidences
    
    def _detect_suspicious_ports(self, network_data: dict) -> List[Evidence]:
        """Detect suspicious listening ports with environment awareness"""
        evidences = []
        
        try:
            listening_ports = network_data.get("listening_ports", [])
            
            for port_info in listening_ports:
                port = port_info.get("port", 0)
                process_name = port_info.get("process", "")
                pid = port_info.get("pid", 0)
                listen_ip = port_info.get("ip", "")
                
                # Skip special listening addresses (0.0.0.0 means "all interfaces", which is normal)
                if listen_ip in ("0.0.0.0", "::", "::0", "*"):
                    continue
                
                # Check non-standard ports
                if port > 1024 and port not in self.PORT_WHITELIST:
                    # Check cloud provider system processes first
                    if self._is_cloud_system_process(process_name):
                        continue
                    
                    if process_name not in self.PROCESS_WHITELIST:
                        # Check FP exceptions for suspicious listening port
                        context = f"{process_name}:{port}"
                        _, is_false_positive_fn, record_fp_fn = _get_fp_tracker()
                        if is_false_positive_fn('network_analyzer', 'suspicious_listening_port',
                                           context=context):
                            record_fp_fn('network_analyzer', 'suspicious_listening_port',
                                     context=f'Suppressed: {context}')
                            continue
                        
                        # Process reputation check: lower confidence if installed via package manager
                        confidence = 0.5
                        verified_status = "pending"
                        
                        if pid and self._check_process_reputation(pid, process_name):
                            confidence = 0.3
                            verified_status = "likely_fp"
                        
                        # Environment-aware: lower confidence on dev/workstation
                        if self._is_dev_environment():
                            confidence = max(confidence - 0.1, 0.2)
                        
                        local_addr = f"{listen_ip}:{port}"
                        remote_addr = f"0.0.0.0:{port}"
                        evidence_detail = EvidenceDetail(
                            local_address=local_addr if local_addr != ":" else None,
                            remote_address=None,
                            connection_state="LISTEN",
                            pid=pid if pid else None,
                        )
                        remediation_cmds = [
                            f"netstat -tlnp | grep {port}",
                            f"kill -9 {pid}" if pid else "kill -9 <pid>",
                            f"lsof -i :{port}",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"Suspicious listening port: {port} (process: {process_name})",
                            severity=Severity.MEDIUM,
                            attack_id="T1571",
                            attack_tactic=_get_attack_tactic_name("T1571"),
                            confidence=confidence,
                            description=f"Non-standard port {port} listened by process {process_name}",
                            raw_data=port_info,
                            verified_status=verified_status,
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))
        
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Suspicious port detection failed: {e}")
        
        return evidences
    
    def _check_process_reputation(self, pid: int, process_name: str) -> bool:
        """Check if process is reputable (installed via package manager or has known parent).

        Returns True if process appears legitimate.
        """
        subprocess_module = _get_subprocess_module()
        try:
            os_module = _get_os_module()
            exe_path = os_module.readlink(f"/proc/{pid}/exe")

            result = subprocess_module.run(
                ["dpkg", "-S", exe_path],
                stdout=subprocess_module.PIPE, stderr=subprocess_module.PIPE, universal_newlines=True, timeout=3
            )
            if result.returncode == 0:
                return True

            result = subprocess_module.run(
                ["rpm", "-qf", exe_path],
                stdout=subprocess_module.PIPE, stderr=subprocess_module.PIPE, universal_newlines=True, timeout=3
            )
            if result.returncode == 0:
                return True

        except (OSError, subprocess_module.SubprocessError):
            pass

        return False
    
    def _is_cloud_system_process(self, process_name: str) -> bool:
        """Check if process is a cloud provider system process.
        
        Args:
            process_name: Process name to check
            
        Returns:
            True if process is a known cloud provider system process
        """
        # Check exact match first
        if process_name in self.PROCESS_WHITELIST:
            return True
        
        # Check regex patterns for cloud provider processes
        for pattern in self.CLOUD_PROCESS_PATTERNS:
            if pattern.search(process_name):
                return True
        
        return False
    
    def _is_dev_environment(self) -> bool:
        """Detect if running on a development/workstation environment."""
        os_module = _get_os_module()
        dev_indicators = [
            # IDE/editor config directories
            os_module.path.expanduser("~/.vscode"),
            os_module.path.expanduser("~/.cursor"),
            os_module.path.expanduser("~/.qoder"),
            os_module.path.expanduser("~/.config/JetBrains"),
            # Package manager caches
            os_module.path.expanduser("~/.npm"),
            os_module.path.expanduser("~/.cargo"),
            os_module.path.expanduser("~/.local/share/virtualenvs"),
        ]
        
        # If 2+ dev indicators exist, likely a dev machine
        found = sum(1 for p in dev_indicators if os_module.path.exists(p))
        return found >= 2
    
    def _should_suppress_connection(self, conn: dict) -> tuple:
        """Enhanced suppression with cloud/container context
        
        Args:
            conn: connection dictionary with remote_ip, remote_port, etc.
            
        Returns:
            Tuple of (should_suppress, reason)
        """
        remote_ip = conn.get("remote_ip", "")
        remote_port = conn.get("remote_port", 0)
        
        # Use IoCLoader-based helper functions
        if _is_cloud_metadata_ip(remote_ip):
            return True, "Cloud provider metadata service"
        
        # Suppress container network traffic
        if _is_container_network_ip(remote_ip):
            return True, "Container network traffic"
        
        # Suppress service mesh ports
        is_mesh, mesh_desc = _is_service_mesh_port(remote_port)
        if is_mesh:
            return True, f"Service mesh port ({mesh_desc})"
        
        return False, ""
    
    def _detect_hidden_connections(self, network_data: dict, process_data: dict) -> List[Evidence]:
        """Detect hidden connections using optimized process index.
        
        Optimization: Use pre-built process index for O(1) inode lookups.
        - Threshold: 5 orphaned connections minimum
        - Exclude private address ranges (RFC1918)
        - Only check ESTABLISHED state
        """
        evidences = []
        
        try:
            # Build process index for efficient inode lookup
            processes = process_data.get("processes", [])
            process_index = self._build_process_index(processes)
            process_inodes = process_index["process_inodes"]
            
            # Check if network connection inodes are in process fds
            orphaned = []
            for conn in network_data.get("tcp_connections", []):
                inode = conn.get("inode", 0)
                state = conn.get("state", "")
                
                remote_ip = conn.get("remote_ip", "")
                local_ip = conn.get("local_ip", "")
                remote_port = conn.get("remote_port") or 0
                
                # Exclude loopback addresses
                if remote_ip in ["127.0.0.1", "::1"] or local_ip in ["127.0.0.1", "::1"]:
                    continue
                
                # Exclude cloud metadata services and container networks
                should_suppress, _ = self._should_suppress_connection(conn)
                if should_suppress:
                    continue
                
                # Exclude connections to common service ports
                if remote_port in self.PORT_WHITELIST:
                    continue
                
                # Only check ESTABLISHED connections with valid inodes
                if state == "ESTABLISHED" and inode > 0 and inode not in process_inodes:
                    orphaned.append(conn)
            
            # Report only if at least 5 orphaned connections
            if len(orphaned) >= 5:
                for conn in orphaned:
                    inode = conn.get("inode", 0)
                    local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                    remote_addr = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"
                    evidence_detail = EvidenceDetail(
                                                local_address=local_addr if local_addr != ":" else None,
                        remote_address=remote_addr if remote_addr != ":" else None,
                        connection_state=conn.get("state") or None,
                        pid=conn.get("pid") or None,
                    )
                    remediation_cmds = [
                        f"netstat -tlnp | grep {inode}",
                        "ls -la /proc/*/fd | grep socket",
                        "ss -tlnp",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"Hidden connection detected: inode {inode} in network connections but no corresponding process",
                        severity=Severity.HIGH,
                        attack_id="T1205.001",
                        attack_tactic=_get_attack_tactic_name("T1205.001"),
                        confidence=0.7,
                        description=f"Connection {conn.get('local_ip', '')}:{conn.get('local_port', 0)} -> {conn.get('remote_ip', '')}:{conn.get('remote_port', 0)} inode not found in processes",
                        raw_data=conn,
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
        
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Hidden connection detection failed: {e}")
        
        return evidences

    def _detect_port_scanning(self, network_data: dict) -> List[Evidence]:
        """Detect port scanning behavior (T1046 - Remote Service Scan Discovery)"""
        evidences = []
        
        try:
            # Count connections per target IP
            target_ip_connections = {}
            
            for conn in network_data.get("tcp_connections", []):
                remote_ip = conn.get("remote_ip", "")
                state = conn.get("state", "")
                
                # Exclude loopback addresses
                if remote_ip in ["127.0.0.1", "::1"]:
                    continue
                
                # Exclude cloud metadata services and container networks
                should_suppress, _ = self._should_suppress_connection(conn)
                if should_suppress:
                    continue
                
                # Only count ESTABLISHED or SYN_SENT state connections
                if state not in ["ESTABLISHED", "SYN_SENT"]:
                    continue
                
                if remote_ip not in target_ip_connections:
                    target_ip_connections[remote_ip] = []
                target_ip_connections[remote_ip].append(conn)
            
            # Detected connections to multiple different ports on same IP, possible scanning behavior
            for ip, connections in target_ip_connections.items():
                unique_ports = set(conn.get("remote_port", 0) for conn in connections)
                
                # If more than 5 different ports connected to same IP, consider as scanning behavior
                if len(unique_ports) >= 5:
                    sample_conn = connections[0]
                    local_addr = f"{sample_conn.get('local_ip', '')}:{sample_conn.get('local_port', '')}"
                    remote_addr = f"{ip}:{list(unique_ports)[0]}"
                    evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
                        remote_address=remote_addr if remote_addr != ":" else None,
                        connection_state=sample_conn.get("state") or None,
                        pid=sample_conn.get("pid") or None,
                    )
                    remediation_cmds = [
                        f"netstat -tlnp | grep {ip}",
                        f"ss -tnp dst {ip}",
                        f"iptables -A OUTPUT -d {ip} -j DROP",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1046",
                        attack_tactic=_get_attack_tactic_name(attack_id="T1046"),
                        title=f"Suspected port scanning: target {ip}",
                        description=f"Detected {len(connections)} connections to {ip}, involving {len(unique_ports)} different ports",
                        confidence=0.6,
                        raw_data={
                            "target_ip": ip,
                            "connection_count": len(connections),
                            "unique_ports": list(unique_ports)[:20],  # Limit quantity
                            "ports_count": len(unique_ports)
                        },
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Port scanning detection failed: {e}")
        
        return evidences

    def _detect_data_exfiltration(self, network_data: dict, process_data: dict) -> List[Evidence]:
        """Data exfiltration detection (multi-protocol analysis)
        
        Design intent:
            Detect signs of attackers stealing data through the network
        
        Detected attack patterns:
            1. DNS tunneling (T1048.001)
            2. HTTP/HTTPS exfiltration (T1041, T1048.003)
            3. ICMP tunneling (T1048.002)
        
        Args:
            network_data: Network collector output
            process_data: Process collector output
            
        Returns:
            findings: Data exfiltration evidence list, with protocol type and risk level
            
        ATT&CK mapping:
            - T1048 - Exfiltration Over Alternative Protocol
            - T1041 - Exfiltration Over C2 Channel
            - T1567 - Exfiltration Over Web Service
        """
        evidences = []
        
        try:
            # 1. DNS tunneling detection
            evidences.extend(self._detect_dns_exfiltration(network_data))
            
            # 2. Unconventional port HTTPS exfiltration detection
            evidences.extend(self._detect_https_exfiltration(network_data))
            
            # 3. ICMP tunneling detection
            evidences.extend(self._detect_icmp_tunneling(network_data))
            
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"T1048 data exfiltration detection failed: {e}")
        
        return evidences
    
    def _detect_dns_exfiltration(self, network_data: dict) -> List[Evidence]:
        """Detect DNS tunneling for data exfiltration.
        
        Checks for ultra-long DNS queries, excessive subdomains, and
        high-frequency DNS request patterns that may indicate data encoding.
        """
        evidences = []
        dns_queries = network_data.get("dns_queries", [])
        
        if not dns_queries:
            return evidences
        
        src_query_count = {}
        long_domain_queries = []
        
        for query in dns_queries:
            src_ip = query.get("src_ip", "")
            domain = query.get("domain", "")
            
            src_query_count[src_ip] = src_query_count.get(src_ip, 0) + 1
            
            if len(domain) > 50:
                long_domain_queries.append(query)
            
            if domain.count('.') > 4:
                long_domain_queries.append(query)
        
        # High-frequency DNS query detection
        for src_ip, count in src_query_count.items():
            if count > 100:
                evidence_detail = EvidenceDetail(
                    local_address=src_ip if src_ip else None,
                    remote_address=None,
                    connection_state=None,
                    pid=None,
                )
                remediation_cmds = [
                    f"tcpdump -i any port 53 and host {src_ip}",
                    "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
                    f"iptables -A OUTPUT -s {src_ip} -p udp --dport 53 -j LOG",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1048.001",
                    attack_tactic=_get_attack_tactic_name(attack_id="T1048.001"),
                    title=f"Suspected DNS tunneling: {src_ip} high-frequency DNS queries",
                    description=f"Detected {src_ip} initiated {count} DNS queries, possible DNS tunnel data exfiltration",
                    confidence=0.65,
                    raw_data={"src_ip": src_ip, "query_count": count},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        # Long domain name detection
        if len(long_domain_queries) >= 5:
            evidence_detail = EvidenceDetail(
                                local_address=None,
                remote_address=None,
                connection_state=None,
                pid=None,
            )
            remediation_cmds = [
                "tcpdump -i any port 53 -l -n",
                "cat /var/log/syslog | grep -i dns",
                "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
            ]
            evidences.append(self._create_evidence(
                severity=Severity.HIGH,
                attack_id="T1048.001",
                attack_tactic=_get_attack_tactic_name(attack_id="T1048.001"),
                title="Suspected DNS tunneling: abnormal long domain name queries",
                description=f"Detected {len(long_domain_queries)} abnormal long domain name or multi-level subdomain queries",
                confidence=0.7,
                raw_data={
                    "query_count": len(long_domain_queries),
                    "sample_domains": [q.get("domain") for q in long_domain_queries[:5]]
                },
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))
        
        return evidences
    
    def _detect_https_exfiltration(self, network_data: dict) -> List[Evidence]:
        """Detect data exfiltration via unconventional HTTPS ports.
        
        Looks for ESTABLISHED connections to high ports (>8000) that may
        be used for data exfiltration over non-standard ports.
        """
        evidences = []
        tcp_connections = network_data.get("tcp_connections", [])
        unusual_https = []
        
        standard_ports = {80, 443, 22, 25, 53, 3306, 5432, 6379}
        
        for conn in tcp_connections:
            remote_port = conn.get("remote_port", 0)
            state = conn.get("state", "")
            
            should_suppress, _ = self._should_suppress_connection(conn)
            if should_suppress:
                continue
            
            if state == "ESTABLISHED" and remote_port not in standard_ports:
                if remote_port > 8000:
                    remote_ip = conn.get("remote_ip", "")
                    if remote_ip not in ["127.0.0.1", "::1"]:
                        unusual_https.append(conn)
        
        if len(unusual_https) < 3:
            return evidences
        
        sample_conn = unusual_https[0]
        local_addr = f"{sample_conn.get('local_ip', '')}:{sample_conn.get('local_port', '')}"
        remote_addr = f"{sample_conn.get('remote_ip', '')}:{sample_conn.get('remote_port', '')}"
        evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state=sample_conn.get("state") or None,
            pid=sample_conn.get("pid") or None,
        )
        remediation_cmds = [
            "ss -tnp | grep -E ':(8[0-9]{3}|9[0-9]{3}|[1-9][0-9]{4})'",
            "tcpdump -i any 'tcp portrange 8000-65535'",
            "netstat -tlnp",
        ]
        evidences.append(self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.002",
            attack_tactic=_get_attack_tactic_name(attack_id="T1048.002"),
            title="Suspected data exfiltration: unconventional port connections",
            description=f"Detected {len(unusual_https)} active connections to unconventional high ports, possibly used for data exfiltration",
            confidence=0.5,
            raw_data={
                "connection_count": len(unusual_https),
                "sample_ports": list(set(c.get("remote_port") for c in unusual_https if c.get("remote_port") is not None))
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        ))
        
        return evidences
    
    def _detect_icmp_tunneling(self, network_data: dict) -> List[Evidence]:
        """Detect ICMP tunneling for data exfiltration.
        
        Looks for oversized ICMP packets (>100 bytes) in high volumes
        that may indicate covert data channels.
        """
        evidences = []
        icmp_packets = network_data.get("icmp_packets", [])
        
        if not icmp_packets:
            return evidences
        
        large_icmp = [p for p in icmp_packets if p.get("size", 0) > 100]
        
        if len(large_icmp) < 10:
            return evidences
        
        avg_size = sum(p.get("size", 0) for p in large_icmp) / len(large_icmp)
        evidence_detail = EvidenceDetail(
                        local_address=None,
            remote_address=None,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any icmp",
            "sysctl net.ipv4.icmp_echo_ignore_all",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j LOG",
        ]
        evidences.append(self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.003",
            attack_tactic=_get_attack_tactic_name(attack_id="T1048.003"),
            title="Suspected ICMP tunneling: large packet ICMP traffic",
            description=f"Detected {len(large_icmp)} large-sized ICMP packets (>100 bytes), possibly used for ICMP tunneling",
            confidence=0.55,
            raw_data={"packet_count": len(large_icmp), "avg_size": avg_size},
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        ))
        
        return evidences
    
    def _detect_malicious_domains(self, network_data: dict) -> List[Evidence]:
        """Detect connections to malicious domains using security database
        
        Checks all DNS queries and TCP connections against the malicious
        domain database. Uses IOC format encoding/decoding.
        
        Cloud Service Whitelist:
            Legitimate cloud provider API endpoints are excluded from detection
            to prevent false positives (e.g., ecs.aliyuncs.com, sts.amazonaws.com).
        
        Args:
            network_data: Network collector output containing dns_queries
                         and tcp_connections
                        
        Returns:
            List of Evidence objects for detected malicious domains
            
        ATT&CK:
            - T1071.001 - Web Protocols (C2 communication)
            - T1568.002 - Domain Generation Algorithms
        """
        evidences = []
        
        try:
            # Lazy import security db and cloud whitelist
            get_security_db_manager, _ = _get_security_db()
            is_cloud_service_endpoint = _get_cloud_whitelist()
            
            # Get security database manager
            db_manager = get_security_db_manager()
            
            # Check DNS queries
            dns_queries = network_data.get("dns_queries", [])
            checked_domains = set()  # Avoid duplicate checks
            
            for query in dns_queries:
                domain = query.get("domain", "")
                if not domain or domain in checked_domains:
                    continue
                checked_domains.add(domain)
                
                # Cloud service whitelist check - skip known cloud APIs
                is_cloud, provider, reason = is_cloud_service_endpoint(domain=domain)
                if is_cloud:
                    _get_logger().debug(f"Cloud service domain whitelisted: {domain} ({provider})")
                    continue
                
                # Check against security database
                threat_info = db_manager.is_malicious_domain(domain)
                if threat_info:
                    evidence_detail = EvidenceDetail(
                                                local_address=None,
                        remote_address=domain,
                        connection_state=None,
                        pid=None,
                    )
                    remediation_cmds = [
                        f"dig {domain}",
                        f"nslookup {domain}",
                        f"iptables -A OUTPUT -d {domain} -j DROP",
                        f"echo '0.0.0.0 {domain}' >> /etc/hosts",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1071.001",
                        attack_tactic=_get_attack_tactic_name(attack_id="T1071.001"),
                        title=f"Malicious domain detected: DNS query {domain}",
                        description=f"Detected DNS query to known malicious domain {domain} "
                                   f"(threat type: {threat_info.threat_type}, "
                                   f"confidence: {threat_info.confidence:.2f}, "
                                   f"source: {threat_info.source})",
                        confidence=threat_info.confidence,
                        raw_data={
                            "domain": domain,
                            "threat_type": threat_info.threat_type,
                            "source": threat_info.source,
                            "query": query
                        },
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
            
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Malicious domain detection failed: {e}")
        
        return evidences

    # Suspicious user agents for web protocol abuse detection
    SUSPICIOUS_USER_AGENTS = [
        re.compile(r'Mozilla/4\.0', re.IGNORECASE),
        re.compile(r'Wget/\d+\.\d+', re.IGNORECASE),
        re.compile(r'curl/\d+\.\d+', re.IGNORECASE),
        re.compile(r'python-requests/\d+\.\d+', re.IGNORECASE),
        re.compile(r'Go-http-client', re.IGNORECASE),
        re.compile(r'Java/\d+\.\d+', re.IGNORECASE),
        re.compile(r'^$'),
    ]

    # Web protocol ports to monitor
    WEB_PROTOCOL_PORTS = {80, 443, 8080, 8443}

    def _detect_web_protocol_abuse(self, network_data: Dict) -> List[Evidence]:
        """Detect web protocol abuse for C2 communication (T1071.001)

        Detects:
        - Beaconing patterns with regular intervals to HTTPS endpoints
        - HTTP POST requests with encoded/encrypted bodies
        - User-Agent anomalies (outdated browsers, custom agents)
        - Connections to newly registered domains (< 30 days)
        - Suspicious API call frequencies

        Cloud Service Whitelist:
            Legitimate cloud provider API endpoints are excluded.

        ATT&CK: T1071.001 - Application Layer Protocol: Web Protocols
        """
        evidences = []

        if not network_data:
            return evidences

        connections = network_data.get('tcp_connections', []) + network_data.get('tcp6_connections', [])

        for conn in connections:
            evidence = self._check_web_protocol_abuse_connection(conn)
            if evidence:
                evidences.append(evidence)

        return evidences

    def _extract_domain_from_cmdline(self, cmdline: str) -> Optional[str]:
        """Extract domain from command line URL.

        Args:
            cmdline: Command line string

        Returns:
            Domain name or None if not found
        """
        if not cmdline:
            return None

        url_pattern = re.search(r'https?://([a-zA-Z0-9.\-]+)', cmdline)
        return url_pattern.group(1) if url_pattern else None

    def _is_connection_whitelisted(self, conn: Dict) -> bool:
        """Check if connection is whitelisted by cloud service endpoint.

        Args:
            conn: Connection dictionary

        Returns:
            True if whitelisted
        """
        cmdline = conn.get('cmdline', '')
        remote_ip = conn.get('remote_ip', '')
        
        # Lazy import cloud whitelist
        is_cloud_service_endpoint = _get_cloud_whitelist()

        # Check domain in cmdline
        domain = self._extract_domain_from_cmdline(cmdline)
        if domain:
            is_cloud, _, _ = is_cloud_service_endpoint(domain=domain)
            if is_cloud:
                return True

        # Check remote IP
        if remote_ip:
            is_cloud, _, _ = is_cloud_service_endpoint(ip=remote_ip)
            if is_cloud:
                return True

        return False

    def _has_suspicious_user_agent(self, cmdline: str) -> bool:
        """Check if command line has suspicious user agent.

        Args:
            cmdline: Command line string

        Returns:
            True if suspicious user agent detected
        """
        return any(ua_pattern.search(cmdline) for ua_pattern in self.SUSPICIOUS_USER_AGENTS)

    def _has_post_with_encoding(self, cmdline: str) -> bool:
        """Check if command line has POST request with data encoding.

        Args:
            cmdline: Command line string

        Returns:
            True if suspicious POST pattern detected
        """
        return bool(re.search(r'POST.*(-d|--data|Content-Type.*application)', cmdline, re.IGNORECASE))

    def _create_web_protocol_abuse_evidence(self, conn: Dict, indicators: Dict) -> Evidence:
        """Create evidence for web protocol abuse.

        Args:
            conn: Connection dictionary
            indicators: Dict with suspicious_ua and post_with_encoding flags

        Returns:
            Evidence object
        """
        remote_ip = conn.get('remote_ip', '')
        remote_port = conn.get('remote_port', 0)
        state = conn.get('state', '')
        cmdline = conn.get('cmdline', '')

        local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
        remote_addr = f"{remote_ip}:{remote_port}"

        evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state=state or None,
            pid=conn.get('pid') or None,
        )

        remediation_cmds = [
            f"netstat -tlnp | grep {remote_port}",
            f"curl -v https://{remote_ip}:{remote_port}",
            f"iptables -A OUTPUT -d {remote_ip} -p tcp --dport {remote_port} -j LOG",
        ]

        return self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id='T1071.001',
            attack_tactic=_get_attack_tactic_name('T1071.001'),
            title='Potential Web Protocol C2 Communication',
            description=(
                f'Suspicious HTTP/HTTPS connection detected:\n'
                f'Remote: {remote_ip}:{remote_port}\n'
                f'Command: {cmdline[:150]}'
            ),
            confidence=0.55,
            source_path='network_connections',
            raw_data={
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'cmdline': cmdline[:200],
                'indicators': indicators,
            },
            remediation='Investigate destination endpoint. Verify if traffic is legitimate.',
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )

    def _check_web_protocol_abuse_connection(self, conn: Dict) -> Optional[Evidence]:
        """Check single connection for web protocol abuse indicators.

        Args:
            conn: Connection dictionary

        Returns:
            Evidence if suspicious, None otherwise
        """
        cmdline = conn.get('cmdline', '')
        remote_port = conn.get('remote_port', 0)
        state = conn.get('state', '')

        # Skip if no cmdline or not established
        if not cmdline or state != 'ESTABLISHED':
            return None

        # Skip if should be suppressed
        should_suppress, _ = self._should_suppress_connection(conn)
        if should_suppress:
            return None

        # Skip if whitelisted
        if self._is_connection_whitelisted(conn):
            return None

        # Only check web protocol ports
        if remote_port not in self.WEB_PROTOCOL_PORTS:
            return None

        # Check for suspicious indicators
        has_suspicious_ua = self._has_suspicious_user_agent(cmdline)
        has_post_encoding = self._has_post_with_encoding(cmdline)

        if not has_suspicious_ua and not has_post_encoding:
            return None

        return self._create_web_protocol_abuse_evidence(
            conn,
            indicators={
                'suspicious_ua': has_suspicious_ua,
                'post_with_encoding': has_post_encoding,
            }
        )

    def _detect_c2_communication(self, network_data: Dict) -> List[Evidence]:
        """Detect command and control communication

        Cloud Service Whitelist:
            Legitimate cloud provider API endpoints are excluded from C2 detection
            to prevent false positives in development/cloud environments.

            Examples of whitelisted endpoints:
            - Alibaba Cloud: *.aliyuncs.com, ecs.aliyuncs.com
            - AWS: *.amazonaws.com, sts.amazonaws.com
            - Azure: *.azure.com, management.azure.com
            - GCP: *.googleapis.com, compute.googleapis.com

        ATT&CK: T1071, T1573
        """
        evidences = []

        if not network_data:
            return evidences

        connections = network_data.get('tcp_connections', []) + network_data.get('tcp6_connections', [])

        c2_patterns = [
            (re.compile(r'beacon|callback.*interval', re.IGNORECASE), 'C2 beacon pattern'),
            (re.compile(r'cobaltstrike|sliver|havoc', re.IGNORECASE), 'Known C2 framework'),
            (re.compile(r'tor.*hidden|onion.*routing', re.IGNORECASE), 'Tor anonymization'),
            (re.compile(r'dns.*txt.*query.*long', re.IGNORECASE), 'DNS-based C2 channel'),
        ]

        # Lazy import cloud whitelist
        is_cloud_service_endpoint = _get_cloud_whitelist()
        
        for conn in connections:
            cmdline = conn.get('cmdline', '')
            remote_ip = conn.get('remote_ip', '')
            remote_port = conn.get('remote_port', 0)

            domain_in_cmdline = ""
            if cmdline:
                url_pattern = re.search(r'https?://([a-zA-Z0-9.\-]+)', cmdline)
                if url_pattern:
                    domain_in_cmdline = url_pattern.group(1)

            if domain_in_cmdline:
                is_cloud, provider, reason = is_cloud_service_endpoint(domain=domain_in_cmdline)
                if is_cloud:
                    _get_logger().debug(f"C2 detection skipped: cloud service endpoint {domain_in_cmdline} ({provider})")
                    continue

            if remote_ip:
                is_cloud, provider, reason = is_cloud_service_endpoint(ip=remote_ip)
                if is_cloud:
                    _get_logger().debug(f"C2 detection skipped: cloud service IP {remote_ip} ({provider})")
                    continue

            for pattern, desc in c2_patterns:
                if pattern.search(cmdline):
                    local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                    remote_addr = f"{remote_ip}:{remote_port}"
                    evidence_detail = EvidenceDetail(
                                                local_address=local_addr if local_addr != ":" else None,
                        remote_address=remote_addr if remote_addr != ":" else None,
                        connection_state=conn.get('state') or None,
                        pid=conn.get('pid') or None,
                    )
                    remediation_cmds = [
                        f"netstat -tlnp | grep {remote_port}",
                        f"kill -9 {conn.get('pid', 0)}" if conn.get('pid') else "kill -9 <pid>",
                        f"iptables -A OUTPUT -d {remote_ip} -j DROP",
                        "ss -tnp",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id='T1071',
                        attack_tactic=_get_attack_tactic_name('T1071'),
                        title=f'C2 communication indicator: {desc}',
                        description=f'Connection: {cmdline[:200]}',
                        confidence=0.70,
                        source_path='network_connections',
                        raw_data={'pattern': desc},
                        remediation='Block C2 communication. Isolate system. Investigate.',
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break

        return evidences

    def _detect_dns_tunneling(self, collected_data: dict) -> List[Evidence]:
        """Detect DNS tunneling for data exfiltration and C2 communication
        
        Detects:
        - Unusually long DNS queries (>50 chars)
        - High-entropy subdomain patterns (random-looking)
        - High-frequency DNS requests
        - TXT record abuse
        - Known DNS tunneling tools
        
        ATT&CK: T1048.001, T1071.004
        """
        evidences = []
        
        if not collected_data:
            return evidences
        
        try:
            dns_data = self._get_data(collected_data, "dns")
        except KeyError:
            return evidences
        
        dns_queries = dns_data.get('queries', [])
        domain_query_count = {}
        
        for query in dns_queries:
            domain = query.get('domain', '')
            query_type = query.get('type', '')
            
            if not domain:
                continue
            
            base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            domain_query_count[base_domain] = domain_query_count.get(base_domain, 0) + 1
            
            evidences.extend(self._check_dns_long_domain(domain, query_type))
            evidences.extend(self._check_dns_high_entropy(domain, query_type))
            evidences.extend(self._check_dns_txt_abuse(domain, query_type))
        
        evidences.extend(self._check_dns_high_frequency(domain_query_count))
        evidences.extend(self._check_dns_tunnel_tools(collected_data))
        
        return evidences
    
    def _check_dns_long_domain(self, domain: str, query_type: str) -> List[Evidence]:
        """Check for unusually long domain names indicating DNS tunneling."""
        if len(domain) <= self.DNS_TUNNEL_DOMAIN_LENGTH_THRESHOLD:
            return []
        
        evidence_detail = EvidenceDetail(
                        local_address=None,
            remote_address=domain,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any port 53 -l -n",
            f"dig {domain}",
            "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
        ]
        return [self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.001",
            title=f"DNS Tunneling Indicator: Long Domain",
            description=f"Unusually long DNS query detected ({len(domain)} chars): {domain[:100]}...",
            confidence=0.6,
            raw_data={
                "domain": domain,
                "length": len(domain),
                "query_type": query_type,
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _check_dns_high_entropy(self, domain: str, query_type: str) -> List[Evidence]:
        """Check for high-entropy subdomains indicating random-looking names."""
        if '.' not in domain:
            return []
        
        subdomain = domain.split('.')[0]
        if len(subdomain) <= 10:
            return []
        
        entropy = self._calculate_entropy(subdomain)
        if entropy <= self.DNS_HIGH_ENTROPY_THRESHOLD:
            return []
        
        evidence_detail = EvidenceDetail(
                        local_address=None,
            remote_address=domain,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any port 53 -l -n",
            f"dig {domain}",
            "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
        ]
        return [self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.001",
            title=f"DNS Tunneling Indicator: High Entropy",
            description=f"High-entropy subdomain detected (entropy={entropy:.2f}): {subdomain}",
            confidence=0.65,
            raw_data={
                "domain": domain,
                "subdomain": subdomain,
                "entropy": entropy,
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]
    
    def _check_dns_txt_abuse(self, domain: str, query_type: str) -> List[Evidence]:
        """Check for TXT record abuse commonly used for DNS tunneling."""
        if query_type != 'TXT' or len(domain) <= 30:
            return []
        
        evidence_detail = EvidenceDetail(
                        local_address=None,
            remote_address=domain,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any port 53 -l -n",
            f"dig TXT {domain}",
            "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
        ]
        return [self._create_evidence(
            severity=Severity.LOW,
            attack_id="T1048.001",
            title=f"DNS Tunneling Indicator: TXT Record",
            description=f"Long TXT query detected (potential C2/exfil): {domain[:100]}...",
            confidence=0.5,
            raw_data={
                "domain": domain,
                "query_type": query_type,
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]
    
    def _check_dns_high_frequency(self, domain_query_count: Dict[str, int]) -> List[Evidence]:
        """Check for high-frequency DNS requests to same domain (potential beaconing)."""
        evidences = []
        
        for base_domain, count in domain_query_count.items():
            if count < self.DNS_QUERY_RATE_THRESHOLD:
                continue
            
            evidence_detail = EvidenceDetail(
                                local_address=None,
                remote_address=base_domain,
                connection_state=None,
                pid=None,
            )
            remediation_cmds = [
                "tcpdump -i any port 53 -l -n",
                f"dig {base_domain}",
                "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
            ]
            evidences.append(self._create_evidence(
                severity=Severity.MEDIUM,
                attack_id="T1071.004",
                title=f"DNS Tunneling Indicator: High Frequency",
                description=f"High-frequency DNS queries to {base_domain} ({count} queries)",
                confidence=0.7,
                raw_data={
                    "domain": base_domain,
                    "query_count": count,
                },
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))
        
        return evidences
    
    def _check_dns_tunnel_tools(self, collected_data: dict) -> List[Evidence]:
        """Check for known DNS tunneling tools running as processes."""
        evidences = []
        dns_tunnel_tools = ['iodine', 'dnscat', 'dnscat2', 'tun2socks', 'dns2tcp']
        
        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            return evidences
        
        for proc in process_data.get("processes", []):
            cmdline = proc.get("cmdline", "").lower()
            comm = proc.get("comm", "").lower()
            pid = proc.get("pid", 0)
            
            for tool in dns_tunnel_tools:
                if tool not in cmdline and tool not in comm:
                    continue
                
                evidence_detail = EvidenceDetail(
                                        local_address=None,
                    remote_address=None,
                    connection_state=None,
                    pid=pid if pid else None,
                )
                remediation_cmds = [
                    f"kill -9 {pid}" if pid else "kill -9 <pid>",
                    f"ps aux | grep {tool}",
                    f"netstat -tlnp | grep {pid}" if pid else "netstat -tlnp",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1048.001",
                    title=f"DNS Tunneling Tool Detected: {tool}",
                    description=f"Detected DNS tunneling tool {tool} running (PID {pid})",
                    confidence=0.85,
                    raw_data={
                        "pid": pid,
                        "tool": tool,
                        "cmdline": cmdline[:200],
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
                break
        
        return evidences
    
    def _detect_connection_beaconing(self, connections: List[Dict]) -> List[Evidence]:
        """Detect beaconing patterns indicating C2 communication
        
        Analyzes connection timing patterns to identify:
        - Periodic outbound connections (regular intervals)
        - Consistent connection durations
        - Repeated connections to same destination
        """
        evidences = []
        
        # Group connections by destination
        defaultdict_cls = _get_defaultdict()
        dest_connections = defaultdict_cls(list)
        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            remote_port = conn.get("remote_port", 0)
            dest_key = f"{remote_ip}:{remote_port}"
            
            timestamp = conn.get("timestamp", 0)
            if timestamp and remote_ip:
                dest_connections[dest_key].append({
                    "timestamp": timestamp,
                    "local_process": conn.get("process_name", ""),
                    "state": conn.get("state", "")
                })
        
        # Analyze each destination for beaconing patterns
        for dest_key, conn_list in dest_connections.items():
            if len(conn_list) < 3:
                continue
            
            # Sort by timestamp
            conn_list.sort(key=lambda x: x["timestamp"])
            
            # Calculate inter-connection intervals
            intervals = []
            for i in range(1, len(conn_list)):
                interval = conn_list[i]["timestamp"] - conn_list[i-1]["timestamp"]
                if interval > 0:
                    intervals.append(interval)
            
            if not intervals:
                continue
            
            # Check for regular intervals (low standard deviation)
            if len(intervals) >= 2:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                
                # Coefficient of variation < 0.3 indicates regular timing
                if avg_interval > 0:
                    cv = std_dev / avg_interval
                    
                    if cv < 0.3 and avg_interval < 3600:  # Regular intervals within 1 hour
                        dest_parts = dest_key.split(":")
                        remote_addr = dest_key
                        evidence_detail = EvidenceDetail(
                                                        local_address=None,
                            remote_address=remote_addr if remote_addr != ":" else None,
                            connection_state=conn_list[0].get("state") or None,
                            pid=None,
                        )
                        remediation_cmds = [
                            f"netstat -tlnp | grep {dest_parts[0]}" if dest_parts else "netstat -tlnp",
                            f"ss -tnp dst {dest_parts[0]}",
                            f"iptables -A OUTPUT -d {dest_parts[0]} -j DROP",
                        ]
                        evidence = self._create_evidence(
                            title=f"Potential C2 Beaconing Detected",
                            description=(
                                f"Regular connection pattern detected to {dest_key}:\n"
                                f"Average interval: {avg_interval:.1f}s\n"
                                f"Standard deviation: {std_dev:.1f}s\n"
                                f"Connection count: {len(conn_list)}\n"
                                f"This pattern indicates automated C2 communication."
                            ),
                            severity=Severity.HIGH,
                            confidence=0.75,
                            attack_id="T1071.001",
                            attack_tactic="Command and Control",
                            source_path=f"/proc/net/tcp",
                            raw_data={
                                "destination": dest_key,
                                "avg_interval": avg_interval,
                                "std_dev": std_dev,
                                "coefficient_of_variation": cv,
                                "connection_count": len(conn_list),
                                "pattern": "beaconing"
                            },
                            remediation=(
                                f"Investigate connections to {dest_key}. "
                                f"Check if this is legitimate monitoring or update traffic. "
                                f"Block destination if malicious."
                            ),
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        )
                        evidences.append(evidence)
        
        return evidences
    
    def _detect_data_staging(self, connections: List[Dict], processes: List[Dict]) -> List[Evidence]:
        """Detect data staging patterns before exfiltration
        
        Identifies:
        - Large data transfers to external hosts
        - Compression/archival tool usage with network activity
        - Unusual upload/download ratios
        """
        evidences = []
        
        # Look for large outbound connections
        staging_ports = {443, 8443, 8080, 80, 21, 22, 990}  # HTTPS, FTPS, SSH
        
        for conn in connections:
            remote_port = conn.get("remote_port", 0)
            local_process = conn.get("process_name", "").lower()
            
            # Check for archival/compression tools with network activity
            staging_tools = ['tar', 'zip', 'gzip', '7z', 'rar', 'rsync', 'scp', 'curl', 'wget']
            
            if any(tool in local_process for tool in staging_tools) and remote_port in staging_ports:
                local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                remote_addr = f"{conn.get('remote_ip', '')}:{remote_port}"
                evidence_detail = EvidenceDetail(
                                        local_address=local_addr if local_addr != ":" else None,
                    remote_address=remote_addr if remote_addr != ":" else None,
                    connection_state=conn.get("state") or None,
                    pid=conn.get("pid") or None,
                )
                remediation_cmds = [
                    f"netstat -tlnp | grep {remote_port}",
                    f"ps aux | grep {local_process}",
                    f"lsof -i :{remote_port}",
                ]
                evidence = self._create_evidence(
                    title=f"Potential Data Staging Activity",
                    description=(
                        f"Data staging tool '{local_process}' has active network connection:\n"
                        f"Remote: {conn.get('remote_ip', '')}:{remote_port}\n"
                        f"State: {conn.get('state', '')}"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.70,
                    attack_id="T1560",
                    attack_tactic="Collection",
                    source_path="/proc/net/tcp",
                    raw_data={
                        "process": local_process,
                        "remote_ip": conn.get("remote_ip", ""),
                        "remote_port": remote_port,
                        "pattern": "data_staging"
                    },
                    remediation=(
                        f"Verify if '{local_process}' network activity is authorized. "
                        f"Check for sensitive data compression or transfer."
                    ),
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                )
                evidences.append(evidence)
        
        return evidences
    
    def _collect_connection_states(self, network_data: Dict) -> Tuple[Dict, Dict]:
        """Collect and organize connection states from network data.
        
        Args:
            network_data: Network data dictionary
            
        Returns:
            Tuple of (state_counts, state_details)
        """
        all_connections = (
            network_data.get("tcp_connections", []) +
            network_data.get("tcp6_connections", [])
        )
        
        defaultdict_cls = _get_defaultdict()
        state_counts = defaultdict_cls(int)
        state_details = defaultdict_cls(list)
        
        for conn in all_connections:
            state = conn.get("state", "")
            if state:
                state_counts[state] += 1
                
                if len(state_details[state]) < 10:
                    state_details[state].append({
                        "local_ip": conn.get("local_ip", ""),
                        "local_port": conn.get("local_port", 0),
                        "remote_ip": conn.get("remote_ip", ""),
                        "remote_port": conn.get("remote_port", 0),
                        "pid": conn.get("pid", 0),
                        "process_name": conn.get("process_name", ""),
                    })
        
        return state_counts, state_details
    
    def _update_historical_baselines(self, state_counts: Dict) -> float:
        """Update historical baselines with current counts.
        
        Args:
            state_counts: Current state connection counts
            
        Returns:
            Current timestamp
        """
        time_module = _get_time_module()
        current_time = time_module.time()
        with self._BASELINES_LOCK:
            for state, count in state_counts.items():
                if state not in self._HISTORICAL_BASELINES:
                    self._HISTORICAL_BASELINES[state] = {"counts": [], "timestamps": []}

                baseline = self._HISTORICAL_BASELINES[state]
                baseline["counts"].append(count)
                baseline["timestamps"].append(current_time)

                # Keep only recent samples (last 100 readings)
                if len(baseline["counts"]) > 100:
                    baseline["counts"] = baseline["counts"][-100:]
                    baseline["timestamps"] = baseline["timestamps"][-100:]

        return current_time
    
    def _create_state_anomaly_evidence(
        self,
        state_name: str,
        count: int,
        threshold: int,
        baseline_info: Optional[Dict],
        is_anomalous: bool,
        state_details: List[Dict],
        severity: Severity,
        confidence: float,
        description: str,
        attack_id: str,
        remediation: str,
        remediation_commands: List[str],
        extra_raw_data: Dict = None
    ) -> Evidence:
        """Create evidence for connection state anomaly.
        
        Args:
            state_name: Connection state name (CLOSE_WAIT, TIME_WAIT, etc.)
            count: Current connection count
            threshold: Alert threshold
            baseline_info: Baseline deviation info
            is_anomalous: Whether baseline deviation detected
            state_details: Sample connection details
            severity: Base severity level
            confidence: Base confidence score
            description: Description text
            attack_id: ATT&CK technique ID
            remediation: Remediation text
            remediation_commands: List of remediation commands
            extra_raw_data: Additional raw data fields
            
        Returns:
            Evidence object
        """
        # Adjust severity and confidence based on baseline deviation
        adjusted_severity = severity
        adjusted_confidence = confidence
        
        if is_anomalous and baseline_info:
            deviation_ratio = baseline_info.get("deviation_ratio", 0)
            if deviation_ratio > 5:
                adjusted_severity = Severity.HIGH
            adjusted_confidence = min(0.90, confidence + deviation_ratio * 0.03)
            
            description += (
                f"\nBaseline deviation detected: current {count} vs "
                f"historical avg {baseline_info['avg']:.0f} "
                f"(deviation: {baseline_info['deviation_ratio']:.1f}x)\n"
            )
        
        sample_conn = state_details[0] if state_details else {}
        local_addr = f"{sample_conn.get('local_ip', '')}:{sample_conn.get('local_port', '')}"
        remote_addr = f"{sample_conn.get('remote_ip', '')}:{sample_conn.get('remote_port', '')}"
        
        raw_data = {
            "state": state_name,
            "count": count,
            "threshold": threshold,
            "baseline_avg": baseline_info.get("avg", 0) if baseline_info else 0,
            "deviation_ratio": baseline_info.get("deviation_ratio", 0) if baseline_info else 0,
            "sample_connections": state_details[:5],
        }
        if extra_raw_data:
            raw_data.update(extra_raw_data)
        
        evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state=state_name,
            pid=sample_conn.get("pid") or None,
        )
        
        return self._create_evidence(
            title=f"Abnormal {state_name} connections: {count} detected",
            description=description,
            severity=adjusted_severity,
            confidence=adjusted_confidence,
            attack_id=attack_id,
            attack_tactic=_get_attack_tactic_name(attack_id),
            raw_data=raw_data,
            remediation=remediation,
            evidence_details=evidence_detail,
            remediation_commands=remediation_commands,
        )
    
    def _check_close_wait_anomaly(
        self,
        count: int,
        threshold: int,
        state_details: List[Dict],
        baseline_info: Optional[Dict],
        is_anomalous: bool
    ) -> Optional[Evidence]:
        """Check and create evidence for CLOSE_WAIT anomaly.
        
        Args:
            count: Current CLOSE_WAIT count
            threshold: Alert threshold
            state_details: Sample connection details
            baseline_info: Baseline deviation info
            is_anomalous: Whether baseline deviation detected
            
        Returns:
            Evidence object if anomaly detected, None otherwise
        """
        if count == 0:
            return None
        
        if count <= threshold and not is_anomalous:
            return None
        
        # Find involved processes
        processes_involved = set()
        for detail in state_details:
            if detail.get("process_name"):
                processes_involved.add(detail["process_name"])
        
        description = (
            f"Detected {count} connections in CLOSE_WAIT state "
            f"(threshold: {threshold}).\n"
            f"This indicates application connection leak - remote side closed connections "
            f"but local application hasn't closed its end.\n"
        )
        description += f"Top processes: {', '.join(list(processes_involved)[:5]) if processes_involved else 'unknown'}"
        
        remediation_cmds = [
            "ss -tnp state close-wait",
            "netstat -tnp | grep CLOSE_WAIT",
            "cat /proc/sys/net/ipv4/tcp_keepalive_time",
        ]
        
        return self._create_state_anomaly_evidence(
            state_name="CLOSE_WAIT",
            count=count,
            threshold=threshold,
            baseline_info=baseline_info,
            is_anomalous=is_anomalous,
            state_details=state_details,
            severity=Severity.MEDIUM,
            confidence=0.75,
            description=description,
            attack_id="T1499",
            remediation=(
                "Check application connection pool settings. "
                "Verify proper socket cleanup in application code. "
                "Review processes with most CLOSE_WAIT connections."
            ),
            remediation_commands=remediation_cmds,
            extra_raw_data={"processes": list(processes_involved)[:10]},
        )
    
    def _check_time_wait_anomaly(
        self,
        count: int,
        threshold: int,
        state_details: List[Dict],
        baseline_info: Optional[Dict],
        is_anomalous: bool
    ) -> Optional[Evidence]:
        """Check and create evidence for TIME_WAIT anomaly.
        
        Args:
            count: Current TIME_WAIT count
            threshold: Alert threshold
            state_details: Sample connection details
            baseline_info: Baseline deviation info
            is_anomalous: Whether baseline deviation detected
            
        Returns:
            Evidence object if anomaly detected, None otherwise
        """
        if count == 0:
            return None
        
        if count <= threshold and not is_anomalous:
            return None
        
        description = (
            f"Detected {count} connections in TIME_WAIT state "
            f"(threshold: {threshold}).\n"
            f"This may indicate connection storm or rapid connection churn.\n"
            f"Can exhaust local ports and cause connection failures."
        )
        
        remediation_cmds = [
            "ss -tnp state time-wait",
            "sysctl net.ipv4.tcp_tw_reuse",
            "sysctl net.ipv4.tcp_max_tw_buckets",
        ]
        
        return self._create_state_anomaly_evidence(
            state_name="TIME_WAIT",
            count=count,
            threshold=threshold,
            baseline_info=baseline_info,
            is_anomalous=is_anomalous,
            state_details=state_details,
            severity=Severity.MEDIUM,
            confidence=0.70,
            description=description,
            attack_id="T1498",
            remediation=(
                "Consider enabling tcp_tw_reuse kernel parameter. "
                "Review connection pool reuse. "
                "Check for connection flood or DoS attack."
            ),
            remediation_commands=remediation_cmds,
        )
    
    def _check_fin_wait_anomaly(
        self,
        fin_wait1_count: int,
        fin_wait2_count: int,
        threshold: int,
        baseline_info: Optional[Dict],
        is_anomalous: bool
    ) -> Optional[Evidence]:
        """Check and create evidence for FIN_WAIT anomaly.
        
        Args:
            fin_wait1_count: FIN_WAIT1 connection count
            fin_wait2_count: FIN_WAIT2 connection count
            threshold: Alert threshold
            baseline_info: Baseline deviation info
            is_anomalous: Whether baseline deviation detected
            
        Returns:
            Evidence object if anomaly detected, None otherwise
        """
        total_fin_wait = fin_wait1_count + fin_wait2_count
        
        if total_fin_wait == 0:
            return None
        
        if total_fin_wait <= threshold and not is_anomalous:
            return None
        
        description = (
            f"Detected {total_fin_wait} connections in FIN_WAIT states "
            f"(FIN_WAIT1: {fin_wait1_count}, FIN_WAIT2: {fin_wait2_count}, "
            f"threshold: {threshold}).\n"
            f"High FIN_WAIT count may indicate slow connection teardown or network issues."
        )
        
        remediation_cmds = [
            "ss -tnp state fin-wait-1 state fin-wait-2",
            "sysctl net.ipv4.tcp_fin_timeout",
            "cat /proc/sys/net/ipv4/tcp_fin_timeout",
        ]
        
        return self._create_state_anomaly_evidence(
            state_name="FIN_WAIT",
            count=total_fin_wait,
            threshold=threshold,
            baseline_info=baseline_info,
            is_anomalous=is_anomalous,
            state_details=[],
            severity=Severity.MEDIUM,
            confidence=0.65,
            description=description,
            attack_id="T1499",
            remediation=(
                "Check network latency and packet loss. "
                "Review application connection termination logic. "
                "Consider tuning TCP timeout parameters."
            ),
            remediation_commands=remediation_cmds,
            extra_raw_data={
                "fin_wait1_count": fin_wait1_count,
                "fin_wait2_count": fin_wait2_count,
                "total": total_fin_wait,
            },
        )
    
    def _detect_connection_state_anomalies(self, network_data: Dict) -> List[Evidence]:
        """Detect TCP connection state anomalies.
        
        Detects:
        - CLOSE_WAIT connection leak (> 100 connections)
        - TIME_WAIT connection storm (> 1000 connections)
        - FIN_WAIT accumulation (> 500 connections)
        - Abnormal state distribution patterns
        - Baseline deviation (current count > 3x historical baseline)
        - Rate anomaly (sudden spike in connection states)
        
        ATT&CK:
        - T1498 - Network Denial of Service (connection exhaustion)
        - T1499 - Endpoint Denial of Service (resource exhaustion)
        """
        evidences = []
        
        if not network_data:
            return evidences
        
        try:
            # Step 1: Collect connection states
            state_counts, state_details = self._collect_connection_states(network_data)
            
            if not state_counts:
                return evidences
            
            # Step 2: Update historical baselines
            current_time = self._update_historical_baselines(state_counts)
            
            # Step 3: Check CLOSE_WAIT anomalies
            close_wait_count = state_counts.get("CLOSE_WAIT", 0)
            if close_wait_count > 0:
                is_anomalous, baseline_info = self._check_baseline_deviation(
                    "CLOSE_WAIT", close_wait_count, current_time
                )
                evidence = self._check_close_wait_anomaly(
                    count=close_wait_count,
                    threshold=self.CLOSE_WAIT_THRESHOLD,
                    state_details=state_details.get("CLOSE_WAIT", []),
                    baseline_info=baseline_info,
                    is_anomalous=is_anomalous,
                )
                if evidence:
                    evidences.append(evidence)
            
            # Step 4: Check TIME_WAIT anomalies
            time_wait_count = state_counts.get("TIME_WAIT", 0)
            if time_wait_count > 0:
                is_anomalous, baseline_info = self._check_baseline_deviation(
                    "TIME_WAIT", time_wait_count, current_time
                )
                evidence = self._check_time_wait_anomaly(
                    count=time_wait_count,
                    threshold=self.TIME_WAIT_THRESHOLD,
                    state_details=state_details.get("TIME_WAIT", []),
                    baseline_info=baseline_info,
                    is_anomalous=is_anomalous,
                )
                if evidence:
                    evidences.append(evidence)
            
            # Step 5: Check FIN_WAIT anomalies
            fin_wait1_count = state_counts.get("FIN_WAIT1", 0)
            fin_wait2_count = state_counts.get("FIN_WAIT2", 0)
            if (fin_wait1_count + fin_wait2_count) > 0:
                is_anomalous, baseline_info = self._check_baseline_deviation(
                    "FIN_WAIT", fin_wait1_count + fin_wait2_count, current_time
                )
                evidence = self._check_fin_wait_anomaly(
                    fin_wait1_count=fin_wait1_count,
                    fin_wait2_count=fin_wait2_count,
                    threshold=self.FIN_WAIT_THRESHOLD,
                    baseline_info=baseline_info,
                    is_anomalous=is_anomalous,
                )
                if evidence:
                    evidences.append(evidence)
            
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Connection state anomaly detection failed: {e}")
        
        return evidences
    
    def _check_baseline_deviation(self, state: str, current_count: int, current_time: float) -> Tuple[bool, Dict]:
        """Check if current count significantly deviates from historical baseline
        
        Args:
            state: Connection state (CLOSE_WAIT, TIME_WAIT, FIN_WAIT)
            current_count: Current connection count for this state
            current_time: Current timestamp
            
        Returns:
            Tuple of (is_anomalous, baseline_info_dict)
            baseline_info contains: avg, std_dev, deviation_ratio, sample_count
        """
        with self._BASELINES_LOCK:
            baseline = self._HISTORICAL_BASELINES.get(state, {})
            counts = list(baseline.get("counts", []))

        # Need minimum samples for reliable baseline
        if len(counts) < self.MIN_BASELINE_SAMPLES:
            return False, None
        
        # Use recent samples (last 20 readings)
        recent_counts = counts[-20:]
        
        # Calculate statistics
        avg = sum(recent_counts) / len(recent_counts)
        
        if avg == 0:
            # If historical average is 0, any positive count is anomalous
            return current_count > 0, {"avg": 0, "std_dev": 0, "deviation_ratio": 99999.0, "sample_count": len(recent_counts)}
        
        variance = sum((x - avg) ** 2 for x in recent_counts) / len(recent_counts)
        std_dev = variance ** 0.5
        
        # Calculate deviation ratio (how many times current exceeds baseline)
        deviation_ratio = current_count / avg if avg > 0 else 99999.0
        
        # Anomaly if:
        # 1. Current count > BASELINE_RATE_THRESHOLD * average, OR
        # 2. Current count > avg + 3 * std_dev (statistical outlier)
        is_anomalous = (
            deviation_ratio > self.BASELINE_RATE_THRESHOLD or
            (std_dev > 0 and (current_count - avg) / std_dev > 3)
        )
        
        return is_anomalous, {
            "avg": avg,
            "std_dev": std_dev,
            "deviation_ratio": deviation_ratio,
            "sample_count": len(recent_counts),
        }

    def _detect_per_ip_connection_state_anomalies(self, network_data: Dict) -> List[Evidence]:
        """Detect per-IP TCP connection state anomalies
        
        Detects connection state anomalies grouped by remote IP:
        - Single IP causing CLOSE_WAIT connection leak (> 20 connections)
        - Single IP causing TIME_WAIT connection storm (> 100 connections)
        - Single IP causing FIN_WAIT accumulation (> 50 connections)
        
        ATT&CK:
        - T1498 - Network Denial of Service (targeted connection exhaustion)
        - T1499 - Endpoint Denial of Service (resource exhaustion)
        """
        evidences = []
        
        if not network_data:
            return evidences
        
        try:
            all_connections = (
                network_data.get("tcp_connections", []) +
                network_data.get("tcp6_connections", [])
            )
            
            if not all_connections:
                return evidences
            
            ip_state_counts, ip_state_details = self._collect_per_ip_states(all_connections)
            
            for ip, state_counts in ip_state_counts.items():
                evidences.extend(self._check_per_ip_close_wait(ip, state_counts, ip_state_details))
                evidences.extend(self._check_per_ip_time_wait(ip, state_counts, ip_state_details))
                evidences.extend(self._check_per_ip_fin_wait(ip, state_counts, ip_state_details))
            
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Per-IP connection state anomaly detection failed: {e}")
        
        return evidences
    
    def _collect_per_ip_states(self, connections: List[Dict]) -> Tuple[Dict, Dict]:
        """Group connection states by remote IP.
        
        Returns:
            Tuple of (ip_state_counts, ip_state_details)
        """
        defaultdict_cls = _get_defaultdict()
        ip_state_counts = defaultdict_cls(lambda: defaultdict_cls(int))
        ip_state_details = defaultdict_cls(lambda: defaultdict_cls(list))
        
        for conn in connections:
            state = conn.get("state", "")
            remote_ip = conn.get("remote_ip", "")
            
            if not state or not remote_ip:
                continue
            
            if remote_ip in ["127.0.0.1", "::1"]:
                continue
            
            should_suppress, _ = self._should_suppress_connection(conn)
            if should_suppress:
                continue
            
            ip_state_counts[remote_ip][state] += 1
            
            if len(ip_state_details[remote_ip][state]) < 5:
                ip_state_details[remote_ip][state].append({
                    "local_port": conn.get("local_port", 0),
                    "remote_port": conn.get("remote_port", 0),
                    "pid": conn.get("pid", 0),
                    "process_name": conn.get("process_name", ""),
                })
        
        return ip_state_counts, ip_state_details
    
    def _check_per_ip_close_wait(self, ip: str, state_counts: Dict, ip_state_details: Dict) -> List[Evidence]:
        """Check per-IP CLOSE_WAIT anomalies."""
        close_wait_count = state_counts.get("CLOSE_WAIT", 0)
        if close_wait_count <= self.PER_IP_CLOSE_WAIT_THRESHOLD:
            return []
        
        processes_involved = set()
        for detail in ip_state_details[ip]["CLOSE_WAIT"]:
            if detail.get("process_name"):
                processes_involved.add(detail["process_name"])
        
        sample_detail = ip_state_details[ip]["CLOSE_WAIT"][0] if ip_state_details[ip]["CLOSE_WAIT"] else {}
        local_addr = f":{sample_detail.get('local_port', '')}"
        remote_addr = f"{ip}:{sample_detail.get('remote_port', '')}"
        evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state="CLOSE_WAIT",
            pid=sample_detail.get("pid") or None,
        )
        remediation_cmds = [
            f"ss -tnp dst {ip} state close-wait",
            f"netstat -tnp | grep {ip} | grep CLOSE_WAIT",
            f"iptables -A OUTPUT -d {ip} -j DROP",
        ]
        return [self._create_evidence(
            title=f"Per-IP CLOSE_WAIT anomaly: {ip} has {close_wait_count} connections",
            description=(
                f"Remote IP {ip} has {close_wait_count} connections in CLOSE_WAIT state "
                f"(threshold: {self.PER_IP_CLOSE_WAIT_THRESHOLD}).\n"
                f"This indicates connection leak to specific endpoint - remote side closed "
                f"connections but local application hasn't closed its end.\n"
                f"Top processes: {', '.join(list(processes_involved)[:5]) if processes_involved else 'unknown'}"
            ),
            severity=Severity.MEDIUM,
            confidence=0.80,
            attack_id="T1499",
            attack_tactic=_get_attack_tactic_name("T1499"),
            raw_data={
                "remote_ip": ip,
                "state": "CLOSE_WAIT",
                "count": close_wait_count,
                "threshold": self.PER_IP_CLOSE_WAIT_THRESHOLD,
                "sample_connections": ip_state_details[ip]["CLOSE_WAIT"][:5],
                "processes": list(processes_involved)[:10],
            },
            remediation=(
                f"Investigate connections to {ip}. "
                f"Check application connection handling to remote endpoint. "
                f"Verify if remote service is misbehaving or under attack."
            ),
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]
    
    def _check_per_ip_time_wait(self, ip: str, state_counts: Dict, ip_state_details: Dict) -> List[Evidence]:
        """Check per-IP TIME_WAIT anomalies."""
        time_wait_count = state_counts.get("TIME_WAIT", 0)
        if time_wait_count <= self.PER_IP_TIME_WAIT_THRESHOLD:
            return []
        
        sample_detail = ip_state_details[ip]["TIME_WAIT"][0] if ip_state_details[ip]["TIME_WAIT"] else {}
        local_addr = f":{sample_detail.get('local_port', '')}"
        remote_addr = f"{ip}:{sample_detail.get('remote_port', '')}"
        evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state="TIME_WAIT",
            pid=sample_detail.get("pid") or None,
        )
        remediation_cmds = [
            f"ss -tnp dst {ip} state time-wait",
            f"netstat -tnp | grep {ip} | grep TIME_WAIT",
            f"iptables -A INPUT -s {ip} -j RATE_LIMIT",
        ]
        return [self._create_evidence(
            title=f"Per-IP TIME_WAIT anomaly: {ip} has {time_wait_count} connections",
            description=(
                f"Remote IP {ip} has {time_wait_count} connections in TIME_WAIT state "
                f"(threshold: {self.PER_IP_TIME_WAIT_THRESHOLD}).\n"
                f"This may indicate connection storm or rapid connection churn to specific endpoint.\n"
                f"Can exhaust local ports and cause connection failures to this IP."
            ),
            severity=Severity.MEDIUM,
            confidence=0.75,
            attack_id="T1498",
            attack_tactic=_get_attack_tactic_name("T1498"),
            raw_data={
                "remote_ip": ip,
                "state": "TIME_WAIT",
                "count": time_wait_count,
                "threshold": self.PER_IP_TIME_WAIT_THRESHOLD,
                "sample_connections": ip_state_details[ip]["TIME_WAIT"][:5],
            },
            remediation=(
                f"Review connection pattern to {ip}. "
                f"Check for connection flood or DoS attack targeting this endpoint. "
                f"Consider enabling connection pooling or rate limiting."
            ),
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]
    
    def _check_per_ip_fin_wait(self, ip: str, state_counts: Dict, ip_state_details: Dict) -> List[Evidence]:
        """Check per-IP FIN_WAIT anomalies."""
        fin_wait1_count = state_counts.get("FIN_WAIT1", 0)
        fin_wait2_count = state_counts.get("FIN_WAIT2", 0)
        total_fin_wait = fin_wait1_count + fin_wait2_count
        
        if total_fin_wait <= self.PER_IP_FIN_WAIT_THRESHOLD:
            return []
        
        evidence_detail = EvidenceDetail(
                        local_address=None,
            remote_address=ip,
            connection_state="FIN_WAIT",
            pid=None,
        )
        remediation_cmds = [
            f"ss -tnp dst {ip} state fin-wait-1 state fin-wait-2",
            f"netstat -tnp | grep {ip} | grep FIN_WAIT",
            f"iptables -A INPUT -s {ip} -j DROP",
        ]
        return [self._create_evidence(
            title=f"Per-IP FIN_WAIT anomaly: {ip} has {total_fin_wait} connections",
            description=(
                f"Remote IP {ip} has {total_fin_wait} connections in FIN_WAIT states "
                f"(FIN_WAIT1: {fin_wait1_count}, FIN_WAIT2: {fin_wait2_count}, "
                f"threshold: {self.PER_IP_FIN_WAIT_THRESHOLD}).\n"
                f"High FIN_WAIT count to specific IP may indicate slow connection "
                f"teardown or network issues with this endpoint."
            ),
            severity=Severity.MEDIUM,
            confidence=0.70,
            attack_id="T1499",
            attack_tactic=_get_attack_tactic_name("T1499"),
            raw_data={
                "remote_ip": ip,
                "state": "FIN_WAIT",
                "fin_wait1_count": fin_wait1_count,
                "fin_wait2_count": fin_wait2_count,
                "total": total_fin_wait,
                "threshold": self.PER_IP_FIN_WAIT_THRESHOLD,
            },
            remediation=(
                f"Check network connectivity to {ip}. "
                f"Review application connection termination logic for this endpoint. "
                f"Consider tuning TCP timeout parameters."
            ),
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]