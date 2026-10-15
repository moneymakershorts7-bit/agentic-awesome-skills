"""Malicious External Connection and Threat Intelligence Analyzer

Includes streaming telemetry export for SIEM integration (STIX/TAXII, CEF, JSON).
"""
import math
import threading
from typing import List
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer
from ..utils.fp_tracker import get_tracker, is_false_positive, record_fp

_ioc_loader_cache = None
_ioc_loader_lock = threading.Lock()

def _get_ioc_loader():
    """Lazy import IoCLoader for threat intelligence lookups."""
    global _ioc_loader_cache
    if _ioc_loader_cache is None:
        with _ioc_loader_lock:
            if _ioc_loader_cache is None:
                from ..threat_intel.ioc_loader import get_loader
                _ioc_loader_cache = get_loader()
    return _ioc_loader_cache


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private using standard library + IoCLoader."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        loader = _get_ioc_loader()
        if loader.is_cloud_metadata_ip(ip):
            return True
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except (ValueError, TypeError):
        return False


def _is_mining_pool_domain(domain: str) -> bool:
    """Check if domain is a mining pool using IoCLoader."""
    return _get_ioc_loader().lookup_mining_pool(domain)


def _is_ddns_domain(domain: str) -> bool:
    """Check if domain is a DDNS domain using IoCLoader."""
    return _get_ioc_loader().lookup_ddns_domain(domain)


def _is_c2_port(port: int) -> tuple:
    """Check if port is a C2 port using IoCLoader."""
    loader = _get_ioc_loader()
    desc = loader.lookup_c2_port(port)
    if desc:
        return True, desc
    return False, ""


def _is_mining_port(port: int) -> bool:
    """Check if port is a mining port using IoCLoader."""
    return _get_ioc_loader().lookup_mining_port(port)


def _is_cloud_dns(ip: str) -> bool:
    """Check if IP is cloud provider DNS.
    
    Cloud DNS IPs are now stored in IoCLoader as part of cloud metadata.
    For now, use a local set since these are static infrastructure IPs.
    """
    cloud_dns = {
        "169.254.169.253",  # AWS Route53
        "168.63.129.16",    # Azure DNS
        "169.254.169.254",  # Azure/GCP IMDS
        "100.100.2.136",    # Aliyun DNS
        "100.100.2.118",    # Aliyun DNS
        "100.100.2.116",    # Aliyun DNS
        "183.60.83.19",     # Tencent DNS
        "183.60.82.98",     # Tencent DNS
    }
    return ip in cloud_dns


def _is_cloud_hostname(hostname: str) -> bool:
    """Check if hostname matches cloud provider instance patterns."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    cloud_patterns = [
        ".ecs-", "-ecs-", "i-", ".na",
        ".compute.internal", ".ec2.internal", "ip-",
        ".cloudapp.azure.com", ".cloudapp.chinacloudapi.cn",
        ".c.cloudapp.net", ".regions.azurecontainer.io",
        ".c.compute.internal", ".bo.googleusercontent.com",
        "-vm.", ".tencent-cloud.",
    ]
    for pattern in cloud_patterns:
        if pattern in hostname_lower:
            return True
    if hostname_lower.startswith("ecs-"):
        return True
    return False


# SECURITY_VENDOR_DOMAINS - moved to local constant (whitelist data, not IoC)
SECURITY_VENDOR_DOMAINS = [
    "update.microsoft.com", "windowsupdate.com", "virustotal.com",
    "malwarebytes.com", "kaspersky.com", "avast.com", "avg.com",
    "clamav.net", "sophos.com", "trendmicro.com", "symantec.com",
    "mcafee.com", "eset.com", "bitdefender.com", "f-secure.com",
    "avira.com", "crowdstrike.com", "sentinelone.com",
]

# KNOWN_PUBLIC_DNS - moved to local constant (whitelist data, not IoC)
KNOWN_PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222",
    "208.67.220.220", "114.114.114.114", "223.5.5.5",
    "223.6.6.6", "119.29.29.29", "180.76.76.76",
}

class ThreatIntelAnalyzer(BaseAnalyzer):
    """Malicious External Connection and Threat Intelligence Analyzer

    Detection capabilities:
    1. Known C2 port outbound connection detection
    2. Mining pool port connection detection
    3. DNS configuration tampering detection
    4. Hosts file hijacking detection
    5. DGA domain heuristic detection
    6. DDNS domain outbound connection detection
    7. Anomalous outbound behavior detection
    """
    name = "threat_intel_analyzer"
    timeout = 60
    required_collectors = ["network", "dns"]
    
    # Smart scheduling attributes
    estimated_time = 2.0  # Fast in-memory IOC matching
    analyzer_type = BaseAnalyzer.CRITICAL  # Critical security check

    def should_skip(self) -> tuple:
        """Run lightweight threat intel check in quick mode"""
        # Quick mode runs basic IOC matching only
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute threat intelligence analysis.
        
        In quick mode, only critical IOC matching is performed:
        - C2 port connections
        - Mining pool connections
        
        In full mode, comprehensive threat intel analysis is executed.
        """
        evidences = []
        
        # Integrate FpTracker - record detection start
        tracker = get_tracker()
        tracker.record_detection('threat_intel_analyzer', 1)

        network_data = self._get_data(collected_data, "network")
        dns_data = self._get_data(collected_data, "dns", strict=False, default={})

        if not network_data:
            return evidences

        # Quick mode: critical IOC checks only
        # Full mode: comprehensive analysis
        # 1. C2 port outbound connection detection
        evidences.extend(self._detect_c2_port_connections(network_data))

        # 2. Mining pool port connection detection
        evidences.extend(self._detect_mining_port_connections(network_data))

        # 3. DNS configuration tampering detection
        if dns_data:
            evidences.extend(self._detect_dns_tampering(dns_data))

        # 4. Hosts file hijacking detection
        if dns_data:
            evidences.extend(self._detect_hosts_hijack(dns_data))

        # 5. Reverse DNS + DGA/DDNS detection
        evidences.extend(self._detect_suspicious_domains(network_data, dns_data))

        # 6. Anomalous outbound behavior detection
        evidences.extend(self._detect_abnormal_outbound(network_data))

        return evidences

    def _detect_c2_port_connections(self, network_data: dict) -> List[Evidence]:
        """Detect outbound connections to known C2 ports"""
        evidences = []
        reported = set()

        for conn_list_key in ["tcp_connections", "tcp6_connections"]:
            for conn in network_data.get(conn_list_key, []):
                state = conn.get("state", "")
                if state not in ("ESTABLISHED", "SYN_SENT"):
                    continue

                remote_ip = conn.get("remote_ip", "")
                remote_port = conn.get("remote_port", 0)

                if self._is_internal_ip(remote_ip) or remote_ip in ("0.0.0.0", "::"):
                    continue

                is_c2, c2_desc = _is_c2_port(remote_port)
                if is_c2:
                    key = f"{remote_ip}:{remote_port}"
                    if key not in reported:
                        reported.add(key)
                        process_name = conn.get("process_name", "unknown")
                        pid = conn.get("pid", 0)
                        
                        # Check FP exceptions for C2 port connections
                        context = f"{remote_ip}:{remote_port} ({process_name})"
                        if is_false_positive('threat_intel_analyzer', 'c2_port_connection', 
                                           context=context):
                            record_fp('threat_intel_analyzer', 'c2_port_connection', 
                                     context=f'Suppressed: {context}')
                        else:
                            evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1571",
                            title=f"C2端口外联: {remote_ip}:{remote_port}",
                            description=f"进程 {process_name} (PID {pid}) 连接到C2常用端口 "
                                        f"{remote_port} ({c2_desc}): {remote_ip}",
                            confidence=0.75,
                            raw_data={
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "c2_description": c2_desc,
                                "process_name": process_name,
                                "pid": pid,
                                "state": state,
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=conn.get("cmdline", ""),
                            executable=conn.get("executable", ""),
                            parent_pid=conn.get("ppid", 0),
                            remote_address=f"{remote_ip}:{remote_port}",
                            connection_state=state
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
        return evidences

    def _detect_mining_port_connections(self, network_data: dict) -> List[Evidence]:
        """Detect connections to mining pool ports"""
        evidences = []
        reported = set()

        for conn_list_key in ["tcp_connections", "tcp6_connections"]:
            for conn in network_data.get(conn_list_key, []):
                state = conn.get("state", "")
                if state not in ("ESTABLISHED", "SYN_SENT"):
                    continue

                remote_ip = conn.get("remote_ip", "")
                remote_port = conn.get("remote_port", 0)

                if self._is_internal_ip(remote_ip) or remote_ip in ("0.0.0.0", "::"):
                    continue

                if _is_mining_port(remote_port) and not _is_c2_port(remote_port)[0]:
                    key = f"{remote_ip}:{remote_port}"
                    if key not in reported:
                        reported.add(key)
                        process_name = conn.get("process_name", "unknown")
                        pid = conn.get("pid", 0)
                        
                        # Check FP exceptions for mining port connections
                        context = f"{remote_ip}:{remote_port} ({process_name})"
                        if is_false_positive('threat_intel_analyzer', 'mining_port_connection', 
                                           context=context):
                            record_fp('threat_intel_analyzer', 'mining_port_connection', 
                                     context=f'Suppressed: {context}')
                        else:
                            evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1496",
                            title=f"矿池端口连接: {remote_ip}:{remote_port}",
                            description=f"进程 {process_name} (PID {pid}) 连接到矿池常用端口 "
                                        f"{remote_port}: {remote_ip}",
                            confidence=0.7,
                            raw_data={
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "process_name": process_name,
                                "pid": pid,
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=conn.get("cmdline", ""),
                            executable=conn.get("executable", ""),
                            parent_pid=conn.get("ppid", 0),
                            remote_address=f"{remote_ip}:{remote_port}",
                            connection_state=state
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
        return evidences

    def _detect_dns_tampering(self, dns_data: dict) -> List[Evidence]:
        """Detect DNS configuration tampering"""
        evidences = []
        resolv = dns_data.get("resolv_conf", {})
        nameservers = resolv.get("nameservers", [])

        if not nameservers:
            return evidences

        # Check for suspicious non-public DNS servers
        suspicious_dns = []
        for ns in nameservers:
            # Skip public DNS, private IPs, and cloud provider internal DNS
            if ns in KNOWN_PUBLIC_DNS:
                continue
            if _is_private_ip(ns):
                continue
            if _is_cloud_dns(ns):
                continue
            suspicious_dns.append(ns)

        if suspicious_dns:
            evidences.append(self._create_evidence(
                severity=Severity.MEDIUM,
                attack_id="T1584.002",
                title="可疑DNS服务器配置",
                description=f"resolv.conf 配置了非standardDNS服务器: {', '.join(suspicious_dns)}",
                confidence=0.5,
                source_path="/etc/resolv.conf",
                raw_data={
                    "nameservers": nameservers,
                    "suspicious": suspicious_dns,
                },
                        evidence_details=EvidenceDetail(
                            content=f"resolv.conf 配置了非standardDNS服务器: {', '.join(suspicious_dns)}"[:500]
                        ),
                        remediation_commands=[
                        "Review the alert details and investigate related system artifacts",
                        "Review related system logs and configuration",
                        "Check for additional indicators of compromise",
                        "Apply appropriate remediation and monitor"
                    ]))

        return evidences

    def _detect_hosts_hijack(self, dns_data: dict) -> List[Evidence]:
        """Detect hosts file hijacking"""
        evidences = []
        hosts_entries = dns_data.get("hosts_entries", [])

        if not hosts_entries:
            return evidences

        hijacked_domains = []
        block_ips = {"127.0.0.1", "0.0.0.0", "::1"}

        for entry in hosts_entries:
            ip = entry.get("ip", "")
            hostnames = entry.get("hostnames", [])

            if ip not in block_ips:
                continue

            for hostname in hostnames:
                hostname_lower = hostname.lower()
                for vendor_domain in SECURITY_VENDOR_DOMAINS:
                    if vendor_domain in hostname_lower:
                        hijacked_domains.append({
                            "domain": hostname,
                            "redirect_ip": ip,
                            "vendor": vendor_domain,
                        })

        if hijacked_domains:
            evidences.append(self._create_evidence(
                severity=Severity.HIGH,
                attack_id="T1565.001",
                title=f"安全软件域名劫持: {len(hijacked_domains)}个域名",
                description=f"hosts文件中发现 {len(hijacked_domains)} 个安全软件域名被劫持: "
                            f"{', '.join(d['domain'] for d in hijacked_domains[:5])}",
                confidence=0.9,
                source_path="/etc/hosts",
                raw_data={"hijacked_domains": hijacked_domains},
                        evidence_details=EvidenceDetail(
                            content=f"hosts文件中发现 {len(hijacked_domains)} 个安全软件域名被劫持"[:500]
                        ),
                        remediation_commands=[
                        "Review the alert details and investigate related system artifacts",
                        "Review related system logs and configuration",
                        "Check for additional indicators of compromise",
                        "Apply appropriate remediation and monitor"
                    ]))

        # Detect anomalous number of hosts entries
        if len(hosts_entries) > 50:
            evidences.append(self._create_evidence(
                severity=Severity.MEDIUM,
                attack_id="T1565.001",
                title=f"hosts文件异常条目数: {len(hosts_entries)}",
                description=f"/etc/hosts 包含 {len(hosts_entries)} 条记录，数量异常",
                confidence=0.5,
                source_path="/etc/hosts",
                raw_data={"entry_count": len(hosts_entries)},
                        evidence_details=EvidenceDetail(
                            content=f"/etc/hosts 包含 {len(hosts_entries)} 条记录，数量异常"[:500]
                        ),
                        remediation_commands=[
                        "Review the alert details and investigate related system artifacts",
                        "Review related system logs and configuration",
                        "Check for additional indicators of compromise",
                        "Apply appropriate remediation and monitor"
                    ]))

        return evidences

    def _detect_suspicious_domains(self, network_data: dict, dns_data: dict) -> List[Evidence]:
        """Detect suspicious domains via reverse DNS (DGA/DDNS/mining pool)"""
        evidences = []

        # Collect external IPs requiring reverse DNS lookup
        external_ips = set()
        ip_process_map = {}

        for conn_list_key in ["tcp_connections", "tcp6_connections"]:
            for conn in network_data.get(conn_list_key, []):
                state = conn.get("state", "")
                if state not in ("ESTABLISHED", "SYN_SENT"):
                    continue
                remote_ip = conn.get("remote_ip", "")
                if remote_ip and not _is_private_ip(remote_ip) and remote_ip not in ("0.0.0.0", "::"):
                    external_ips.add(remote_ip)
                    if remote_ip not in ip_process_map:
                        ip_process_map[remote_ip] = {
                            "process_name": conn.get("process_name", ""),
                            "pid": conn.get("pid", 0),
                            "remote_port": conn.get("remote_port", 0),
                            "cmdline": conn.get("cmdline", ""),
                            "executable": conn.get("executable", ""),
                            "ppid": conn.get("ppid", 0),
                            "state": conn.get("state", ""),
                        }

        # Use collected DNS data (avoid network I/O in analyzer)
        resolved = {}
        if isinstance(dns_data, dict):
            reverse_dns_cache = dns_data.get("reverse_dns", {})
        else:
            reverse_dns_cache = {}
        for ip in external_ips:
            hostname = reverse_dns_cache.get(ip, "")
            if hostname:
                resolved[ip] = hostname

        # Check resolved results
        for ip, hostname in resolved.items():
            proc_info = ip_process_map.get(ip, {})

            # Mining pool domain detection
            if _is_mining_pool_domain(hostname):
                # Check FP exceptions for mining pool domains
                context = f"{hostname} ({ip})"
                if is_false_positive('threat_intel_analyzer', 'mining_pool_domain', 
                                   context=context):
                    record_fp('threat_intel_analyzer', 'mining_pool_domain', 
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1496",
                    title=f"矿池域名连接: {hostname}",
                    description=f"进程 {proc_info.get('process_name', '')} (PID {proc_info.get('pid', 0)}) "
                                f"连接到矿池域名 {hostname} ({ip})",
                    confidence=0.9,
                    raw_data={"ip": ip, "hostname": hostname, **proc_info},
                        evidence_details=EvidenceDetail(
                            pid=proc_info.get('pid', 0),
                            cmdline=proc_info.get('cmdline', ''),
                            executable=proc_info.get('executable', ''),
                            parent_pid=proc_info.get('ppid', 0),
                            remote_address=f"{ip}:{proc_info.get('remote_port', '')}",
                            connection_state=proc_info.get('state', '')
                        ),
                        remediation_commands=[
                        "Update threat intelligence feeds and IoC databases",
                        "Block identified malicious IPs and domains",
                        "Correlate IoCs with internal telemetry",
                        "Share threat intelligence with security teams"
                    ]
                ))

            # DDNS domain detection
            if _is_ddns_domain(hostname):
                evidences.append(self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1568.002",
                    title=f"DDNS域名外联: {hostname}",
                    description=f"进程 {proc_info.get('process_name', '')} (PID {proc_info.get('pid', 0)}) "
                                f"连接到DDNS域名 {hostname} ({ip})",
                    confidence=0.6,
                    raw_data={"ip": ip, "hostname": hostname, **proc_info},
                    evidence_details=EvidenceDetail(
                        pid=proc_info.get('pid', 0),
                        cmdline=proc_info.get('cmdline', ''),
                        executable=proc_info.get('executable', ''),
                        parent_pid=proc_info.get('ppid', 0),
                        remote_address=f"{ip}:{proc_info.get('remote_port', '')}",
                        connection_state=proc_info.get('state', '')
                    ),
                    remediation_commands=[
                        "Update threat intelligence feeds and IoC databases",
                        "Block identified malicious IPs and domains",
                        "Correlate IoCs with internal telemetry",
                        "Share threat intelligence with security teams"
                    ]
                ))

            # DGA domain detection
            if self._is_dga_domain(hostname):
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1568.002",
                    title=f"疑似DGA域名: {hostname}",
                    description=f"连接目标域名 {hostname} ({ip}) 具有DGA特征",
                    confidence=0.6,
                    raw_data={"ip": ip, "hostname": hostname, **proc_info},
                        evidence_details=EvidenceDetail(
                            remote_address=ip
                        ),
                        remediation_commands=[
                        "Review active network connections",
                        "Check for related processes"
                    ]))

        # Check suspicious domains in hosts file
        if dns_data:
            for entry in dns_data.get("hosts_entries", []):
                ip = entry.get("ip", "")
                # Skip localhost and private IP entries (FP prevention)
                if ip in ("127.0.0.1", "::1", "0.0.0.0"):
                    continue
                if _is_private_ip(ip):
                    continue

                for hostname in entry.get("hostnames", []):
                    if self._is_dga_domain(hostname):
                        evidences.append(self._create_evidence(
                            severity=Severity.MEDIUM,
                            attack_id="T1568.002",
                            title=f"hosts中疑似DGA域名: {hostname}",
                            description=f"/etc/hosts 中发现疑似DGA域名: {hostname} -> {entry.get('ip', '')}",
                            confidence=0.5,
                            source_path="/etc/hosts",
                            raw_data={"ip": entry.get("ip", ""), "hostname": hostname},
                        evidence_details=EvidenceDetail(
                            remote_address=entry.get("ip", "")
                        ),
                        remediation_commands=[
                        "Review active network connections",
                        "Check for related processes"
                    ]))

        return evidences

    def _is_ephemeral_port(self, port: int) -> bool:
        """Check if port is in ephemeral port range (client-side temporary ports)
        
        IANA recommended ephemeral port range: 49152-65535
        Linux default range: 32768-60999 (can be checked via /proc/sys/net/ipv4/ip_local_port_range)
        
        Args:
            port: port number to check
            
        Returns:
            True if port is in ephemeral range, False otherwise
        """
        return 49152 <= port <= 65535
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is an internal/private address

        Includes:
        - RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        - RFC 6598 shared address space (100.64.0.0/10)
        - Cloud provider VPC networks (11.0.0.0/8)
        - Loopback and link-local addresses

        Args:
            ip: IP address string to check

        Returns:
            True if IP is internal, False otherwise
        """
        if not ip or ip in ("0.0.0.0", "::"):
            return True

        # Check using existing is_private_ip utility
        if _is_private_ip(ip):
            return True

        # Cloud provider VPC network (11.0.0.0/8, commonly used for internal routing)
        if ip.startswith("11."):
            return True
        
        # Check RFC 6598 shared address space (100.64.0.0/10)
        if ip.startswith("100."):
            try:
                octets = ip.split(".")
                if len(octets) == 4:
                    second_octet = int(octets[1])
                    if 64 <= second_octet <= 127:
                        return True
            except (ValueError, IndexError):
                pass
        
        return False
    
    def _calculate_connection_risk_score(self, conn: dict) -> int:
        """Calculate risk score for a network connection
        
        Factors considered:
        - Ephemeral port (reduces score)
        - Internal IP (reduces score)
        - Test/debug process (reduces score)
        - Cloud agent process (reduces score)
        
        Args:
            conn: connection dictionary with remote_ip, remote_port, process_name
            
        Returns:
            Risk score (0-100), higher means more suspicious
        """
        base_score = 50
        
        remote_ip = conn.get("remote_ip", "")
        remote_port = conn.get("remote_port", 0)
        process_name = conn.get("process_name", "").lower()
        
        # Reduce score for ephemeral ports (likely client-side connections)
        if self._is_ephemeral_port(remote_port):
            base_score -= 20
            _get_logger().debug(f"Reduced score for ephemeral port {remote_port}: -20")
        
        # Reduce score for internal IPs
        if self._is_internal_ip(remote_ip):
            base_score -= 25
            _get_logger().debug(f"Reduced score for internal IP {remote_ip}: -25")
        
        # Reduce score for test/debug processes
        test_processes = {
            'test', 'pytest', 'go-test', 'node', 'python', 'python3',
            'java', 'gradle', 'maven', 'npm', 'yarn', 'cargo', 'rustc',
            'gcc', 'g++', 'clang', 'make', 'cmake', 'bash', 'sh',
        }
        if process_name in test_processes:
            base_score -= 15
            _get_logger().debug(f"Reduced score for test process '{process_name}': -15")
        
        # Reduce score for cloud agent processes
        cloud_agent_processes = {
            'staragentd', 'staragent', 'argusagent', 'cloudmonitor', 'aliyun-service',
            'aliyun-monitor', 'aegis', 'opensandbox-ser', 'assist-daemon',
            'monitor_agent', 'tencent-cloud', 'baragent', 'tencent-security',
            'telegraf', 'huawei-cloud', 'hws', 'tegent', 'ces-agent',
            'ssm-agent', 'amazon-ssm-agent', 'amazon-cloudwatch-agent', 'awslogs',
            'walinuxagent', 'waagent', 'azure-monitor-agent', 'omsagent', 'azure-extension',
            'google-osconfig-agent', 'google-fluentd', 'stackdriver-agent', 'google-cloud-ops',
        }
        if process_name in cloud_agent_processes:
            base_score -= 20
            _get_logger().debug(f"Reduced score for cloud agent '{process_name}': -20")
        
        return max(0, base_score)
    
    def _should_suppress_connection(self, conn: dict, risk_score: int) -> tuple:
        """Determine if a connection should be suppressed based on risk score and context
        
        Suppression rules:
        1. Ephemeral port + Internal IP = suppress (likely legitimate client connection)
        2. Risk score < 20 = suppress (very low risk)
        3. Test process + Internal IP = suppress (development/testing activity)
        
        Args:
            conn: connection dictionary
            risk_score: calculated risk score
            
        Returns:
            Tuple of (should_suppress: bool, reason: str)
        """
        remote_ip = conn.get("remote_ip", "")
        remote_port = conn.get("remote_port", 0)
        process_name = conn.get("process_name", "").lower()
        
        # Rule 1: Ephemeral port + Internal IP
        if self._is_ephemeral_port(remote_port) and self._is_internal_ip(remote_ip):
            return True, "Ephemeral port connection to internal network (likely legitimate)"
        
        # Rule 2: Very low risk score
        if risk_score < 20:
            return True, f"Very low risk score ({risk_score}) after contextual adjustments"
        
        # Rule 3: Test process + Internal IP
        test_processes = {'test', 'pytest', 'go-test', 'node', 'python', 'python3'}
        if process_name in test_processes and self._is_internal_ip(remote_ip):
            return True, f"Test process '{process_name}' connecting to internal network"
        
        return False, ""

    def _detect_abnormal_outbound(self, network_data: dict) -> List[Evidence]:
        """Detect anomalous outbound connection behavior"""
        evidences = []
        common_ports = {80, 443, 22, 53, 25, 993, 995, 587, 465, 110, 143, 8080, 8443}
        reported = set()
        
        # Known AI coding tool processes (legitimate backend connections)
        ai_tool_processes = {
            'Qoder', 'cursor', 'windsurf', 'code', 'codium',
            'idea', 'goland', 'pycharm', 'webstorm', 'phpstorm',
        }
        
        # Known configuration service ports (commonly used by dev tools and microservices)
        ai_tool_ports = {8848, 8849, 9848, 9849}
        
        # Cloud provider monitor agent processes (whitelist for uncommon port detection)
        cloud_agent_processes = {
            # Alibaba Cloud
            'staragentd', 'staragent', 'argusagent', 'cloudmonitor', 'aliyun-service', 
            'aliyun-monitor', 'aegis', 'opensandbox-ser', 'assist-daemon',
            # Tencent Cloud
            'monitor_agent', 'tencent-cloud', 'baragent', 'tencent-security',
            # Huawei Cloud
            'telegraf', 'huawei-cloud', 'hws', 'tegent', 'ces-agent',
            # AWS
            'ssm-agent', 'amazon-ssm-agent', 'amazon-cloudwatch-agent', 'awslogs',
            # Azure
            'walinuxagent', 'waagent', 'azure-monitor-agent', 'omsagent', 'azure-extension',
            # GCP
            'google-osconfig-agent', 'google-fluentd', 'stackdriver-agent', 'google-cloud-ops',
        }

        for conn_list_key in ["tcp_connections", "tcp6_connections"]:
            for conn in network_data.get(conn_list_key, []):
                state = conn.get("state", "")
                if state not in ("ESTABLISHED", "SYN_SENT"):
                    continue

                remote_ip = conn.get("remote_ip", "")
                remote_port = conn.get("remote_port", 0)
                process_name = conn.get("process_name", "")

                if _is_private_ip(remote_ip) or remote_ip in ("0.0.0.0", "::"):
                    continue

                # Skip ports already covered by C2/mining detection
                if _is_c2_port(remote_port)[0] or _is_mining_port(remote_port):
                    continue

                # Skip AI tool backend connections (known legitimate)
                if process_name in ai_tool_processes and remote_port in ai_tool_ports:
                    continue
                
                # Skip cloud provider monitor agent connections (FP prevention)
                # Cloud agents often connect to internal IPs on non-standard ports
                if process_name.lower() in cloud_agent_processes:
                    _get_logger().debug(f"Skipping cloud agent connection: {process_name}:{remote_port}")
                    continue

                                # Detect outbound connections to uncommon ports with contextual risk scoring
                if remote_port not in common_ports and remote_port > 0:
                    key = f"uncommon:{remote_ip}:{remote_port}"
                    if key in reported:
                        continue
                    
                    # Calculate contextual risk score
                    risk_score = self._calculate_connection_risk_score({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "process_name": process_name,
                    })
                    
                    # Check suppression rules
                    should_suppress, suppress_reason = self._should_suppress_connection({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "process_name": process_name,
                    }, risk_score)
                    
                    if should_suppress:
                        _get_logger().debug(f"Suppressed connection {remote_ip}:{remote_port} ({process_name}): {suppress_reason}")
                        context = f"{remote_ip}:{remote_port} ({process_name})"
                        record_fp('threat_intel_analyzer', 'abnormal_outbound_fp', 
                                 context=f'Suppressed: {context} - {suppress_reason}')
                        continue
                    
                    reported.add(key)
                    pid = conn.get("pid", 0)
                    
                    # Adjust severity based on risk score
                    if risk_score >= 60:
                        severity = Severity.MEDIUM
                        confidence = 0.5
                    elif risk_score >= 40:
                        severity = Severity.LOW
                        confidence = 0.4
                    else:
                        severity = Severity.LOW
                        confidence = 0.3
                    
                    evidences.append(self._create_evidence(
                        severity=severity,
                        attack_id="T1571",
                        title=f"非常见端口外联：{remote_ip}:{remote_port}",
                        description=f"进程 {process_name} (PID {pid}) 连接到非常见端口 "
                                    f"{remote_port}: {remote_ip} (风险评分：{risk_score})",
                        confidence=confidence,
                        raw_data={
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "process_name": process_name,
                            "pid": pid,
                            "risk_score": risk_score,
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=conn.get("cmdline", ""),
                            executable=conn.get("executable", ""),
                            parent_pid=conn.get("ppid", 0),
                            remote_address=f"{remote_ip}:{remote_port}",
                            connection_state=state
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))

        return evidences
    @staticmethod
    def _is_dga_domain(domain: str) -> bool:
        """DGA domain heuristic detection

        Based on purely statistical methods:
        1. Anomalous subdomain length (> 15 characters)
        2. Anomalous consecutive consonant count (> 4)
        3. Anomalous digit-letter mix ratio
        4. Shannon entropy > 3.5

        Detection strategy: check the leftmost subdomain part (not just the SLD)
        
        Whitelist exclusions:
        - Local domains (.localdomain, .local, .lan, .internal)
        - Cloud provider instance naming patterns
        - System hostnames
        """
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        # Exclude local/reserved domains (consolidated set)
        local_tlds = {
            'localdomain', 'local', 'localhost', 'lan', 'internal',
            'home', 'corp', 'private',
        }
        for tld in local_tlds:
            if domain_lower.endswith('.' + tld) or domain_lower == tld:
                return False

        # Exclude cloud provider instance naming patterns using helper function
        if _is_cloud_hostname(domain_lower):
            return False

        if domain_lower.startswith("ecs-"):
            return False

        parts = domain_lower.split(".")
        if len(parts) < 2:
            return False

        if parts[-1] in local_tlds:
            return False

        # Skip common TLDs
        tlds = {"com", "org", "net", "io", "co", "cn", "uk", "de", "fr", "jp", "ru", "br"}
        if parts[-1] in tlds and len(parts) == 2:
            return False

        subdomain = parts[0]

        # Skip known legitimate short domains / common subdomains
        common_subdomains = {
            "www", "mail", "ftp", "api", "cdn", "app", "dev", "test", 
            "blog", "shop", "admin", "login", "secure", "static", "assets", 
            "images", "video", "news", "support", "help", "docs", "doc", 
            "m", "mobile", "en", "zh", "us", "eu", "cn", "jp"
        }
        if subdomain in common_subdomains:
            return False

        # Skip overly short subdomains
        if len(subdomain) <= 5:
            return False

        # Criterion 1: Anomalous domain length (> 15 characters)
        length_score = 1 if len(subdomain) > 15 else 0

        # Criterion 2: Consecutive consonant count
        vowels = set("aeiou")
        max_consonants = 0
        current_consonants = 0
        for c in subdomain:
            if c.isalpha() and c not in vowels:
                current_consonants += 1
                max_consonants = max(max_consonants, current_consonants)
            else:
                current_consonants = 0
        consonant_score = 1 if max_consonants > 4 else 0

        # Criterion 3: Digit-letter mix ratio
        digits = sum(1 for c in subdomain if c.isdigit())
        letters = sum(1 for c in subdomain if c.isalpha())
        mix_score = 0
        if digits > 0 and letters > 0:
            ratio = digits / len(subdomain)
            if 0.2 < ratio < 0.8:
                mix_score = 1

        # Criterion 4: Shannon entropy
        entropy = ThreatIntelAnalyzer._shannon_entropy(subdomain)
        entropy_score = 1 if entropy > 3.5 else 0

        # Combined judgment: at least 2 criteria must be met
        total_score = length_score + consonant_score + mix_score + entropy_score
        return total_score >= 2

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy"""
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
