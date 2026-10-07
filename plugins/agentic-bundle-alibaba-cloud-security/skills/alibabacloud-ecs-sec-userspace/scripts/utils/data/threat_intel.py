"""Built-in Threat Intelligence Database

Provides threat intelligence data including malicious IPs, domains, ports, etc., for network exfiltration detection.
Data sources: Open source threat intelligence summaries, for heuristic detection reference only.
"""
import ipaddress
from typing import Dict, Tuple

# Threat intelligence version metadata
THREAT_INTEL_VERSION = "2026.03.30"
THREAT_INTEL_UPDATED = "2026-03-30"
THREAT_INTEL_SOURCE = "sec-userspace team"


# Known C2/malicious service common ports
C2_PORTS = {
    4444: "Metasploit default",
    4445: "Metasploit alt",
    5555: "Android debug / Mining",
    6666: "IRC botnet",
    6667: "IRC botnet",
    6697: "IRC over TLS",
    8888: "Mining pool",
    9999: "Mining pool",
    1337: "Backdoor common",
    31337: "Back Orifice",
    12345: "NetBus",
    50050: "Cobalt Strike",
    2222: "Backdoor SSH",
    1234: "Common backdoor",
    7777: "Common C2",
    48101: "Mirai default",
    # Added: Common remote control and C2 ports (2025-2026 threat intelligence)
    4443: "Cobalt Strike HTTPS",
    8080: "HTTP proxy/C2",
    8443: "HTTPS C2 common",
    9001: "Tor relay/common C2",
    9030: "Tor default",
    1080: "SOCKS proxy",
    9200: "Elasticsearch C2",
    5900: "VNC backdoor",
    5901: "VNC backdoor alt",
    11111: "memcached exploitation",
    6379: "Redis backdoor",
    27017: "MongoDB unauthorized",
    # 2026 Added: Sliver C2 and new remote control ports
    8889: "Sliver C2 mTLS",
    4446: "Sliver C2 HTTP",
    4447: "Sliver C2 HTTPS",
    1338: "Quasar RAT",
    5556: "AsyncRAT common",
    6668: "RemcosRAT",
    9090: "Warzone RAT",
    1133: "AgentTesla",
    22222: "NjRat/Bladabindi",
    8081: "LimeRAT",
    44444: "SystemBC",
    50001: "AnyDesk (abused)",
    # 2026 Q1-Q2 Added: Latest threat intelligence
    4448: "Sliver C2 DNS",
    4449: "Sliver C2 external",
    5558: "AsyncRAT alternate",
    1521: "Oracle DB exploitation",
    1433: "MSSQL exploitation",
    3389: "RDP brute force/target",
    5432: "PostgreSQL exploitation",
    11211: "Memcached DDoS amplification",
    2181: "Zookeeper exploitation",
    9042: "Cassandra exploitation",
    27018: "MongoDB router",
}

# Mining pool domain signatures
MINING_POOL_DOMAINS = {
    "pool.minexmr.com",
    "xmr.pool.minergate.com",
    "monerohash.com",
    "stratum.f2pool.com",
    "pool.supportxmr.com",
    "xmrpool.eu",
    "mine.moneropool.com",
    "xmr.nanopool.org",
    "xmr.hashvault.pro",
    "pool.hashvault.pro",
    "xmr.herominers.com",
    "gulf.moneroocean.stream",
    "pool.monero.hashvault.pro",
    # Common mining pools (2025-2026)
    "de01.mine.xmrpool.net",
    "xmr-eu2.nanopool.org",
    "xmr-us-east1.nanopool.org",
    "xmr-asia1.nanopool.org",
    "pool.oxbtc.com",
    "xmr.suprnova.cc",
    # 2026 Added: BTC/ETH mining pools
    "pool.btc.com",
    "stratum.antpool.com",
    "eth.nanopool.org",
    "ethf.nanopool.org",
    "etc.nanopool.org",
    "rvn-ravencoin.network",
    "pool.nicehash.com",
    # 2026 Q1-Q2 Added: More mining pool addresses
    "pool.bcmonster.com",
    "ltc.nanopool.org",
    "dash.nanopool.org",
    "zec.nanopool.org",
    "xvg.mykings.top",
    "monero.hashflare.io",
    "sha256.poolin.com",
    "scrypt.poolin.com",
    "pool.mining.be",
    "prohashing.com",
    "miningpoolhub.com",
    "zpool.ca",
    "ahashpool.com",
}

# Mining pool domain suffix patterns
MINING_POOL_PATTERNS = [
    ".nanopool.org",
    ".hashvault.pro",
    ".herominers.com",
    ".nicehash.com",
    ".dwarfpool.com",
    ".moneroocean.stream",
    ".f2pool.com",
    ".antpool.com",
    ".poolin.com",
    ".viabtc.com",
]

# Common mining pool ports
MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560, 45700}

# Dynamic DNS domain suffixes (often exploited by malware)
DDNS_DOMAINS = [
    ".ddns.net",
    ".no-ip.com",
    ".no-ip.org",
    ".duckdns.org",
    ".dynu.com",
    ".freedns.org",
    ".hopto.org",
    ".zapto.org",
    ".sytes.net",
    ".serveftp.com",
    ".servegame.com",
    ".redirectme.net",
    ".bounceme.net",
    ".myftp.biz",
    ".myftp.org",
    ".myvnc.com",
]

# Security software domain list (for detecting hosts hijacking)
SECURITY_VENDOR_DOMAINS = [
    "update.microsoft.com",
    "windowsupdate.com",
    "virustotal.com",
    "malwarebytes.com",
    "kaspersky.com",
    "avast.com",
    "avg.com",
    "clamav.net",
    "sophos.com",
    "trendmicro.com",
    "symantec.com",
    "mcafee.com",
    "eset.com",
    "bitdefender.com",
    "f-secure.com",
    "avira.com",
    "crowdstrike.com",
    "sentinelone.com",
]

# Cloud provider instance naming patterns (for DGA false positive prevention)
CLOUD_HOSTNAME_PATTERNS = [
    # Alibaba Cloud ECS instance names
    ".ecs-",
    "-ecs-",
    "i-",  # Aliyun instance ID prefix
    ".na",  # Alibaba Cloud zone suffix (e.g., .na131)
    # AWS EC2 instance names
    ".compute.internal",
    ".ec2.internal",
    "ip-",  # AWS private DNS (e.g., ip-10-0-0-1.ec2.internal)
    # Azure VM names
    ".cloudapp.azure.com",
    ".cloudapp.chinacloudapi.cn",
    ".c.cloudapp.net",
    ".regions.azurecontainer.io",
    # GCP instance names
    ".c.compute.internal",
    ".bo.googleusercontent.com",
    # Tencent Cloud
    "-vm.",
    ".tencent-cloud.",
]

# Public DNS servers (should not be considered malicious)
KNOWN_PUBLIC_DNS = {
    "8.8.8.8",          # Google
    "8.8.4.4",          # Google
    "1.1.1.1",          # Cloudflare
    "1.0.0.1",          # Cloudflare
    "9.9.9.9",          # Quad9
    "149.112.112.112",  # Quad9
    "208.67.222.222",   # OpenDNS
    "208.67.220.220",   # OpenDNS
    "114.114.114.114",  # 114DNS
    "223.5.5.5",        # Alibaba
    "223.6.6.6",        # Alibaba
    "119.29.29.29",     # DNSPod
    "180.76.76.76",     # Baidu
}

# Cloud provider internal DNS servers (should not be considered malicious)
CLOUD_DNS_SERVERS = {
    # AWS
    "169.254.169.253",  # AWS Route53 DNS
    # Azure
    "168.63.129.16",    # Azure DNS
    "169.254.169.254",  # Azure IMDS/DNS
    # Alibaba Cloud
    "100.100.2.136",    # Aliyun DNS
    "100.100.2.118",    # Aliyun DNS
    "100.100.2.116",    # Aliyun DNS
    # Tencent Cloud
    "183.60.83.19",     # Tencent DNS
    "183.60.82.98",     # Tencent DNS
    # GCP
    "169.254.169.254",  # GCP Metadata/DNS
}

# Cloud provider metadata service IPs (should not be considered malicious)
CLOUD_METADATA_IPS = {
    # AWS
    "169.254.169.254",  # AWS Instance Metadata Service (IMDS)
    # Azure
    "168.63.129.16",    # Azure Instance Metadata Service
    "169.254.169.254",  # Azure IMDS alternate
    # GCP
    "169.254.169.254",  # GCP Metadata Server
    "169.254.169.253",  # GCP Metadata Server alternate
    # Alibaba Cloud
    "100.100.100.200",  # Alibaba Cloud Metadata Service
    # Tencent Cloud
    "169.254.0.1",      # Tencent Cloud Metadata Service
    # Huawei Cloud
    "169.254.169.169",  # Huawei Cloud Metadata Service
}

# Container network IP ranges
CONTAINER_NETWORK_RANGES = [
    # Docker bridge networks
    ipaddress.ip_network("172.17.0.0/16"),
    ipaddress.ip_network("172.18.0.0/16"),
    ipaddress.ip_network("172.19.0.0/16"),
    ipaddress.ip_network("172.20.0.0/16"),
    ipaddress.ip_network("172.21.0.0/16"),
    ipaddress.ip_network("172.22.0.0/16"),
    ipaddress.ip_network("172.23.0.0/16"),
    ipaddress.ip_network("172.24.0.0/16"),
    ipaddress.ip_network("172.25.0.0/16"),
    ipaddress.ip_network("172.26.0.0/16"),
    ipaddress.ip_network("172.27.0.0/16"),
    ipaddress.ip_network("172.28.0.0/16"),
    ipaddress.ip_network("172.29.0.0/16"),
    ipaddress.ip_network("172.30.0.0/16"),
    ipaddress.ip_network("172.31.0.0/16"),
    # Kubernetes Pod CIDR (common defaults)
    ipaddress.ip_network("10.244.0.0/16"),
    ipaddress.ip_network("10.245.0.0/16"),
    ipaddress.ip_network("10.246.0.0/16"),
    ipaddress.ip_network("192.168.32.0/20"),  # Kind
    ipaddress.ip_network("192.168.48.0/20"),  # Minikube
    # CNI networks
    ipaddress.ip_network("10.42.0.0/16"),     # K3s
    ipaddress.ip_network("10.43.0.0/16"),     # RKE
]

# Service mesh ports
SERVICE_MESH_PORTS = {
    # Istio
    15001: "Istio Intercept",
    15006: "Istio Inbound",
    15010: "Istio XDS",
    15011: "Istio XDS TLS",
    15012: "Istio XDS Webhook",
    15014: "Istio Metrics",
    15020: "Istio Health",
    15021: "Istio Readiness",
    # Linkerd
    4140: "Linkerd Inbound",
    4141: "Linkerd Outbound",
    4142: "Linkerd Control",
    # Consul Connect
    8500: "Consul HTTP",
    8501: "Consul HTTPS",
    8502: "Consul gRPC",
    # Envoy sidecar
    9901: "Envoy Admin",
}

# Private network IP ranges (IANA reserved)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# TEST-NET IP ranges (RFC 5737 defined, for documentation and examples, should be considered suspicious in production environments)
TEST_NET_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
]


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is a private network address (excluding TEST-NET IPs)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check if TEST-NET IP (should not be considered private)
        for network in TEST_NET_NETWORKS:
            if ip in network:
                return False
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except (ValueError, TypeError):
        return False


def is_mining_pool_domain(domain: str) -> bool:
    """Check if domain is a mining pool domain"""
    domain_lower = domain.lower()
    if domain_lower in MINING_POOL_DOMAINS:
        return True
    for pattern in MINING_POOL_PATTERNS:
        if domain_lower.endswith(pattern):
            return True
    return False


def is_ddns_domain(domain: str) -> bool:
    """Check if domain is a DDNS domain"""
    domain_lower = domain.lower()
    for suffix in DDNS_DOMAINS:
        if domain_lower.endswith(suffix):
            return True
    return False


def is_c2_port(port: int) -> Tuple[bool, str]:
    """Check if port is a common C2 port"""
    if port in C2_PORTS:
        return True, C2_PORTS[port]
    return False, ""


# Known malicious IPs (sample data for demonstration)
# In production, this would be loaded from external threat intel feeds
MALICIOUS_IPS = {
    # All IPs below use RFC 5737 TEST-NET ranges (safe, non-routable)
    # In production, load real IoCs from external threat intel feeds
    "198.51.100.11",  # Simulated Tor exit node
    "198.51.100.12",  # Simulated Tor exit node
    "198.51.100.13",  # Simulated Tor exit node
    "198.51.100.14",  # Simulated Tor exit node
    "198.51.100.15",  # Simulated Tor exit node
    "198.51.100.20",  # Simulated C2 infrastructure
    "198.51.100.1",   # TEST-NET-2
    "203.0.113.1",    # TEST-NET-3
    "192.0.2.100",    # TEST-NET-1
    "192.0.2.200",    # TEST-NET-1
}

# Known malicious domains (sample data for demonstration)
MALICIOUS_DOMAINS = {
    # All domains below use RFC 2606 reserved .example.com/.example.net
    # In production, load real IoCs from external threat intel feeds
    "malware-c2.example.com",
    "evil-domain.example.com",
    "bad-actor.example.net",
    "c2-server.example.org",
    "phishing.example.com",
    "dga-random-1234567890.example.com",
    # Mining pool detection entries (also flagged by is_mining_pool_domain)
    "pool.minexmr.com",
    "xmr.pool.minergate.com",
}


def is_mining_port(port: int) -> bool:
    """Check if port is a mining pool port"""
    return port in MINING_PORTS


def is_cloud_dns(ip_str: str) -> bool:
    """Check if IP is a cloud provider internal DNS server"""
    return ip_str in CLOUD_DNS_SERVERS


def is_cloud_hostname(hostname: str) -> bool:
    """Check if hostname matches cloud provider instance naming patterns
    
    Args:
        hostname: hostname or domain to check
        
    Returns:
        True if hostname matches cloud provider patterns, False otherwise
    """
    if not hostname:
        return False
    
    hostname_lower = hostname.lower()
    for pattern in CLOUD_HOSTNAME_PATTERNS:
        if pattern in hostname_lower:
            return True
    
    # Special case: Alibaba Cloud ECS instance name pattern
    # e.g., ecs-sec-dev011166002139.na131
    if hostname_lower.startswith("ecs-"):
        return True
    
    return False


def is_cloud_metadata_ip(ip_str: str) -> bool:
    """Check if IP is a cloud provider metadata service
    
    Args:
        ip_str: IP address to check
        
    Returns:
        True if IP is a known cloud metadata service IP
    """
    return ip_str in CLOUD_METADATA_IPS


def is_container_network_ip(ip_str: str) -> bool:
    """Check if IP belongs to common container networks
    
    Args:
        ip_str: IP address to check
        
    Returns:
        True if IP belongs to Docker, Kubernetes, or other container networks
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in CONTAINER_NETWORK_RANGES:
            if ip in network:
                return True
        return False
    except (ValueError, TypeError):
        return False


def is_service_mesh_port(port: int) -> Tuple[bool, str]:
    """Check if port is a service mesh port
    
    Args:
        port: port number to check
        
    Returns:
        Tuple of (is_service_mesh, description)
    """
    if port in SERVICE_MESH_PORTS:
        return True, SERVICE_MESH_PORTS[port]
    return False, ""

def get_version_info() -> Dict[str, str]:
    """Get threat intelligence version information
    
    Returns:
        dictionary containing version number, update date, and source
    """
    return {
        "version": THREAT_INTEL_VERSION,
        "updated": THREAT_INTEL_UPDATED,
        "source": THREAT_INTEL_SOURCE,
    }


def check_update_available(current_version: str) -> bool:
    """Check if update is available
    
    Args:
        current_version: current running version number (format: YYYY.MM.DD)
        
    Returns:
        True if update is available, otherwise False
    """
    try:
        current = [int(x) for x in current_version.split('.')]
        latest = [int(x) for x in THREAT_INTEL_VERSION.split('.')]
        return latest > current
    except (ValueError, AttributeError):
        return False


def get_intel_stats() -> Dict[str, int]:
    """Get threat intelligence statistics
    
    Returns:
        dictionary containing counts of various intelligence types
    """
    return {
        "c2_ports": len(C2_PORTS),
        "mining_pools": len(MINING_POOL_DOMAINS),
        "mining_ports": len(MINING_PORTS),
        "ddns_suffixes": len(DDNS_DOMAINS),
        "public_dns": len(KNOWN_PUBLIC_DNS),
        "cloud_dns": len(CLOUD_DNS_SERVERS),
        "cloud_metadata_ips": len(CLOUD_METADATA_IPS),
        "container_networks": len(CONTAINER_NETWORK_RANGES),
        "service_mesh_ports": len(SERVICE_MESH_PORTS),
    }
