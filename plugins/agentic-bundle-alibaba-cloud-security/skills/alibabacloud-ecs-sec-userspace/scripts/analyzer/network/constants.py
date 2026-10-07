"""Constants for network anomaly detection analyzer.

Contains all whitelists, thresholds, regex patterns, and configuration values
used by the NetworkAnalyzer and its sub-modules.
"""
import re
import threading

# =============================================================================
# Port Whitelist - Common services and development tools
# =============================================================================
PORT_WHITELIST = frozenset({
    # Standard services
    22, 80, 443, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 8080, 8443,
    # System service ports (NTP, printing, DHCP, mDNS, etc.)
    1123,   # chronyd - NTP time synchronization control port
    631,    # cupsd - CUPS printing service
    68,     # dhclient - DHCP client
    67,     # dhcpd - DHCP server
    5353,   # avahi - mDNS/DNS-SD
    123,    # ntpd - NTP daemon
    514,    # rsyslogd - Syslog daemon
    6831,   # corosync - Cluster communication
    2049,   # nfsd - NFS server
    111,    # rpcbind - RPC port mapper
    # Development tool ports
    3000,   # Node.js dev server
    3001,   # Next.js alternate / React dev
    4200,   # Angular CLI dev server
    5173, 5174,  # Vite dev server
    5000, 5001,  # Flask / .NET dev server
    8000, 8001,  # Django / Python dev servers
    8888,   # Jupyter Notebook
    9000, 9003,  # PHP-FPM / Xdebug
    9229, 9230,  # Node.js debug port
    5678,   # Python debugpy
    2345,   # Go delve debugger
    # IDE / AI coding tool ports
    34257,  # Common Node.js ephemeral port
    56000, 56510,  # Qoder IDE
    49100, 49200,  # Cursor IDE range
    63342,  # JetBrains IDE built-in server
    # Container / orchestration
    2375, 2376,  # Docker daemon
    10250,  # Kubelet
    6443,   # Kubernetes API server
    2379, 2380,  # etcd
    # Cloud provider system ports
    8087,   # Alibaba Cloud opensandbox-ser
    15772,  # Alibaba Cloud staragentd
    15776,  # Alibaba Cloud argusagent
    19777,  # Alibaba Cloud argusagent
    1688,   # Alibaba Cloud assist-daemon
    # Service mesh ports
    15001, 15006, 15010, 15011, 15012, 15014, 15020, 15021,  # Istio
    4140, 4141, 4142,  # Linkerd
    8500, 8501, 8502,  # Consul Connect
    9901,   # Envoy Admin
})

# =============================================================================
# Process Whitelist - Standard services and development tools
# =============================================================================
PROCESS_WHITELIST = frozenset({
    # System services
    "sshd", "nginx", "apache2", "httpd", "mysqld", "postgres", "redis-server", "docker-proxy",
    "containerd", "dockerd", "kubelet", "kube-proxy", "etcd",
    "systemd-timesyncd", "systemd-timesyn",
    "chronyd", "ntpd",
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
})

# =============================================================================
# Cloud Provider Process Patterns (regex for flexible matching)
# =============================================================================
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

# =============================================================================
# Shell Process Pattern
# =============================================================================
SHELL_PATTERNS = re.compile(r'^(bash|sh|zsh|ash|dash|ksh|fish|csh|tcsh)$')

# =============================================================================
# DNS Tunneling Detection Thresholds
# =============================================================================
DNS_TUNNEL_DOMAIN_LENGTH_THRESHOLD = 50   # Unusually long domain names
DNS_HIGH_ENTROPY_THRESHOLD = 4.0           # High entropy = random-looking subdomains
DNS_QUERY_RATE_THRESHOLD = 100             # Queries per minute

# =============================================================================
# Connection State Anomaly Thresholds (global)
# =============================================================================
CLOSE_WAIT_THRESHOLD = 100   # Alert if more than 100 CLOSE_WAIT connections
TIME_WAIT_THRESHOLD = 1000   # Alert if more than 1000 TIME_WAIT connections
FIN_WAIT_THRESHOLD = 500     # Alert if more than 500 FIN_WAIT connections

# =============================================================================
# Per-IP Connection State Thresholds
# =============================================================================
PER_IP_CLOSE_WAIT_THRESHOLD = 20   # Alert if single IP has > 20 CLOSE_WAIT
PER_IP_TIME_WAIT_THRESHOLD = 100   # Alert if single IP has > 100 TIME_WAIT
PER_IP_FIN_WAIT_THRESHOLD = 50     # Alert if single IP has > 50 FIN_WAIT

# =============================================================================
# Baseline Adaptation Thresholds
# =============================================================================
BASELINE_RATE_THRESHOLD = 3.0      # Alert if current count > 3x historical baseline
MIN_BASELINE_SAMPLES = 5           # Minimum samples for reliable baseline
RATE_WINDOW_SECONDS = 300          # 5 minutes window for rate detection

# =============================================================================
# Service Mesh Ports (not in IoCLoader)
# =============================================================================
SERVICE_MESH_PORTS = {
    15001: "Istio Intercept", 15006: "Istio Inbound",
    15010: "Istio XDS", 15014: "Istio Metrics",
    4140: "Linkerd Inbound", 4141: "Linkerd Outbound",
    8500: "Consul HTTP", 9901: "Envoy Admin",
}

# =============================================================================
# Container Network Ranges
# =============================================================================
CONTAINER_NETWORK_RANGES = [
    "172.17.0.0/16",
    "10.244.0.0/16",
    "10.42.0.0/16",
    "10.43.0.0/16",
]

# =============================================================================
# Quick Mode Configuration
# =============================================================================
QUICK_MODE_CONNECTION_LIMIT = 50
QUICK_MODE_SCAN_BUDGET_SECONDS = 1.5

# =============================================================================
# Suspicious User Agents for Web Protocol Abuse Detection
# =============================================================================
SUSPICIOUS_USER_AGENTS = [
    re.compile(r'Mozilla/4\.0', re.IGNORECASE),
    re.compile(r'Wget/\d+\.\d+', re.IGNORECASE),
    re.compile(r'curl/\d+\.\d+', re.IGNORECASE),
    re.compile(r'python-requests/\d+\.\d+', re.IGNORECASE),
    re.compile(r'Go-http-client', re.IGNORECASE),
    re.compile(r'Java/\d+\.\d+', re.IGNORECASE),
    re.compile(r'^$'),
]

# =============================================================================
# Web Protocol Ports to Monitor
# =============================================================================
WEB_PROTOCOL_PORTS = frozenset({80, 443, 8080, 8443})

# =============================================================================
# Data Staging Ports
# =============================================================================
STAGING_PORTS = frozenset({443, 8443, 8080, 80, 21, 22, 990})

# =============================================================================
# Data Staging Tools
# =============================================================================
STAGING_TOOLS = ['tar', 'zip', 'gzip', '7z', 'rar', 'rsync', 'scp', 'curl', 'wget']

# =============================================================================
# DNS Tunneling Tools
# =============================================================================
DNS_TUNNEL_TOOLS = ['iodine', 'dnscat', 'dnscat2', 'tun2socks', 'dns2tcp']

# =============================================================================
# Lateral Movement Patterns
# =============================================================================
LATERAL_MOVEMENT_PATTERNS = [
    (re.compile(r'psexec|wmic|winrm', re.IGNORECASE), 'Windows lateral movement tool'),
    (re.compile(r'ssh.*-t.*bash|ssh.*-t.*sh', re.IGNORECASE), 'Interactive SSH execution'),
    (re.compile(r'rdp|vnc|teamviewer', re.IGNORECASE), 'Remote desktop tool'),
]

# =============================================================================
# C2 Communication Patterns
# =============================================================================
C2_PATTERNS = [
    (re.compile(r'beacon|callback.*interval', re.IGNORECASE), 'C2 beacon pattern'),
    (re.compile(r'cobaltstrike|sliver|havoc', re.IGNORECASE), 'Known C2 framework'),
    (re.compile(r'tor.*hidden|onion.*routing', re.IGNORECASE), 'Tor anonymization'),
    (re.compile(r'dns.*txt.*query.*long', re.IGNORECASE), 'DNS-based C2 channel'),
]

# =============================================================================
# Standard Ports for HTTPS Exfiltration Detection
# =============================================================================
STANDARD_PORTS = frozenset({80, 443, 22, 25, 53, 3306, 5432, 6379})

# =============================================================================
# Historical Baseline Storage
# =============================================================================
_HISTORICAL_BASELINES: dict = {}
_BASELINES_LOCK = threading.Lock()
