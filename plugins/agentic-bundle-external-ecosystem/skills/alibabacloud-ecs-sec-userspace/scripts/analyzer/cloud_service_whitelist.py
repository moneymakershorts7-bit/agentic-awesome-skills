"""Cloud Service API Whitelist Module

Provides domain and IP whitelisting for major cloud providers to prevent
false positive C2 detection when legitimate cloud SDK/API calls are made.

Supported providers:
- Alibaba Cloud (Aliyun)
- Amazon Web Services (AWS)
- Microsoft Azure
- Google Cloud Platform (GCP)
- Tencent Cloud
- Huawei Cloud

Usage:
    from .cloud_service_whitelist import is_cloud_service_endpoint
    
    # Check if domain is a cloud service endpoint
    if is_cloud_service_endpoint("ecs.aliyuncs.com"):
        # Skip C2 detection for this connection
        pass
"""
import re
import socket
import ipaddress


# Major cloud provider API domains
CLOUD_PROVIDER_DOMAINS = {
    # Alibaba Cloud (Aliyun)
    'alibaba_cloud': [
        '*.aliyuncs.com',
        '*.alicloudapi.com',
        '*.aliyuncs.cn',
        '*.alibabacloud.com',
        '*.aliyun.com',
        'ecs.aliyuncs.com',
        'sts.aliyuncs.com',
        'ram.aliyuncs.com',
        'vpc.aliyuncs.com',
        'slb.aliyuncs.com',
        'rds.aliyuncs.com',
        'oss.aliyuncs.com',
        'log.aliyuncs.com',
        'cms.aliyuncs.com',
    ],
    
    # Amazon Web Services (AWS)
    'aws': [
        '*.amazonaws.com',
        '*.amazon.com',
        '*.aws.amazon.com',
        '*.cloudfront.net',
        '*.execute-api.*.amazonaws.com',
        '*.lambda-url.*.on.aws',
        'sts.amazonaws.com',
        'ec2.amazonaws.com',
        's3.amazonaws.com',
        'iam.amazonaws.com',
        'lambda.amazonaws.com',
        'rds.amazonaws.com',
        'dynamodb.amazonaws.com',
        'cloudwatch.amazonaws.com',
        'sns.amazonaws.com',
        'sqs.amazonaws.com',
    ],
    
    # Microsoft Azure
    'azure': [
        '*.azure.com',
        '*.azure.net',
        '*.windows.net',
        '*.microsoftonline.com',
        '*.office365.com',
        '*.live.com',
        '*.msftauth.net',
        '*.msauth.net',
        'management.azure.com',
        'login.microsoftonline.com',
        'graph.microsoft.com',
        'vault.azure.net',
        'blob.core.windows.net',
        'queue.core.windows.net',
        'table.core.windows.net',
        'database.windows.net',
    ],
    
    # Google Cloud Platform (GCP)
    'gcp': [
        '*.googleapis.com',
        '*.google.com',
        '*.gstatic.com',
        '*.cloud.google.com',
        '*.appspot.com',
        '*.run.app',
        '*.cloudfunctions.net',
        'oauth2.googleapis.com',
        'compute.googleapis.com',
        'storage.googleapis.com',
        'iam.googleapis.com',
        'bigquery.googleapis.com',
        'pubsub.googleapis.com',
        'cloudresourcemanager.googleapis.com',
    ],
    
    # Tencent Cloud
    'tencent_cloud': [
        '*.tencentcloudapi.com',
        '*.myqcloud.com',
        '*.qcloud.com',
        '*.tencent-cloud.net',
        'cvm.tencentcloudapi.com',
        'cdb.tencentcloudapi.com',
        'clb.tencentcloudapi.com',
        'cam.tencentcloudapi.com',
        'monitor.tencentcloudapi.com',
    ],
    
    # Huawei Cloud
    'huawei_cloud': [
        '*.myhuaweicloud.com',
        '*.huaweicloud.com',
        '*.hwclouds.com',
        '*.hwcloudtest.cn',
        'iam.myhuaweicloud.com',
        'ecs.myhuaweicloud.com',
        'obs.myhuaweicloud.com',
        'vpc.myhuaweicloud.com',
    ],
}


# Compiled regex patterns for domain matching
CLOUD_DOMAIN_PATTERNS = []


def _compile_domain_patterns():
    """Compile domain patterns for efficient matching"""
    global CLOUD_DOMAIN_PATTERNS
    CLOUD_DOMAIN_PATTERNS = []
    
    for provider, domains in CLOUD_PROVIDER_DOMAINS.items():
        for domain_pattern in domains:
            # Convert wildcard pattern to regex
            if '*' in domain_pattern:
                # *.example.com -> ^.*\.example\.com$
                regex_pattern = '^' + domain_pattern.replace('.', r'\.').replace('*', '.*') + '$'
            else:
                # Exact match
                regex_pattern = '^' + re.escape(domain_pattern) + '$'
            
            CLOUD_DOMAIN_PATTERNS.append((re.compile(regex_pattern, re.IGNORECASE), provider))


_compile_domain_patterns()


# Cloud provider IP ranges (major public cloud CIDRs)
# These are commonly used for cloud APIs and metadata services
CLOUD_IP_RANGES = {
    # AWS IP ranges (subset of common API endpoints)
    'aws': [
        ipaddress.ip_network('52.94.0.0/16'),
        ipaddress.ip_network('54.239.0.0/16'),
        ipaddress.ip_network('99.86.0.0/16'),
        ipaddress.ip_network('13.32.0.0/15'),
        ipaddress.ip_network('13.35.0.0/16'),
    ],
    
    # Azure IP ranges
    'azure': [
        ipaddress.ip_network('40.64.0.0/10'),
        ipaddress.ip_network('13.64.0.0/11'),
        ipaddress.ip_network('20.33.0.0/16'),
        ipaddress.ip_network('20.34.0.0/15'),
        ipaddress.ip_network('20.36.0.0/14'),
    ],
    
    # GCP IP ranges
    'gcp': [
        ipaddress.ip_network('35.184.0.0/13'),
        ipaddress.ip_network('35.192.0.0/14'),
        ipaddress.ip_network('35.196.0.0/15'),
        ipaddress.ip_network('35.198.0.0/16'),
        ipaddress.ip_network('35.199.0.0/17'),
    ],
    
    # Alibaba Cloud IP ranges
    'alibaba_cloud': [
        ipaddress.ip_network('47.88.0.0/13'),
        ipaddress.ip_network('47.96.0.0/11'),
        ipaddress.ip_network('8.128.0.0/10'),
        ipaddress.ip_network('47.236.0.0/14'),
        ipaddress.ip_network('47.240.0.0/14'),
    ],
}


def is_cloud_service_domain(domain: str) -> tuple:
    """Check if domain belongs to a known cloud provider API endpoint
    
    Args:
        domain: Domain name to check (e.g., "ecs.aliyuncs.com")
        
    Returns:
        Tuple of (is_cloud: bool, provider: str)
        - is_cloud: True if domain matches cloud provider pattern
        - provider: Cloud provider name or empty string
        
    Examples:
        >>> is_cloud_service_domain("ecs.aliyuncs.com")
        (True, "alibaba_cloud")
        
        >>> is_cloud_service_domain("evil-c2.example.com")
        (False, "")
    """
    if not domain:
        return False, ""
    
    domain_lower = domain.lower().rstrip('.')
    
    # Check against compiled patterns
    for pattern, provider in CLOUD_DOMAIN_PATTERNS:
        if pattern.match(domain_lower):
            return True, provider
    
    return False, ""


def is_cloud_service_ip(ip_str: str) -> tuple:
    """Check if IP belongs to a known cloud provider range
    
    Args:
        ip_str: IP address string (e.g., "52.94.123.45")
        
    Returns:
        Tuple of (is_cloud: bool, provider: str)
        - is_cloud: True if IP is in cloud provider range
        - provider: Cloud provider name or empty string
        
    Examples:
        >>> is_cloud_service_ip("52.94.123.45")
        (True, "aws")
        
        >>> is_cloud_service_ip("192.168.1.1")
        (False, "")
    """
    if not ip_str:
        return False, ""
    
    try:
        ip = ipaddress.ip_address(ip_str)
        
        for provider, networks in CLOUD_IP_RANGES.items():
            for network in networks:
                if ip in network:
                    return True, provider
                    
        return False, ""
    except (ValueError, TypeError):
        return False, ""


def is_cloud_service_endpoint(domain: str = "", ip: str = "") -> tuple:
    """Check if endpoint (domain or IP) belongs to a cloud service
    
    This is the main entry point for C2 detection integration.
    
    Args:
        domain: Optional domain name to check
        ip: Optional IP address to check
        
    Returns:
        Tuple of (is_cloud: bool, provider: str, reason: str)
        - is_cloud: True if endpoint is a cloud service
        - provider: Cloud provider name or empty string
        - reason: Explanation of why it matched
        
    Examples:
        >>> is_cloud_service_endpoint(domain="sts.aliyuncs.com")
        (True, "alibaba_cloud", "Domain matches Alibaba Cloud API pattern")
        
        >>> is_cloud_service_endpoint(ip="52.94.123.45")
        (True, "aws", "IP in AWS range")
    """
    if domain:
        is_match, provider = is_cloud_service_domain(domain)
        if is_match:
            return True, provider, f"Domain matches {provider} API pattern"
    
    if ip:
        is_match, provider = is_cloud_service_ip(ip)
        if is_match:
            return True, provider, f"IP in {provider} range"
    
    return False, "", ""


def resolve_domain_to_ip(domain: str) -> list:
    """Resolve domain to IP addresses for additional checking
    
    Args:
        domain: Domain name to resolve
        
    Returns:
        List of resolved IP addresses, empty list on failure
    """
    if not domain:
        return []
    
    try:
        # Use getaddrinfo to handle both IPv4 and IPv6
        results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for result in results:
            ip = result[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except OSError:
        return []


def check_endpoint_with_resolution(domain: str) -> tuple:
    """Check domain and also resolve to IP for comprehensive checking
    
    Useful when you have a domain but want to verify the actual IP
    is in a cloud provider range.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Tuple of (is_cloud: bool, provider: str, reason: str, resolved_ips: list)
    """
    # First check domain pattern
    is_cloud, provider, reason = is_cloud_service_endpoint(domain=domain)
    if is_cloud:
        resolved_ips = resolve_domain_to_ip(domain)
        return is_cloud, provider, reason, resolved_ips
    
    # If domain doesn't match, try resolving and checking IPs
    resolved_ips = resolve_domain_to_ip(domain)
    for ip in resolved_ips:
        is_cloud, provider, reason = is_cloud_service_endpoint(ip=ip)
        if is_cloud:
            return is_cloud, provider, reason, resolved_ips
    
    return False, "", "Not a cloud service endpoint", resolved_ips


def get_supported_providers() -> list:
    """Get list of supported cloud providers
    
    Returns:
        List of provider names
    """
    return list(CLOUD_PROVIDER_DOMAINS.keys())


def get_provider_domains(provider: str) -> list:
    """Get domain patterns for a specific provider
    
    Args:
        provider: Provider name (e.g., "alibaba_cloud", "aws")
        
    Returns:
        List of domain patterns for the provider
    """
    return CLOUD_PROVIDER_DOMAINS.get(provider, [])
