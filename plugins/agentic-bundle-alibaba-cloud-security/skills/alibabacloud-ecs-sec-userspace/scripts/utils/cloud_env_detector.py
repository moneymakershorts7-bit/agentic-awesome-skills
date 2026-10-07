"""Cloud Environment Detector - Detect cloud providers and apply whitelists

Provides:
1. Cloud provider detection from system indicators
2. Cloud-specific whitelist patterns
3. Environment-aware false positive filtering
4. Support for major cloud providers (AWS, Azure, GCP, Alibaba, Tencent)

Usage:
    detector = CloudEnvDetector()
    
    # Detect cloud provider
    provider = detector.detect_provider()
    
    # Check if in cloud environment
    if detector.is_cloud_environment():
        # Get cloud-specific indicators
        indicators = detector.get_cloud_indicators(provider)
        
        # Check if an indicator should be whitelisted
        if detector.should_whitelist(ip_address, indicators['dns_servers']):
            logger.debug("Skipping cloud DNS server")

ATT&CK mapping:
- T1592 - Gather Victim Host Information (cloud metadata enumeration)
"""
import os
import re
import logging
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger("sec-userspace")


class CloudProvider(Enum):
    """Cloud provider enumeration"""
    ALIBABA = "alibaba"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    TENCENT = "tencent"
    UNKNOWN = "unknown"


@dataclass
class CloudIndicators:
    """Cloud provider specific indicators"""
    provider: CloudProvider
    product_names: Set[str] = field(default_factory=set)
    dns_servers: Set[str] = field(default_factory=set)
    metadata_ip: Optional[str] = None
    monitoring_processes: Set[str] = field(default_factory=set)
    known_ports: Set[int] = field(default_factory=set)
    known_domains: Set[str] = field(default_factory=set)
    default_disabled_features: Set[str] = field(default_factory=set)
    # Cloud monitoring agents with allowed CWD configurations
    # Format: {'agent_name': {'allowed_cwd': [], 'allowed_cwd_patterns': []}}
    cloud_agent_configs: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)


class CloudEnvDetector:
    """Cloud environment detection and whitelist service"""
    
    # Cloud provider indicators database
    CLOUD_INDICATORS: Dict[CloudProvider, CloudIndicators] = {
        CloudProvider.ALIBABA: CloudIndicators(
            provider=CloudProvider.ALIBABA,
            product_names={'alibaba cloud ecs', 'ecs', 'alibaba cloud'},
            dns_servers={'100.100.2.136', '100.100.2.138'},
            metadata_ip='100.100.100.200',
            monitoring_processes={
                'aliyun-service', 'aegis-client', 'cloudmonitor',
                'assist-daemon', 'aliyun-assistant', 'staragent',
                'argusagent', 'aliyun', 'aegis', 'aliyunassist',
                # Other Chinese cloud providers
                'telegraf', 'huawei-cloud', 'hws', 'tegent', 'ces-agent',
                'baidu-cloud', 'bcc-agent',
                'ucloud-agent', 'uk8s-agent',
                '21vianet-agent'
            },
            known_ports={8080, 9090, 8443},
            known_domains={'*.aliyuncs.com', '*.aliyun.com', '*.alicloud.com'},
            default_disabled_features={'bpf_stats_enabled'},
            cloud_agent_configs={
                'argusagent': {
                    'allowed_cwd_patterns': ['/home/staragent/', '/usr/local/staragent/']
                },
                'assist-daemon': {
                    'allowed_cwd_patterns': ['/usr/local/assist/']
                },
            }
        ),
        CloudProvider.AWS: CloudIndicators(
            provider=CloudProvider.AWS,
            product_names={'amazon ec2', 'ec2', 'amazon cloud'},
            dns_servers={'169.254.169.253'},
            metadata_ip='169.254.169.254',
            monitoring_processes={
                'amazon-cloudwatch-agent', 'ssm-agent', 'amazon-ssm-agent',
                'cwagent', 'aws-network-agent', 'awslogs',
                'amazon-cloudwatch'
            },
            known_ports={8140, 8443},
            known_domains={'*.amazonaws.com', '*.amazon.com'},
            default_disabled_features={'bpf_stats_enabled'},
            cloud_agent_configs={
                'amazon-ssm-agent': {
                    'allowed_cwd': ['/', '/var/lib/amazon/ssm']
                },
                'ssm-agent-worker': {
                    'allowed_cwd': ['/var/lib/amazon/ssm']
                },
            }
        ),
        CloudProvider.AZURE: CloudIndicators(
            provider=CloudProvider.AZURE,
            product_names={'microsoft azure vm', 'azure', 'hyper-v vm'},
            dns_servers={'168.63.129.16'},
            metadata_ip='169.254.169.254',
            monitoring_processes={
                'waagent', 'walinuxagent', 'azure-monitor-agent',
                'ama-metrics', 'omsagent', 'azurearcagent',
                'azure-monitor'
            },
            known_ports={8140},
            known_domains={'*.windows.net', '*.azure.com'},
            default_disabled_features={'bpf_stats_enabled'},
            cloud_agent_configs={
                'waagent': {
                    'allowed_cwd': ['/', '/var/lib/waagent']
                },
                'windows-azure-guest-agent': {
                    'allowed_cwd': ['/var/lib/waagent']
                },
            }
        ),
        CloudProvider.GCP: CloudIndicators(
            provider=CloudProvider.GCP,
            product_names={'google compute engine', 'gce'},
            dns_servers={'169.254.169.254'},
            metadata_ip='169.254.169.254',
            monitoring_processes={
                'google-osconfig-agent', 'stackdriver-agent',
                'fluent-bit-gcp', 'ops-agent', 'google-fluentd',
                'google_oslogin', 'google-osconfig', 'stackdriver',
                'fluent-bit'
            },
            known_ports={8140},
            known_domains={'*.googleapis.com', '*.google.com'},
            default_disabled_features={'bpf_stats_enabled'},
            cloud_agent_configs={
                'google-fluentd': {
                    'allowed_cwd': ['/opt/google/fluentd/'],
                    'allowed_cwd_patterns': ['/opt/google/']
                },
                'google_oslogin': {
                    'allowed_cwd': ['/']
                },
            }
        ),
        CloudProvider.TENCENT: CloudIndicators(
            provider=CloudProvider.TENCENT,
            product_names={'tencent cloud cvm', 'cvm', 'tencent cloud'},
            dns_servers={'183.60.83.19', '183.60.82.98'},
            metadata_ip='100.100.100.200',
            monitoring_processes={
                'barad_agent', 'qcloud-monitor', 'tat-agent',
                'monitor_agent', 'qcloud', 'tencent-cloud', 'tencentcloud'
            },
            known_ports={8080, 9090},
            known_domains={'*.tencentcloud.com', '*.qcloud.com'},
            default_disabled_features={'bpf_stats_enabled'},
        ),
    }
    
    def __init__(self):
        """Initialize cloud environment detector"""
        self._detected_provider: Optional[CloudProvider] = None
        self._is_cloud: Optional[bool] = None
        self._indicators: Optional[CloudIndicators] = None
        self._init_lock = __import__('threading').Lock()
    
    def detect_provider(self) -> CloudProvider:
        """Detect cloud provider from system indicators
        
        Checks multiple sources:
        1. DMI product name (/sys/class/dmi/id/product_name)
        2. Hypervisor vendor (/sys/class/dmi/id/bios_vendor)
        3. Cloud-init configuration
        4. Metadata service endpoints
        
        Returns:
            Detected CloudProvider enum value
        """
        # Try DMI product name first
        try:
            product_path = '/sys/class/dmi/id/product_name'
            if os.path.exists(product_path):
                with open(product_path, 'r', encoding='utf-8') as f:
                    product_name = f.read().strip().lower()
                
                for provider, indicators in self.CLOUD_INDICATORS.items():
                    if any(name in product_name for name in indicators.product_names):
                        logger.debug(f"Detected cloud provider from DMI: {provider.value}")
                        return provider
        except OSError as e:
            logger.debug(f"Cannot read DMI product name: {e}")
        
        # Try hypervisor vendor
        try:
            vendor_path = '/sys/class/dmi/id/bios_vendor'
            if os.path.exists(vendor_path):
                with open(vendor_path, 'r', encoding='utf-8') as f:
                    vendor = f.read().strip().lower()
                
                if 'amazon' in vendor or 'xen' in vendor:
                    logger.debug("Detected AWS from hypervisor vendor")
                    return CloudProvider.AWS
                elif 'microsoft' in vendor:
                    logger.debug("Detected Azure from hypervisor vendor")
                    return CloudProvider.AZURE
        except OSError as e:
            logger.debug(f"Cannot read hypervisor vendor: {e}")
        
        # Try cloud-init directory
        cloud_init_path = '/var/lib/cloud'
        if os.path.exists(cloud_init_path) and os.listdir(cloud_init_path):
            # Check for provider-specific files
            datasource_path = Path(cloud_init_path) / 'instance' / 'cloud-config.txt.run'
            if datasource_path.exists():
                try:
                    with open(datasource_path, 'r', encoding='utf-8') as f:
                        content = f.read().lower()
                    
                    if 'aliyun' in content or 'ecs' in content:
                        return CloudProvider.ALIBABA
                    elif 'ec2' in content or 'amazon' in content:
                        return CloudProvider.AWS
                    elif 'azure' in content:
                        return CloudProvider.AZURE
                except OSError:
                    pass
            
            # Generic cloud-init detected, assume cloud but unknown provider
            logger.debug("Cloud-init detected but provider unknown")
            return CloudProvider.UNKNOWN
        
        # Check for Alibaba Cloud Linux specific file
        if os.path.exists('/etc/alinux-release'):
            logger.debug("Detected Alibaba Cloud Linux")
            return CloudProvider.ALIBABA
        
        # Check product version for KVM + cloud indicators
        try:
            version_path = '/sys/class/dmi/id/product_version'
            if os.path.exists(version_path):
                with open(version_path, 'r', encoding='utf-8') as f:
                    version = f.read().strip().lower()
                
                # KVM virtualization with cloud context
                if 'pc-i440fx' in version or 'qemu' in version:
                    if os.path.exists('/etc/alinux-release'):
                        return CloudProvider.ALIBABA
        except OSError:
            pass
        
        logger.debug("No cloud provider detected (bare-metal or on-prem)")
        return CloudProvider.UNKNOWN
    
    def is_cloud_environment(self) -> bool:
        """Check if running in a cloud environment

        Uses lazy evaluation with caching for performance.

        Returns:
            True if in cloud environment, False otherwise
        """
        if self._is_cloud is None:
            with self._init_lock:
                if self._is_cloud is None:
                    self._detected_provider = self.detect_provider()
                    self._is_cloud = self._detected_provider != CloudProvider.UNKNOWN
                    self._indicators = self.CLOUD_INDICATORS.get(self._detected_provider)

                    if self._is_cloud:
                        logger.info(f"Running in cloud environment: {self._detected_provider.value}")
                    else:
                        logger.debug("Running in bare-metal or on-prem environment")

        return self._is_cloud

    def get_provider(self) -> CloudProvider:
        """Get detected cloud provider

        Returns:
            CloudProvider enum value
        """
        if self._detected_provider is None:
            self.is_cloud_environment()
        return self._detected_provider
    
    def get_cloud_indicators(self, provider: Optional[CloudProvider] = None) -> Optional[CloudIndicators]:
        """Get cloud-specific indicators
        
        Args:
            provider: Specific provider to get indicators for.
                     If None, uses auto-detected provider.
        
        Returns:
            CloudIndicators object or None if not in cloud
        """
        if provider is None:
            if not self.is_cloud_environment():
                return None
            return self._indicators
        
        return self.CLOUD_INDICATORS.get(provider)
    
    def should_whitelist(self, indicator: str, indicator_type: str = 'auto', 
                         context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if an indicator should be whitelisted in cloud environment
        
        Supports multiple indicator types:
        - 'dns': DNS server IP addresses
        - 'process': Process names (optionally with cwd context)
        - 'port': Network ports
        - 'domain': Domain names
        - 'feature': Disabled features (e.g., bpf_stats_enabled)
        - 'auto': Auto-detect type from indicator format
        
        Note: For 'process' type, checks are performed even outside cloud
        environments to identify known cloud agent processes.
        
        Args:
            indicator: The indicator value to check
            indicator_type: Type of indicator
            context: Optional context for whitelist check.
                    For process type, can include:
                    - 'cwd': Current working directory to validate
        
        Returns:
            True if should be whitelisted, False otherwise
        """
        # For process type, always check (even outside cloud)
        is_process_check = indicator_type in ('process', 'auto')
        
        if not is_process_check and not self.is_cloud_environment():
            return False
        
        indicators = self._indicators
        if not indicators and not is_process_check:
            return False
        
        # Auto-detect type if not specified
        if indicator_type == 'auto':
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
                indicator_type = 'dns'
            elif re.match(r'^\d+$', indicator):
                indicator_type = 'port'
            elif '.' in indicator or '*' in indicator:
                indicator_type = 'domain'
            else:
                indicator_type = 'process'
        
        # Check based on type
        if indicator_type == 'dns':
            if not indicators:
                return False
            return indicator in indicators.dns_servers
        elif indicator_type == 'process':
            # Check against ALL cloud providers' monitoring processes
            all_monitoring_procs = set()
            for prov_indicators in self.CLOUD_INDICATORS.values():
                all_monitoring_procs.update(prov_indicators.monitoring_processes)
            
            # Check if process name matches any monitoring process
            is_match = any(proc_name in indicator or indicator in proc_name 
                          for proc_name in all_monitoring_procs)
            
            if not is_match:
                return False
            
            # If context with CWD is provided, validate CWD
            if context and 'cwd' in context:
                proc_cwd = context['cwd']
                # Get allowed CWDs for all providers
                all_allowed_cwds = self._get_all_allowed_cwds()
                
                # Check exact matches
                if proc_cwd in all_allowed_cwds:
                    return True
                
                # Check prefix patterns
                cloud_agent_prefixes = [
                    '/usr/local/staragent/',
                    '/home/staragent/',
                    '/usr/local/assist/',
                    '/var/lib/amazon/ssm',
                    '/var/lib/waagent',
                    '/opt/google/',
                    '/usr/local/qcloud/',
                ]
                if any(proc_cwd.startswith(prefix) for prefix in cloud_agent_prefixes):
                    logger.debug(f"Cloud agent process whitelisted by CWD: {indicator} in {proc_cwd}")
                    return True
                
                # Process name matched but CWD is suspicious
                logger.debug(f"Process {indicator} name matches but CWD {proc_cwd} not whitelisted")
                return False
            else:
                # No CWD context, just match process name
                return True
        elif indicator_type == 'port':
            if not indicators:
                return False
            try:
                return int(indicator) in indicators.known_ports
            except (ValueError, TypeError):
                return False
        elif indicator_type == 'domain':
            if not indicators:
                return False
            for pattern in indicators.known_domains:
                if self._match_domain(indicator, pattern):
                    return True
            return False
        elif indicator_type == 'feature':
            if not indicators:
                return False
            return indicator in indicators.default_disabled_features
        
        return False
    def _get_all_allowed_cwds(self) -> set:
        """Get all allowed CWD paths from all cloud providers
        
        Returns:
            Set of all allowed CWD paths and patterns
        """
        all_cwds = set()
        for provider in self.CLOUD_INDICATORS.keys():
            all_cwds.update(self._get_provider_allowed_cwds(provider))
        return all_cwds
    
    def _get_provider_allowed_cwds(self, provider: CloudProvider) -> set:
        """Get allowed CWD paths for a specific cloud provider
        
        Args:
            provider: Cloud provider enum
        
        Returns:
            Set of allowed CWD paths
        """
        provider_cwds = {
            CloudProvider.ALIBABA: {
                '/',
                '/home/staragent/',
                '/usr/local/staragent/',
                '/usr/local/assist/',
            },
            CloudProvider.AWS: {
                '/',
                '/var/lib/amazon/ssm',
            },
            CloudProvider.AZURE: {
                '/',
                '/var/lib/waagent',
            },
            CloudProvider.GCP: {
                '/',
                '/opt/google/fluentd/',
                '/opt/google/',
            },
            CloudProvider.TENCENT: {
                '/',
                '/usr/local/qcloud/',
            },
        }
        
        return provider_cwds.get(provider, set())
    
    def _match_domain(self, domain: str, pattern: str) -> bool:
        """Match domain against wildcard pattern
        
        Args:
            domain: Domain to check
            pattern: Wildcard pattern (e.g., '*.example.com')
        
        Returns:
            True if domain matches pattern
        """
        if pattern.startswith('*.'):
            suffix = pattern[1:]  # Remove '*'
            return domain.endswith(suffix)
        return domain == pattern
    
    def should_skip_in_cloud(self, feature: str) -> bool:
        """Check if a detection feature should be skipped in cloud environment
        
        This is a convenience method for analyzer integration.
        
        Args:
            feature: Feature name to check (e.g., 'bpf_stats_enabled')
        
        Returns:
            True if feature should be skipped
        """
        return self.should_whitelist(feature, 'feature')
    
    def get_metadata_url(self) -> Optional[str]:
        """Get cloud provider metadata service URL
        
        Returns:
            Metadata service URL or None if not in cloud
        """
        if not self.is_cloud_environment():
            return None
        
        if not self._indicators or not self._indicators.metadata_ip:
            return None
        
        # Build provider-specific metadata URL
        if self._detected_provider == CloudProvider.AWS:
            # AWS IMDSv2
            return f"http://{self._indicators.metadata_ip}/latest/meta-data/"
        elif self._detected_provider == CloudProvider.AZURE:
            return f"http://{self._indicators.metadata_ip}/metadata/instance?api-version=2021-02-01"
        elif self._detected_provider == CloudProvider.GCP:
            return f"http://{self._indicators.metadata_ip}/computeMetadata/v1/"
        elif self._detected_provider == CloudProvider.ALIBABA:
            return f"http://{self._indicators.metadata_ip}/latest/meta-data/"
        elif self._detected_provider == CloudProvider.TENCENT:
            return f"http://{self._indicators.metadata_ip}/latest/meta-data/"
        
        return None
    
    def get_environment_context(self) -> Dict[str, Any]:
        """Get full environment context for reporting
        
        Returns:
            Dictionary with environment information
        """
        is_cloud = self.is_cloud_environment()
        provider = self.get_provider()
        
        context = {
            'environment_type': 'cloud' if is_cloud else 'bare-metal/on-prem',
            'cloud_provider': provider.value if provider != CloudProvider.UNKNOWN else None,
        }
        
        if is_cloud and self._indicators:
            context.update({
                'cloud_dns_servers': list(self._indicators.dns_servers),
                'cloud_monitoring_processes': list(self._indicators.monitoring_processes),
                'cloud_known_ports': list(self._indicators.known_ports),
                'default_disabled_features': list(self._indicators.default_disabled_features),
            })
        
        return context


# Singleton instance
_cloud_detector: Optional[CloudEnvDetector] = None
_cloud_detector_lock = __import__('threading').Lock()


def get_cloud_detector() -> CloudEnvDetector:
    """Get global cloud detector singleton

    Returns:
        CloudEnvDetector instance
    """
    global _cloud_detector
    if _cloud_detector is None:
        with _cloud_detector_lock:
            if _cloud_detector is None:
                _cloud_detector = CloudEnvDetector()
    return _cloud_detector


def is_cloud_environment() -> bool:
    """Convenience function to check cloud environment
    
    Returns:
        True if in cloud environment
    """
    return get_cloud_detector().is_cloud_environment()


def detect_cloud_provider() -> CloudProvider:
    """Convenience function to detect cloud provider
    
    Returns:
        Detected CloudProvider enum value
    """
    return get_cloud_detector().get_provider()


def should_whitelist_cloud_indicator(indicator: str, indicator_type: str = 'auto') -> bool:
    """Convenience function to check cloud whitelist
    
    Args:
        indicator: Indicator to check
        indicator_type: Type of indicator
    
    Returns:
        True if should be whitelisted
    """
    return get_cloud_detector().should_whitelist(indicator, indicator_type)
