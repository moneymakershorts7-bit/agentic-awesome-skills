"""
Client reporting protocol implementation.

Handles cloud metadata detection, system ID generation, and secure reporting.
Follows privacy-first principles: only uploads whitelisted data.
"""

import os
import json
import hashlib
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum


class EnvType(str, Enum):
    """Cloud environment types."""
    ALIYUN = "aliyun"
    AWS = "aws"
    TENCENT = "tencent"
    HUAWEI = "huawei"
    LOCAL = "local"


@dataclass
class CloudMetadata:
    """Cloud instance metadata."""
    instance_id: Optional[str] = None
    region: Optional[str] = None
    zone: Optional[str] = None
    instance_type: Optional[str] = None
    eip: Optional[str] = None


@dataclass
class SystemInfo:
    """System information (whitelisted only)."""
    os_type: str = ""
    kernel: str = ""
    arch: str = ""


@dataclass
class HealthStatus:
    """System health metrics."""
    cpu_usage: float = 0.0
    mem_usage: float = 0.0
    disk_usage: float = 0.0


@dataclass
class ExecutionStatus:
    """Execution statistics."""
    status: str = "success"
    duration: float = 0.0
    error_code: Optional[str] = None


@dataclass
class HeartbeatReport:
    """Heartbeat report structure."""
    uuid: str
    version: str
    timestamp: int
    env: Dict[str, Any]
    system: Dict[str, Any]
    status: Dict[str, Any]


@dataclass
class ExecutionReport:
    """Execution statistics report."""
    uuid: str
    timestamp: int
    execution: Dict[str, Any]


class CloudMetadataDetector:
    """Detect cloud environment and fetch metadata."""
    
    # Cloud metadata endpoints
    METADATA_URLS = {
        EnvType.ALIYUN: "http://100.100.100.200/latest/meta-data/",
        EnvType.AWS: "http://169.254.169.254/latest/meta-data/",
        EnvType.TENCENT: "http://metadata.tencentyun.com/latest/meta-data/",
        EnvType.HUAWEI: "http://169.254.169.254/latest/meta-data/",
    }
    
    # Detection signatures
    DETECTION_SIGNATURES = {
        EnvType.ALIYUN: ["Aliyun", "ecs"],
        EnvType.AWS: ["Amazon", "AWS", "EC2"],
        EnvType.TENCENT: ["Tencent", "CVM"],
        EnvType.HUAWEI: ["Huawei", "ECS"],
    }
    
    def __init__(self, timeout: float = 2.0):
        """Initialize detector with timeout."""
        self.timeout = timeout
    
    def detect_environment(self) -> EnvType:
        """Detect current cloud environment."""
        # Check DMI information
        try:
            if os.path.exists('/sys/class/dmi/id/product_name'):
                with open('/sys/class/dmi/id/product_name', encoding='utf-8') as f:
                    product = f.read().strip()
                    for env_type, signatures in self.DETECTION_SIGNATURES.items():
                        for sig in signatures:
                            if sig.lower() in product.lower():
                                return env_type
        except OSError:
            pass
        
        # Try metadata endpoints
        for env_type, url in self.METADATA_URLS.items():
            if self._check_metadata_endpoint(url):
                return env_type
        
        return EnvType.LOCAL
    
    def _check_metadata_endpoint(self, url: str) -> bool:
        """Check if metadata endpoint is accessible."""
        try:
            import urllib.request
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status == 200
        except (OSError, ValueError):
            return False
    
    def fetch_aliyun_metadata(self) -> CloudMetadata:
        """Fetch Alibaba Cloud metadata."""
        metadata = CloudMetadata()
        base_url = self.METADATA_URLS[EnvType.ALIYUN]
        
        fields = {
            'instance_id': 'instance-id',
            'region': 'region',
            'zone': 'zone',
            'instance_type': 'instance-type',
            'eip': 'eipv4',
        }
        
        for attr, field in fields.items():
            try:
                import urllib.request
                url = f"{base_url}{field}"
                req = urllib.request.Request(url, method='GET')
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    value = response.read().decode('utf-8').strip()
                    setattr(metadata, attr, value)
            except (OSError, ValueError):
                pass

        return metadata

    def fetch_aws_metadata(self) -> CloudMetadata:
        """Fetch AWS metadata (IMDSv2)."""
        metadata = CloudMetadata()
        base_url = self.METADATA_URLS[EnvType.AWS]
        
        # Get token first (IMDSv2)
        token = self._get_aws_token()
        headers = {}
        if token:
            headers['X-aws-ec2-metadata-token'] = token
        
        fields = {
            'instance_id': 'instance-id',
            'region': 'placement/region',
            'zone': 'placement/availability-zone',
            'instance_type': 'instance-type',
            'eip': 'public-ipv4',
        }
        
        for attr, field in fields.items():
            try:
                import urllib.request
                url = f"{base_url}{field}"
                req = urllib.request.Request(url, method='GET', headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    value = response.read().decode('utf-8').strip()
                    setattr(metadata, attr, value)
            except (OSError, ValueError):
                pass

        return metadata

    def _get_aws_token(self) -> Optional[str]:
        """Get AWS IMDSv2 token."""
        try:
            import urllib.request
            url = "http://169.254.169.254/latest/api/token"
            req = urllib.request.Request(
                url, 
                method='PUT',
                headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.read().decode('utf-8').strip()
        except (OSError, ValueError):
            return None
    
    def fetch_tencent_metadata(self) -> CloudMetadata:
        """Fetch Tencent Cloud metadata."""
        metadata = CloudMetadata()
        base_url = self.METADATA_URLS[EnvType.TENCENT]
        
        fields = {
            'instance_id': 'instance-id',
            'region': 'region',
            'zone': 'zone',
            'instance_type': 'instance-type',
        }
        
        for attr, field in fields.items():
            try:
                import urllib.request
                url = f"{base_url}{field}"
                req = urllib.request.Request(url, method='GET')
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    value = response.read().decode('utf-8').strip()
                    setattr(metadata, attr, value)
            except (OSError, ValueError):
                pass

        return metadata

    def fetch_huawei_metadata(self) -> CloudMetadata:
        """Fetch Huawei Cloud metadata."""
        metadata = CloudMetadata()
        base_url = self.METADATA_URLS[EnvType.HUAWEI]
        
        fields = {
            'instance_id': 'instance-id',
            'region': 'region',
            'zone': 'availability-zone',
            'instance_type': 'instance-type',
        }
        
        for attr, field in fields.items():
            try:
                import urllib.request
                url = f"{base_url}{field}"
                req = urllib.request.Request(url, method='GET')
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    value = response.read().decode('utf-8').strip()
                    setattr(metadata, attr, value)
            except (OSError, ValueError):
                pass

        return metadata

    def fetch_metadata(self, env_type: EnvType) -> CloudMetadata:
        """Fetch metadata based on environment type."""
        if env_type == EnvType.ALIYUN:
            return self.fetch_aliyun_metadata()
        elif env_type == EnvType.AWS:
            return self.fetch_aws_metadata()
        elif env_type == EnvType.TENCENT:
            return self.fetch_tencent_metadata()
        elif env_type == EnvType.HUAWEI:
            return self.fetch_huawei_metadata()
        return CloudMetadata()


class SystemIDGenerator:
    """Generate unique system ID for non-cloud environments."""
    
    def generate(self) -> str:
        """Generate unique system ID."""
        # Try machine-id first
        machine_id = self._read_machine_id()
        if machine_id:
            return machine_id[:36]
        
        # Fallback to boot_id + DMI hash
        boot_id = self._read_boot_id()
        dmi_uuid = self._read_dmi_uuid()
        
        combined = f"{boot_id}:{dmi_uuid}"
        return hashlib.sha256(combined.encode()).hexdigest()[:36]
    
    def _read_machine_id(self) -> Optional[str]:
        """Read /etc/machine-id."""
        try:
            if os.path.exists('/etc/machine-id'):
                with open('/etc/machine-id', encoding='utf-8') as f:
                    return f.read().strip()
        except OSError:
            pass
        return None
    
    def _read_boot_id(self) -> str:
        """Read /proc/sys/kernel/random/boot_id."""
        try:
            if os.path.exists('/proc/sys/kernel/random/boot_id'):
                with open('/proc/sys/kernel/random/boot_id', encoding='utf-8') as f:
                    return f.read().strip()
        except OSError:
            pass
        return ""
    
    def _read_dmi_uuid(self) -> str:
        """Read DMI UUID from sysfs."""
        paths = [
            '/sys/class/dmi/id/product_uuid',
            '/sys/class/dmi/id/board_serial',
        ]
        
        for path in paths:
            try:
                if os.path.exists(path):
                    with open(path, encoding='utf-8') as f:
                        return f.read().strip()
            except OSError:
                pass
        
        return ""


class SystemInfoCollector:
    """Collect whitelisted system information."""
    
    def collect(self) -> SystemInfo:
        """Collect system information."""
        info = SystemInfo()
        
        # OS type
        info.os_type = self._get_os_type()
        
        # Kernel version
        info.kernel = self._get_kernel_version()
        
        # Architecture
        info.arch = os.uname().machine or "unknown"
        
        return info
    
    def _get_os_type(self) -> str:
        """Get OS type from /etc/os-release."""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')
        except OSError:
            pass
        
        # Fallback
        uname = os.uname()
        return f"{uname.sysname} {uname.release}"
    
    def _get_kernel_version(self) -> str:
        """Get kernel version."""
        return os.uname().release


class HealthMonitor:
    """Monitor system health metrics."""
    
    def get_health_status(self) -> HealthStatus:
        """Get current health status."""
        status = HealthStatus()
        
        status.cpu_usage = self._get_cpu_usage()
        status.mem_usage = self._get_mem_usage()
        status.disk_usage = self._get_disk_usage()
        
        return status
    
    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage."""
        try:
            with open('/proc/stat', encoding='utf-8') as f:
                line = f.readline()
                parts = line.split()
                if parts[0] == 'cpu':
                    values = [int(x) for x in parts[1:8]]
                    idle = values[3]
                    total = sum(values)
                    
                    # Simple estimation (needs historical data for accuracy)
                    usage = 100.0 * (total - idle) / total if total > 0 else 0.0
                    return round(usage, 1)
        except (OSError, ValueError, IndexError):
            pass
        return 0.0
    
    def _get_mem_usage(self) -> float:
        """Get memory usage percentage."""
        try:
            mem_info = {}
            with open('/proc/meminfo', encoding='utf-8') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = int(parts[1].strip().split()[0])
                        mem_info[key] = value
            
            total = mem_info.get('MemTotal', 0)
            available = mem_info.get('MemAvailable', 0)
            
            if total > 0:
                usage = 100.0 * (total - available) / total
                return round(usage, 1)
        except (OSError, ValueError, KeyError):
            pass
        return 0.0
    
    def _get_disk_usage(self) -> float:
        """Get root disk usage percentage."""
        try:
            stat = os.statvfs('/')
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bfree * stat.f_frsize
            
            if total > 0:
                usage = 100.0 * (total - free) / total
                return round(usage, 1)
        except OSError:
            pass
        return 0.0


class ReportClient:
    """Secure reporting client."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize report client with configuration."""
        self.config = config
        self.enabled = config.get('enabled', True)
        self.server = config.get('server', '')
        self.dry_run = config.get('dry_run', False)
        self.exclude_fields = set(config.get('exclude', []))
    
    def create_heartbeat_report(
        self,
        uuid: str,
        version: str,
        env_type: EnvType,
        cloud_metadata: CloudMetadata,
        system_info: SystemInfo,
        health_status: HealthStatus,
    ) -> HeartbeatReport:
        """Create heartbeat report."""
        env_data = {
            'type': env_type.value,
        }
        
        # Add cloud metadata if available
        if env_type != EnvType.LOCAL:
            if cloud_metadata.instance_id:
                env_data['instance_id'] = cloud_metadata.instance_id
            if cloud_metadata.region:
                env_data['region'] = cloud_metadata.region
            if cloud_metadata.zone:
                env_data['zone'] = cloud_metadata.zone
            if cloud_metadata.instance_type:
                env_data['instance_type'] = cloud_metadata.instance_type
            if cloud_metadata.eip:
                env_data['eip'] = cloud_metadata.eip
        else:
            # Non-cloud environment
            generator = SystemIDGenerator()
            env_data['system_id'] = generator.generate()
        
        # Apply exclusions
        status_data = asdict(health_status)
        for field in self.exclude_fields:
            if field in status_data:
                del status_data[field]
        
        return HeartbeatReport(
            uuid=uuid,
            version=version,
            timestamp=int(time.time()),
            env=env_data,
            system=asdict(system_info),
            status=status_data,
        )
    
    def create_execution_report(
        self,
        uuid: str,
        execution_status: ExecutionStatus,
        analyzers_run: int = 0,
        collectors_run: int = 0,
    ) -> ExecutionReport:
        """Create execution report."""
        exec_data = {
            'status': execution_status.status,
            'duration': execution_status.duration,
        }
        
        if execution_status.error_code:
            exec_data['error_code'] = execution_status.error_code
        
        exec_data['analyzers_run'] = analyzers_run
        exec_data['collectors_run'] = collectors_run
        
        return ExecutionReport(
            uuid=uuid,
            timestamp=int(time.time()),
            execution=exec_data,
        )
    
    def send_report(self, report: Any) -> bool:
        """Send report to server."""
        if not self.enabled:
            return False
        
        if self.dry_run:
            print("[DRY-RUN] Report content:")
            print(json.dumps(asdict(report), indent=2))
            return True
        
        if not self.server:
            return False
        
        try:
            import urllib.request
            
            # Determine endpoint
            if isinstance(report, HeartbeatReport):
                endpoint = "/api/v1/heartbeat"
            else:
                endpoint = "/api/v1/stats/report"
            
            url = f"{self.server}{endpoint}"
            data = json.dumps(asdict(report)).encode('utf-8')
            
            req = urllib.request.Request(
                url,
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 200
        except (OSError, ValueError):
            return False
    
    def validate_report(self, report: Any) -> List[str]:
        """Validate report against privacy policy."""
        errors = []
        
        # Blacklist check
        blacklist_fields = [
            'hostname', 'username', 'user_list', 'process_list',
            'network_connections', 'listening_ports', 'file_contents',
            'log_contents', 'config_contents', 'credentials', 'passwords',
            'keys', 'tokens', 'certificates', 'paths', 'ip_addresses',
        ]
        
        report_dict = asdict(report)
        report_str = json.dumps(report_dict).lower()
        
        for field in blacklist_fields:
            if field in report_str:
                errors.append(f"Blacklisted field detected: {field}")
        
        return errors


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML/JSON file."""
    import json
    
    if not os.path.exists(config_path):
        return {'enabled': True}
    
    try:
        with open(config_path, encoding='utf-8') as f:
            content = f.read()
        
        try:
            import yaml
            config = yaml.safe_load(content)
        except ImportError:
            config = json.loads(content)
        except yaml.YAMLError:
            return {'enabled': True}

        return config.get('report', {'enabled': True})
    except (OSError, ValueError, KeyError):
        return {'enabled': True}
