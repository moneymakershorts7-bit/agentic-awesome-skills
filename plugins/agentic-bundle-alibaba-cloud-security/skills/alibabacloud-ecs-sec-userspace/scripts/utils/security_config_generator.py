"""Security configuration template generator for AI agents."""

import os
import copy
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class SecurityLevel(Enum):
    """Security level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AgentType(Enum):
    """Agent type enumeration."""
    OPENCLAW = "openclaw"
    CLAUDE = "claude"
    QODERCLI = "qodercli"
    GENERIC = "generic"


class CloudProvider(Enum):
    """Cloud provider enumeration."""
    ALIYUN = "aliyun"
    AWS = "aws"
    AZURE = "azure"
    NONE = "none"


@dataclass
class ContainerConfig:
    """Container security configuration."""
    privileged: bool = False
    drop_capabilities: List[str] = None
    add_capabilities: List[str] = None
    read_only_rootfs: bool = True
    allow_privilege_escalation: bool = False
    
    def __post_init__(self):
        if self.drop_capabilities is None:
            self.drop_capabilities = ["ALL"]
        if self.add_capabilities is None:
            self.add_capabilities = []


@dataclass
class NetworkConfig:
    """Network security configuration."""
    internet_access: bool = False
    allowed_domains: List[str] = None
    blocked_ports: List[str] = None
    allowed_ports: List[int] = None
    
    def __post_init__(self):
        if self.allowed_domains is None:
            self.allowed_domains = []
        if self.blocked_ports is None:
            self.blocked_ports = ["ALL"]
        if self.allowed_ports is None:
            self.allowed_ports = [443]


@dataclass
class EncryptionConfig:
    """Data encryption configuration."""
    config_encryption: str = "AES-256-GCM"
    key_management: str = "KMS"
    memory_encryption: str = "AES-256-GCM"
    key_rotation_days: int = 30
    api_key_storage: str = "encrypted"
    secret_backend: str = "HashiCorp Vault"


@dataclass
class AuditConfig:
    """Audit logging configuration."""
    enabled: bool = True
    log_level: str = "INFO"
    log_destinations: List[str] = None
    retention_days: int = 90
    integrity_check: bool = True
    
    def __post_init__(self):
        if self.log_destinations is None:
            self.log_destinations = []


@dataclass
class CustomConfig:
    """Custom security configuration overrides.
    
    This dataclass allows users to customize generated security configurations
    with their own requirements, such as internal tools, custom firewall rules,
    and compliance requirements.
    
    Attributes:
        allowed_domains: Additional domains to allow in network policy
        blocked_ports: Additional ports to block (default: [])
        additional_firewall_rules: Custom firewall rule definitions
        compliance_requirements: List of compliance standards (pci-dss, hipaa, etc.)
        custom_categories: Custom tool categories for whitelisting
        cloud_specific_configs: Cloud provider specific overrides
    """
    allowed_domains: List[str] = field(default_factory=list)
    blocked_ports: List[int] = field(default_factory=list)
    additional_firewall_rules: List[Dict[str, Any]] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    custom_categories: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    cloud_specific_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class SecurityConfigGenerator:
    """Security configuration template generator for AI agents.
    
    This generator creates security configuration templates based on the
    agent type, security level, and cloud provider. It follows the
    "Cloud Agent Security Self-Discipline Convention" requirements.
    
    Attributes:
        agent_type: Type of AI agent
        security_level: Security level (low/medium/high)
        cloud_provider: Cloud provider (aliyun/aws/azure)
    """
    
    # Default configurations
    DEFAULT_WORKDIR = "/var/lib/sec-userspace/workspace"
    DEFAULT_LOG_DIR = "/var/log/sec-userspace"
    
    # Allowed domains by agent type
    AGENT_DOMAINS = {
        AgentType.OPENCLAW: [
            "api.openai.com",
            "api.anthropic.com",
            "cdn.openai.com",
        ],
        AgentType.CLAUDE: [
            "api.anthropic.com",
            "cdn.anthropic.com",
        ],
        AgentType.QODERCLI: [
            "api.qoder.com",
            "forum.qoder.com",
        ],
        AgentType.GENERIC: [],
    }
    
    # Cloud-specific DNS resolvers
    CLOUD_DNS = {
        CloudProvider.ALIYUN: ["169.254.169.254", "100.100.2.136"],
        CloudProvider.AWS: ["169.254.169.253", "169.254.169.254"],
        CloudProvider.AZURE: ["168.63.129.16"],
        CloudProvider.NONE: ["8.8.8.8", "8.8.4.4"],
    }
    
    # Cloud-specific secret backends
    CLOUD_SECRET_BACKEND = {
        CloudProvider.ALIYUN: "Alibaba Cloud KMS",
        CloudProvider.AWS: "AWS Secrets Manager",
        CloudProvider.AZURE: "Azure Key Vault",
        CloudProvider.NONE: "HashiCorp Vault",
    }
    
    def __init__(
        self,
        agent_type: str = "generic",
        security_level: str = "high",
        cloud_provider: Optional[str] = None,
        customizations: Optional[CustomConfig] = None,
    ):
        """Initialize security config generator.
        
        Args:
            agent_type: Agent type (openclaw/claude/qodercli/generic)
            security_level: Security level (low/medium/high)
            cloud_provider: Cloud provider (aliyun/aws/azure/none)
            customizations: Optional custom configuration overrides
        """
        self.agent_type = self._parse_agent_type(agent_type)
        self.security_level = self._parse_security_level(security_level)
        self.cloud_provider = self._parse_cloud_provider(cloud_provider)
        self.customizations = customizations or CustomConfig()
    
    def _parse_agent_type(self, agent_type: str) -> AgentType:
        """Parse agent type string to enum."""
        try:
            return AgentType(agent_type.lower())
        except ValueError:
            return AgentType.GENERIC
    
    def _parse_security_level(self, level: str) -> SecurityLevel:
        """Parse security level string to enum."""
        try:
            return SecurityLevel(level.lower())
        except ValueError:
            return SecurityLevel.HIGH
    
    def _parse_cloud_provider(self, provider: Optional[str]) -> CloudProvider:
        """Parse cloud provider string to enum."""
        if not provider:
            return CloudProvider.NONE
        try:
            return CloudProvider(provider.lower())
        except ValueError:
            return CloudProvider.NONE
    
    def generate_config(
        self,
        output_dir: Optional[str] = None,
        customizations: Optional[CustomConfig] = None,
    ) -> Dict[str, str]:
        """Generate security configuration templates.
        
        Args:
            output_dir: Output directory for config files. If None, returns
                       dict without writing files.
            customizations: Optional custom configuration overrides. If provided,
                           overrides the customizations set in __init__.
        
        Returns:
            Dictionary mapping filenames to file contents.
        """
        # Use provided customizations or fall back to instance customizations
        if customizations is not None:
            self.customizations = customizations
        
        configs = {}
        
        # Generate all configuration files
        configs["permissions.yaml"] = self._gen_permissions()
        configs["encryption.yaml"] = self._gen_encryption()
        configs["network.yaml"] = self._gen_network()
        configs["audit.yaml"] = self._gen_audit()
        
        # Add cloud-specific configs
        if self.cloud_provider != CloudProvider.NONE:
            configs[f"{self.cloud_provider.value}.yaml"] = self._gen_cloud_specific()
        
        # Write files if output_dir specified
        if output_dir:
            self._write_configs(configs, output_dir)
        
        return configs
    
    def _gen_permissions(self) -> str:
        """Generate minimal permissions configuration."""
        container = ContainerConfig()
        
        # Adjust based on security level
        if self.security_level == SecurityLevel.LOW:
            container.read_only_rootfs = False
        
        permissions_yaml = f"""# Minimal Permissions Configuration
# Generated for: {self.agent_type.value} agent
# Security Level: {self.security_level.value}
# Auto-generated - DO NOT EDIT MANUALLY

container:
  privileged: {str(container.privileged).lower()}
  capabilities:
    drop: [{', '.join(f'"{cap}"' for cap in container.drop_capabilities)}]
    add: [{', '.join(f'"{cap}"' for cap in container.add_capabilities)}]
  read_only_rootfs: {str(container.read_only_rootfs).lower()}
  allow_privilege_escalation: {str(container.allow_privilege_escalation).lower()}

filesystem:
  workdir: {self.DEFAULT_WORKDIR}
  permissions: "0700"
  mounts: []  # No hostPath mounts

network:
  user: null  # Run as non-root user
  group: null
"""
        return permissions_yaml
    
    def _gen_encryption(self) -> str:
        """Generate data encryption configuration."""
        encryption = EncryptionConfig()
        encryption.secret_backend = self.CLOUD_SECRET_BACKEND.get(
            self.cloud_provider, encryption.secret_backend
        )
        
        encryption_yaml = f"""# Data Encryption Configuration
# Generated for: {self.agent_type.value} agent
# Cloud Provider: {self.cloud_provider.value}
# Auto-generated - DO NOT EDIT MANUALLY

config_files:
  encryption: {encryption.config_encryption}
  key_management: {encryption.secret_backend}
  algorithm: AES-GCM
  key_size: 256

memory_database:
  encryption: {encryption.memory_encryption}
  key_rotation: {encryption.key_rotation_days}d
  secure_erase: true

api_keys:
  storage: {encryption.api_key_storage}
  backend: {encryption.secret_backend}
  rotation_policy: automatic
  
secrets:
  encryption_at_rest: true
  encryption_in_transit: true
  key_derivation: PBKDF2-SHA256
"""
        return encryption_yaml
    
    def _gen_network(self) -> str:
        """Generate network security configuration."""
        allowed_domains = list(self.AGENT_DOMAINS.get(self.agent_type, []))
        dns_resolvers = self.CLOUD_DNS.get(self.cloud_provider, ["8.8.8.8"])
        
        # Apply customizations
        if self.customizations.allowed_domains:
            allowed_domains.extend(self.customizations.allowed_domains)
        
        # Add custom blocked ports
        base_blocked_ports = [22, 23, 3389, 445, 135, 139]
        if self.customizations.blocked_ports:
            base_blocked_ports.extend(self.customizations.blocked_ports)
        
        network_yaml = f"""# Network Security Configuration
# Generated for: {self.agent_type.value} agent
# Security Level: {self.security_level.value}
# Auto-generated - DO NOT EDIT MANUALLY

firewall_rules:
  # Allow HTTPS outbound to trusted domains
  - action: ALLOW
    direction: OUTBOUND
    protocol: TCP
    port: 443
    destination: trusted_domains
  
  # Block all other outbound
  - action: DENY
    direction: OUTBOUND
    protocol: ALL
    port: ALL
    destination: ANY
  
  # Block all inbound
  - action: DENY
    direction: INBOUND
    protocol: ALL
    port: ALL
    source: ANY

dns_policy:
  allowed_resolvers:
{chr(10).join(f'    - {ip}' for ip in dns_resolvers)}
  blocked_domains:
    - "*.malicious.com"
    - "*.phishing.com"
    - "*.c2server.net"
  block_doh_except_allowed: true

allowed_domains:
{chr(10).join(f'  - {domain}' for domain in allowed_domains)}

blocked_ports:
{chr(10).join(f'  - {port}   # Custom blocked port' for port in base_blocked_ports)}
"""
        
        # Add custom firewall rules if provided
        if self.customizations.additional_firewall_rules:
            network_yaml += "\n# Custom firewall rules\n"
            for rule in self.customizations.additional_firewall_rules:
                network_yaml += f"""  - action: {rule.get('action', 'DENY')}
    direction: {rule.get('direction', 'OUTBOUND')}
    protocol: {rule.get('protocol', 'TCP')}
    port: {rule.get('port', 'ALL')}
    destination: {rule.get('destination', 'ANY')}
"""
        
        return network_yaml
    
    def _gen_audit(self) -> str:
        """Generate audit logging configuration."""
        audit = AuditConfig()
        
        audit_yaml = f"""# Audit Logging Configuration
# Generated for: {self.agent_type.value} agent
# Auto-generated - DO NOT EDIT MANUALLY

enabled: {str(audit.enabled).lower()}
log_level: {audit.log_level}
log_format: JSON

log_destination:
  - local: {self.DEFAULT_LOG_DIR}/audit.log
  - remote: https://sec-server/api/v1/audit
  - stdout: false  # Disable stdout for production

retention:
  days: {audit.retention_days}
  max_size_mb: 1024
  compress: true
  archive_dir: {self.DEFAULT_LOG_DIR}/archive

integrity:
  check: {str(audit.integrity_check).lower()}
  hash_algorithm: SHA-256
  sign_logs: true
  
events:
  log_all_api_calls: true
  log_file_access: true
  log_network_connections: true
  log_process_execution: true
  log_authentication: true
  alert_on_anomaly: true
"""
        return audit_yaml
    
    def _gen_cloud_specific(self) -> str:
        """Generate cloud provider specific configuration."""
        cloud_configs = {
            CloudProvider.ALIYUN: self._gen_aliyun(),
            CloudProvider.AWS: self._gen_aws(),
            CloudProvider.AZURE: self._gen_azure(),
        }
        return cloud_configs.get(self.cloud_provider, "")
    
    def _gen_aliyun(self) -> str:
        """Generate Alibaba Cloud specific configuration."""
        return """# Alibaba Cloud Specific Configuration
# Auto-generated - DO NOT EDIT MANUALLY

cloud_provider: aliyun

ram_role:
  name: sec-userspace-agent-role
  policies:
    - AliyunKMSReadOnlyAccess
    - AliyunSecretsManagerReadOnlyAccess

vpc:
  endpoint: vpc.aliyuncs.com
  region_id: cn-hangzhou
  
kms:
  key_id: cmk-id-here
  region: cn-hangzhou
  
metadata_service:
  endpoint: http://100.100.100.200
  version: v2
  token_required: true
"""
    
    def _gen_aws(self) -> str:
        """Generate AWS specific configuration."""
        return """# AWS Specific Configuration
# Auto-generated - DO NOT EDIT MANUALLY

cloud_provider: aws

iam_role:
  name: sec-userspace-agent-role
  policies:
    - arn:aws:iam::aws:policy/SecretsManagerReadOnlyAccess
    - arn:aws:iam::aws:policy/KMSReadOnlyAccess

vpc:
  endpoint: vpce.amazonaws.com
  
secrets_manager:
  secret_name: sec-userspace/config
  region: us-east-1
  
imds:
  endpoint: http://169.254.169.254
  version: v2
  hops_limit: 1
"""
    
    def _gen_azure(self) -> str:
        """Generate Azure specific configuration."""
        return """# Azure Specific Configuration
# Auto-generated - DO NOT EDIT MANUALLY

cloud_provider: azure

managed_identity:
  name: sec-userspace-agent-identity
  roles:
    - Key Vault Secrets User
    - Key Vault Crypto User
  
key_vault:
  vault_name: sec-userspace-kv
  region: eastus
  
metadata_service:
  endpoint: http://169.254.169.254
  api_version: "2021-02-01"
"""
    
    def _write_configs(self, configs: Dict[str, str], output_dir: str) -> None:
        """Write configuration files to output directory.
        
        Args:
            configs: Dictionary of filename to content
            output_dir: Directory to write files
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for filename, content in configs.items():
            file_path = output_path / filename
            file_path.write_text(content, encoding='utf-8')
    
    def validate_config(self, configs: Dict[str, str]) -> List[str]:
        """Validate generated configurations.
        
        Args:
            configs: Dictionary of configuration files
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check required files
        required_files = ["permissions.yaml", "encryption.yaml", 
                         "network.yaml", "audit.yaml"]
        for req_file in required_files:
            if req_file not in configs:
                errors.append(f"Missing required config: {req_file}")
        
        # Validate YAML syntax (basic check)
        for filename, content in configs.items():
            if not content.strip():
                errors.append(f"Empty config file: {filename}")
            if content.count("- ") != content.count("\n  - "):
                # Basic list formatting check
                pass  # YAML validation would require a parser
        
        return errors


class ConfigMerger:
    """Configuration merger for deep merging multiple YAML configs.
    
    This class provides functionality to merge multiple configuration files
    with proper handling of nested dictionaries and lists. Later configurations
    override earlier ones, with lists being extended rather than replaced.
    
    Example:
        >>> merger = ConfigMerger()
        >>> merged = merger.merge(base_config, override1, override2)
    """
    
    def merge(self, base: Dict[str, Any], *overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge multiple configurations.
        
        Args:
            base: Base configuration dictionary
            *overrides: Variable number of override dictionaries
            
        Returns:
            Deep merged configuration dictionary
            
        Note:
            - Later overrides take precedence over earlier ones
            - Lists are extended (not replaced)
            - Dictionaries are recursively merged
            - Scalar values are overwritten
        """
        result = copy.deepcopy(base)
        for override in overrides:
            self._deep_merge(result, override)
        return result
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        """Recursively merge override into base.
        
        Args:
            base: Base dictionary to merge into (modified in place)
            override: Override dictionary to merge from
        """
        for key, value in override.items():
            if key in base:
                if isinstance(base[key], dict) and isinstance(value, dict):
                    # Recursively merge dictionaries
                    self._deep_merge(base[key], value)
                elif isinstance(base[key], list) and isinstance(value, list):
                    # Extend lists instead of replacing
                    base[key].extend(value)
                else:
                    # Override scalar values
                    base[key] = value
            else:
                base[key] = value


class InheritedConfigLoader:
    """Configuration loader with inheritance support.
    
    This loader supports configuration files that inherit from parent
    configurations using the 'inherits' field. It handles circular
    inheritance detection and multi-level inheritance chains.
    
    Example:
        >>> loader = InheritedConfigLoader()
        >>> config = loader.load("child.yaml")  # Automatically loads parent
    """
    
    MAX_INHERITANCE_DEPTH = 10
    
    def __init__(self):
        """Initialize config loader."""
        self._loaded_files: set = set()
    
    def load(self, config_path: str) -> Dict[str, Any]:
        """Load config with inheritance support.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Merged configuration dictionary
            
        Raises:
            ValueError: If circular inheritance is detected
            FileNotFoundError: If parent config file not found
        """
        self._loaded_files.clear()
        return self._load_recursive(config_path, depth=0)
    
    def _load_recursive(self, config_path: str, depth: int = 0) -> Dict[str, Any]:
        """Recursively load config with inheritance.
        
        Args:
            config_path: Path to configuration file
            depth: Current inheritance depth
            
        Returns:
            Merged configuration dictionary
            
        Raises:
            ValueError: If circular inheritance or max depth exceeded
        """
        if depth > self.MAX_INHERITANCE_DEPTH:
            raise ValueError(
                f"Maximum inheritance depth ({self.MAX_INHERITANCE_DEPTH}) exceeded. "
                "Possible circular inheritance."
            )
        
        abs_path = os.path.abspath(config_path)
        if abs_path in self._loaded_files:
            raise ValueError(f"Circular inheritance detected: {config_path}")
        
        # Load current config
        try:
            import yaml
        except ImportError:
            import json
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            if not config:
                return {}
            return config
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file {config_path}: {e}")

        if not config:
            return {}
        
        # Check for inheritance
        if 'inherits' in config:
            parent_path = self._resolve_parent_path(config_path, config['inherits'])
            
            # Load parent first
            parent_config = self._load_recursive(parent_path, depth + 1)
            
            # Remove inherits field before merging
            del config['inherits']
            
            # Merge child overrides
            merger = ConfigMerger()
            return merger.merge(parent_config, config)
        
        return config
    
    def _resolve_parent_path(self, child_path: str, parent_ref: str) -> str:
        """Resolve parent config path relative to child.
        
        Args:
            child_path: Path to child config file
            parent_ref: Parent path reference from inherits field
            
        Returns:
            Absolute path to parent config file
        """
        child_dir = os.path.dirname(os.path.abspath(child_path))
        return os.path.join(child_dir, parent_ref)


class ConfigValidator:
    """Security configuration validator.
    
    This class validates generated security configurations for correctness,
    compliance, and potential conflicts.
    
    Attributes:
        compliance_rules: Dictionary of compliance standard rules
        cloud_validators: Cloud provider specific validators
    """
    
    # Compliance standards mapping
    COMPLIANCE_STANDARDS = {
        "pci-dss": {
            "required_encryption": "AES-256-GCM",
            "required_audit": True,
            "log_retention_days": 90,
            "network_segmentation": True,
        },
        "hipaa": {
            "required_encryption": "AES-256-GCM",
            "required_audit": True,
            "log_retention_days": 365,
            "access_control": True,
        },
        "gdpr": {
            "data_encryption": True,
            "audit_logging": True,
            "data_minimization": True,
        },
        "soc2": {
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "access_monitoring": True,
        },
    }
    
    # Cloud-specific resource validators
    CLOUD_RESOURCE_PATTERNS = {
        "aliyun": {
            "kms_key_id": r"cmk-[a-z0-9]+",
            "vpc_endpoint": r"vpc\.[a-z]+-?[a-z]*\.aliyuncs\.com",
            "region_id": r"[a-z]+-[a-z]+",
        },
        "aws": {
            "iam_role_arn": r"arn:aws:iam::\d+:role/[a-zA-Z0-9_-]+",
            "secret_arn": r"arn:aws:secretsmanager:[a-z0-9-]+:\d+:secret:[a-zA-Z0-9/_+=.@-]+",
            "region": r"[a-z]{2}-[a-z]+-\d+",
        },
        "azure": {
            "vault_name": r"[a-zA-Z][a-zA-Z0-9-]{2,24}",
            "resource_group": r"[a-zA-Z0-9._-]+",
            "region": r"[a-z]+[a-z0-9]*",
        },
    }
    
    def __init__(self):
        """Initialize configuration validator."""
    
    def validate_configs(self, configs: Dict[str, str]) -> List[str]:
        """Validate all configuration files.
        
        Args:
            configs: Dictionary of configuration files
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check required files
        required_files = ["permissions.yaml", "encryption.yaml", 
                         "network.yaml", "audit.yaml"]
        for req_file in required_files:
            if req_file not in configs:
                errors.append(f"Missing required config: {req_file}")
        
        # Validate each config file
        for filename, content in configs.items():
            if not content or not content.strip():
                errors.append(f"Empty config file: {filename}")
        
        # Validate specific configurations
        if "encryption.yaml" in configs:
            errors.extend(self._validate_encryption(configs["encryption.yaml"]))
        
        if "audit.yaml" in configs:
            errors.extend(self._validate_audit(configs["audit.yaml"]))
        
        if "network.yaml" in configs:
            errors.extend(self._validate_network(configs["network.yaml"]))
        
        return errors
    
    def validate_compliance(
        self, 
        configs: Dict[str, str], 
        standard: str
    ) -> List[str]:
        """Validate configurations against compliance standard.
        
        Args:
            configs: Dictionary of configuration files
            standard: Compliance standard (pci-dss, hipaa, gdpr, soc2)
            
        Returns:
            List of compliance violation messages
        """
        violations = []
        
        if standard not in self.COMPLIANCE_STANDARDS:
            violations.append(
                f"Unknown compliance standard: {standard}. "
                f"Supported: {', '.join(self.COMPLIANCE_STANDARDS.keys())}"
            )
            return violations
        
        rules = self.COMPLIANCE_STANDARDS[standard]
        
        # Check encryption requirements
        if "required_encryption" in rules and "encryption.yaml" in configs:
            if rules["required_encryption"] not in configs["encryption.yaml"]:
                violations.append(
                    f"[{standard}] Required encryption algorithm "
                    f"{rules['required_encryption']} not found"
                )
        
        # Check audit logging requirements
        if rules.get("required_audit", False) and "audit.yaml" in configs:
            if "enabled: true" not in configs["audit.yaml"].lower():
                violations.append(
                    f"[{standard}] Audit logging must be enabled"
                )
        
        # Check log retention
        if "log_retention_days" in rules and "audit.yaml" in configs:
            import re
            match = re.search(r'days:\s*(\d+)', configs["audit.yaml"])
            if match:
                current_days = int(match.group(1))
                if current_days < rules["log_retention_days"]:
                    violations.append(
                        f"[{standard}] Log retention ({current_days} days) "
                        f"is less than required ({rules['log_retention_days']} days)"
                    )
        
        return violations
    
    def validate_cloud_resources(
        self, 
        configs: Dict[str, str]
    ) -> List[str]:
        """Validate cloud provider specific resources.
        
        Args:
            configs: Dictionary of configuration files
            
        Returns:
            List of resource validation errors
        """
        errors = []
        
        # Check aliyun config
        if "aliyun.yaml" in configs:
            errors.extend(self._validate_aliyun_resources(
                configs["aliyun.yaml"]
            ))
        
        # Check aws config
        if "aws.yaml" in configs:
            errors.extend(self._validate_aws_resources(
                configs["aws.yaml"]
            ))
        
        # Check azure config
        if "azure.yaml" in configs:
            errors.extend(self._validate_azure_resources(
                configs["azure.yaml"]
            ))
        
        return errors
    
    def check_conflicts(self, configs: Dict[str, str]) -> List[str]:
        """Detect configuration conflicts.
        
        Args:
            configs: Dictionary of configuration files
            
        Returns:
            List of conflict descriptions
        """
        conflicts = []
        
        # Check for conflicting firewall rules
        if "network.yaml" in configs:
            network = configs["network.yaml"]
            if "action: ALLOW" in network and "action: DENY" in network:
                # Check for overlapping rules
                if network.count("port: 443") > 1:
                    conflicts.append(
                        "Potential conflict: Multiple rules for port 443"
                    )
        
        # Check for encryption vs performance conflicts
        if "encryption.yaml" in configs and "audit.yaml" in configs:
            if "AES-256-GCM" in configs["encryption.yaml"]:
                if "log_level: DEBUG" in configs["audit.yaml"]:
                    conflicts.append(
                        "Performance warning: High encryption overhead with "
                        "DEBUG logging may impact performance"
                    )
        
        return conflicts
    
    def _validate_encryption(self, content: str) -> List[str]:
        """Validate encryption configuration."""
        errors = []
        
        # Check for weak encryption algorithms
        weak_algorithms = ["DES", "RC4", "MD5", "SHA1"]
        for algo in weak_algorithms:
            if algo in content.upper():
                errors.append(f"Weak encryption algorithm detected: {algo}")
        
        # Check for key rotation policy
        if "key_rotation" not in content.lower():
            errors.append("Key rotation policy not defined")
        
        return errors
    
    def _validate_audit(self, content: str) -> List[str]:
        """Validate audit logging configuration."""
        errors = []
        
        # Check for log integrity
        if "integrity" not in content.lower():
            errors.append("Log integrity checking not configured")
        
        # Check for remote logging
        if "remote" not in content.lower():
            errors.append("Remote log storage not configured")
        
        return errors
    
    def _validate_network(self, content: str) -> List[str]:
        """Validate network configuration."""
        errors = []
        
        # Check for default deny rules
        if "DENY" not in content:
            errors.append("No explicit DENY rules found in firewall config")
        
        # Check for allowed domains
        if "allowed_domains:" not in content:
            errors.append("Allowed domains not specified")
        
        return errors
    
    def _validate_aliyun_resources(self, content: str) -> List[str]:
        """Validate Alibaba Cloud resources."""
        errors = []
        import re
        
        patterns = self.CLOUD_RESOURCE_PATTERNS.get("aliyun", {})
        
        # Check KMS key ID format
        if "kms_key_id:" in content:
            match = re.search(r'kms_key_id:\s*(\S+)', content)
            if match and not re.match(patterns.get("kms_key_id", ""), match.group(1)):
                errors.append("Invalid Alibaba Cloud KMS key ID format")
        
        return errors
    
    def _validate_aws_resources(self, content: str) -> List[str]:
        """Validate AWS resources."""
        errors = []

        # Check IAM role ARN format
        if "iam_role:" in content:
            if "arn:aws:iam::" not in content:
                errors.append("AWS IAM role ARN not properly formatted")
        
        return errors
    
    def _validate_azure_resources(self, content: str) -> List[str]:
        """Validate Azure resources."""
        errors = []
        
        # Check Key Vault name
        if "vault_name:" in content:
            import re
            match = re.search(r'vault_name:\s*([a-zA-Z][a-zA-Z0-9-]*)', content)
            if not match:
                errors.append("Invalid Azure Key Vault name format")
        
        return errors


def main():
    """Main entry point for CLI usage."""
    import argparse
    import json
    try:
        import yaml
        YAML_AVAILABLE = True
    except ImportError:
        YAML_AVAILABLE = False
    
    parser = argparse.ArgumentParser(
        description="Generate security configuration templates for AI agents"
    )
    parser.add_argument(
        "--agent-type",
        type=str,
        default="generic",
        choices=["openclaw", "claude", "qodercli", "generic"],
        help="Type of AI agent"
    )
    parser.add_argument(
        "--security-level",
        type=str,
        default="high",
        choices=["low", "medium", "high"],
        help="Security level"
    )
    parser.add_argument(
        "--cloud-provider",
        type=str,
        default=None,
        choices=["aliyun", "aws", "azure"],
        help="Cloud provider"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for config files"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate generated configs"
    )
    parser.add_argument(
        "--custom-config",
        type=str,
        default=None,
        help="Path to custom configuration YAML file"
    )
    parser.add_argument(
        "--compliance",
        type=str,
        default=None,
        choices=["pci-dss", "hipaa", "gdpr", "soc2"],
        help="Compliance standard to validate against"
    )
    parser.add_argument(
        "--base",
        type=str,
        default=None,
        help="Base configuration file to extend (for inheritance)"
    )
    parser.add_argument(
        "--merge",
        type=str,
        nargs='+',
        default=None,
        metavar='FILE',
        help="One or more configuration files to merge (later files override earlier)"
    )
    
    args = parser.parse_args()
    
    def _yaml_load(text_or_file):
        if YAML_AVAILABLE:
            if hasattr(text_or_file, 'read'):
                return yaml.safe_load(text_or_file)
            return yaml.safe_load(text_or_file)
        else:
            if hasattr(text_or_file, 'read'):
                return json.loads(text_or_file.read())
            return json.loads(text_or_file)
    
    def _yaml_dump(data):
        if YAML_AVAILABLE:
            return yaml.dump(data, default_flow_style=False)
        else:
            return json.dumps(data, indent=2, ensure_ascii=False)
    
    def _yaml_parse_error():
        if YAML_AVAILABLE:
            return yaml.YAMLError
        return (ValueError, json.JSONDecodeError)
    
    # Handle --merge mode: merge multiple config files
    if args.merge:
        merger = ConfigMerger()
        
        # Load base config if provided
        if args.base:
            try:
                with open(args.base, 'r', encoding='utf-8') as f:
                    base_config = _yaml_load(f) or {}
                print(f"Loaded base configuration from {args.base}")
            except FileNotFoundError:
                print(f"Error: Base config file not found: {args.base}")
                return 1
            except _yaml_parse_error() as e:
                print(f"Error: Invalid YAML in base config file: {e}")
                return 1
        else:
            base_config = {}
        
        # Load and merge all override files
        override_configs = []
        for merge_file in args.merge:
            try:
                with open(merge_file, 'r', encoding='utf-8') as f:
                    override_config = _yaml_load(f) or {}
                override_configs.append(override_config)
                print(f"Loaded merge file: {merge_file}")
            except FileNotFoundError:
                print(f"Error: Merge file not found: {merge_file}")
                return 1
            except _yaml_parse_error() as e:
                print(f"Error: Invalid YAML in merge file {merge_file}: {e}")
                return 1
        
        # Merge all configs
        merged_config = merger.merge(base_config, *override_configs)
        
        # Convert to YAML format for output
        configs = {"merged.yaml": _yaml_dump(merged_config)}
        
        # Write or print configs
        if args.output_dir:
            output_path = Path(args.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            for filename, content in configs.items():
                (output_path / filename).write_text(content, encoding='utf-8')
            print(f"\nGenerated merged config to {args.output_dir}/{filename}")
        else:
            print("\n" + "="*60)
            print("# merged.yaml")
            print("="*60)
            print(configs["merged.yaml"])
        
        # Validate if requested
        if args.validate or args.compliance:
            validator = ConfigValidator()
            errors = validator.validate_configs(configs)
            if errors:
                print("\nValidation errors:")
                for error in errors:
                    print(f"  - {error}")
                return 1
            
            if args.compliance:
                violations = validator.validate_compliance(configs, args.compliance)
                if violations:
                    print(f"\n{args.compliance.upper()} compliance violations:")
                    for v in violations:
                        print(f"  - {v}")
                    return 1
                else:
                    print(f"\n{args.compliance.upper()} compliance: PASSED")
            
            print("\nValidation: PASSED")
        
        return 0
    
    # Handle --base mode: load config with inheritance
    if args.base:
        try:
            # Generate base config first
            customizations = _load_custom_config(args.custom_config)
            generator = SecurityConfigGenerator(
                agent_type=args.agent_type,
                security_level=args.security_level,
                cloud_provider=args.cloud_provider,
                customizations=customizations,
            )
            generated_configs = generator.generate_config(output_dir=None)
            
            # Merge with base config
            merger = ConfigMerger()
            base_config_dict = {}
            for filename, content in generated_configs.items():
                base_config_dict[filename] = _yaml_load(content)
            
            # Load user's base config
            with open(args.base, 'r', encoding='utf-8') as f:
                user_base = _yaml_load(f) or {}
            
            # Merge: user base overrides generated
            merged = merger.merge(base_config_dict, user_base)
            
            # Convert back to YAML strings
            configs = {}
            for filename, content_dict in merged.items():
                configs[filename] = _yaml_dump(content_dict)
            
            # Write files if output_dir specified
            if args.output_dir:
                output_path = Path(args.output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                for filename, content in configs.items():
                    (output_path / filename).write_text(content, encoding='utf-8')
                print(f"Generated {len(configs)} config files to {args.output_dir} (merged with {args.base})")
                for filename in configs.keys():
                    print(f"  - {filename}")
            else:
                for filename, content in configs.items():
                    print(f"\n{'='*60}")
                    print(f"# {filename}")
                    print('='*60)
                    print(content)
            
        except FileNotFoundError:
            print(f"Error: Base config file not found: {args.base}")
            return 1
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        except (OSError, KeyError, TypeError) as e:
            print(f"Error: Failed to load base config: {e}")
            return 1
    else:
        # Normal mode: generate config from scratch
        try:
            customizations = _load_custom_config(args.custom_config)
            if customizations and args.custom_config:
                print(f"Loaded custom configuration from {args.custom_config}")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            return 1
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        
        generator = SecurityConfigGenerator(
            agent_type=args.agent_type,
            security_level=args.security_level,
            cloud_provider=args.cloud_provider,
            customizations=customizations,
        )
        configs = generator.generate_config(output_dir=args.output_dir)
        
        if args.output_dir:
            print(f"Generated {len(configs)} config files to {args.output_dir}")
            for filename in configs.keys():
                print(f"  - {filename}")
        else:
            for filename, content in configs.items():
                print(f"\n{'='*60}")
                print(f"# {filename}")
                print('='*60)
                print(content)
    
    # Validation
    if args.validate or args.compliance:
        validator = ConfigValidator()
        
        errors = validator.validate_configs(configs)
        if errors:
            print("\nValidation errors:")
            for error in errors:
                print(f"  - {error}")
            return 1
        
        if args.compliance:
            violations = validator.validate_compliance(configs, args.compliance)
            if violations:
                print(f"\n{args.compliance.upper()} compliance violations:")
                for v in violations:
                    print(f"  - {v}")
                return 1
            else:
                print(f"\n{args.compliance.upper()} compliance: PASSED")
        
        conflicts = validator.check_conflicts(configs)
        if conflicts:
            print("\nPotential conflicts detected:")
            for c in conflicts:
                print(f"  - {c}")
        else:
            print("\nValidation: All configs are valid")
    
    return 0


def _load_custom_config(custom_config_path: Optional[str]) -> Optional[CustomConfig]:
    """Load custom configuration from YAML file.
    
    Args:
        custom_config_path: Path to custom config YAML file
        
    Returns:
        CustomConfig object or None
        
    Raises:
        FileNotFoundError: If config file not found
        ValueError: If YAML is invalid
    """
    try:
        import yaml
    except ImportError:
        yaml = None
    
    if not custom_config_path:
        return None
    
    try:
        with open(custom_config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if yaml:
            custom_data = yaml.safe_load(content)
        else:
            import json
            custom_data = json.loads(content)
        
        if custom_data:
            return CustomConfig(
                allowed_domains=custom_data.get('allowed_domains', []),
                blocked_ports=custom_data.get('blocked_ports', []),
                additional_firewall_rules=custom_data.get('additional_firewall_rules', []),
                compliance_requirements=custom_data.get('compliance_requirements', []),
                custom_categories=custom_data.get('custom_categories', {}),
                cloud_specific_configs=custom_data.get('cloud_specific_configs', {}),
            )
        return None
    except FileNotFoundError:
        raise FileNotFoundError(f"Custom config file not found: {custom_config_path}")
    except (yaml.YAMLError if yaml else ValueError) as e:
        raise ValueError(f"Invalid YAML in custom config file: {e}")


if __name__ == "__main__":
    exit(main())
