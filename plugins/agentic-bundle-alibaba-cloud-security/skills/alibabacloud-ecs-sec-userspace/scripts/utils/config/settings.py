"""Configuration settings for sec-userspace"""
import threading
import yaml
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass, field


# Default configuration paths
DEFAULT_CONFIG_DIR = "/etc/sec-userspace"
DEFAULT_CONFIG_FILE = "config.yaml"
USER_CONFIG_DIR = "~/.sec-userspace"


@dataclass
class ImprovementProgramConfig:
    """Configuration for improvement program"""
    enabled: bool = False
    consent_given_at: Optional[str] = None
    data_sharing: Dict[str, bool] = field(default_factory=lambda: {
        "anonymized_findings": True,
        "system_metadata": True,
        "raw_evidence": False,
        "ai_prompt_data": False,
    })
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "enabled": self.enabled,
            "consent_given_at": self.consent_given_at,
            "data_sharing": self.data_sharing,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ImprovementProgramConfig":
        """Create from dictionary"""
        return cls(
            enabled=data.get("enabled", False),
            consent_given_at=data.get("consent_given_at"),
            data_sharing=data.get("data_sharing", {
                "anonymized_findings": True,
                "system_metadata": True,
                "raw_evidence": False,
                "ai_prompt_data": False,
            }),
        )


@dataclass 
class ClientConfig:
    """Client configuration"""
    deployment_type: str = "local"  # local, intranet, external-preview, external-release
    client_uuid: Optional[str] = None
    server_endpoint: Optional[str] = None
    api_key: Optional[str] = None
    provider: str = "bailian"
    model: Optional[str] = None
    base_url: Optional[str] = None
    improvement_program: ImprovementProgramConfig = field(default_factory=ImprovementProgramConfig)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "deployment_type": self.deployment_type,
            "client_uuid": self.client_uuid,
            "server_endpoint": self.server_endpoint,
            "api_key": self.api_key,
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "improvement_program": self.improvement_program.to_dict(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ClientConfig":
        """Create from dictionary"""
        return cls(
            deployment_type=data.get("deployment_type", "local"),
            client_uuid=data.get("client_uuid"),
            server_endpoint=data.get("server_endpoint"),
            api_key=data.get("api_key"),
            provider=data.get("provider", "bailian"),
            model=data.get("model"),
            base_url=data.get("base_url"),
            improvement_program=ImprovementProgramConfig.from_dict(
                data.get("improvement_program", {})
            ),
        )


class ConfigManager:
    """Configuration manager for sec-userspace"""
    
    def __init__(self, config_dir: str = None, config_file: str = None):
        self.config_dir = config_dir or DEFAULT_CONFIG_DIR
        self.config_file = config_file or DEFAULT_CONFIG_FILE
        self._config: Optional[ClientConfig] = None
    
    def _find_config_file(self) -> Optional[str]:
        """Find configuration file"""
        # Try system config directory
        system_config = Path(self.config_dir) / self.config_file
        if system_config.exists():
            return str(system_config)
        
        # Try user config directory
        user_config = Path(USER_CONFIG_DIR).expanduser() / self.config_file
        if user_config.exists():
            return str(user_config)
        
        # Try current directory
        local_config = Path(self.config_file)
        if local_config.exists():
            return str(local_config)
        
        return None
    
    def load(self) -> ClientConfig:
        """Load configuration from file"""
        config_path = self._find_config_file()
        
        if not config_path:
            # Return default configuration
            return ClientConfig()
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if data:
                self._config = ClientConfig.from_dict(data)
            else:
                self._config = ClientConfig()
                
        except (yaml.YAMLError, OSError) as e:
            # On error, return default configuration
            self._config = ClientConfig()
        
        return self._config
    
    def save(self, config: ClientConfig, path: str = None) -> str:
        """Save configuration to file"""
        if path is None:
            path = self._find_config_file()
            if path is None:
                # Create in user config directory
                config_dir = Path(USER_CONFIG_DIR).expanduser()
                config_dir.mkdir(parents=True, exist_ok=True)
                path = str(config_dir / self.config_file)
        
        try:
            # Ensure parent directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(config.to_dict(), f, default_flow_style=False, allow_unicode=True)
            
            return path
            
        except OSError as e:
            raise RuntimeError(f"Failed to save configuration: {e}")
    
    def get_config(self) -> ClientConfig:
        """Get current configuration"""
        if self._config is None:
            self.load()
        return self._config


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None
_config_manager_lock = threading.Lock()


def get_config_manager() -> ConfigManager:
    """Get global configuration manager"""
    global _config_manager
    if _config_manager is None:
        with _config_manager_lock:
            if _config_manager is None:
                _config_manager = ConfigManager()
    return _config_manager


def load_config() -> ClientConfig:
    """Load and return client configuration"""
    return get_config_manager().load()


def get_config() -> ClientConfig:
    """Get current client configuration"""
    return get_config_manager().get_config()
