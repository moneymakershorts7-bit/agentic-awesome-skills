"""Environment Detection Utility

Detects the type of environment where sec-userspace is running:
- development: Development environment (local machines, workstations)
- cloud: Cloud server (ECS, EC2, etc.)
- ci_cd: CI/CD pipeline environment
- production: Production server (default if no other indicators match)
"""
import os
import threading
from pathlib import Path
from typing import List


class EnvironmentDetector:
    """Detects environment type based on system indicators"""

    _instance = None
    _instance_lock = threading.Lock()
    _detected_type = None

    def __new__(cls):
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def detect(self) -> str:
        """Detect environment type
        
        Returns:
            str: One of 'development', 'cloud', 'ci_cd', 'production'
        """
        if self._detected_type is not None:
            return self._detected_type
        
        indicators = {
            'ci_cd': self._check_ci_cd_indicators(),
            'development': self._check_development_indicators(),
            'cloud': self._check_cloud_indicators(),
        }
        
        # Check in priority order: CI/CD > Development > Cloud > Production
        for env_type, checks in indicators.items():
            if sum(checks) >= 1:
                self._detected_type = env_type
                return env_type
        
        # Default to production
        self._detected_type = 'production'
        return 'production'
    
    def _check_ci_cd_indicators(self) -> List[bool]:
        """Check CI/CD environment indicators"""
        return [
            bool(os.environ.get('CI')),
            bool(os.environ.get('GITHUB_ACTIONS')),
            bool(os.environ.get('GITLAB_CI')),
            bool(os.environ.get('JENKINS_URL')),
            bool(os.environ.get('CIRCLECI')),
            bool(os.environ.get('TRAVIS')),
            bool(os.environ.get('BUILD_NUMBER')),
        ]
    
    def _check_development_indicators(self) -> List[bool]:
        """Check development environment indicators"""
        return [
            (Path.cwd() / '.git').exists() and
            bool(os.environ.get('USER')) and
            os.environ.get('USER') != 'root',
            bool(os.environ.get('VIRTUAL_ENV')),
            bool(os.environ.get('CONDA_DEFAULT_ENV')),
        ]
    
    def _check_cloud_indicators(self) -> List[bool]:
        """Check cloud server indicators"""
        return [
            # AWS
            Path('/sys/class/dmi/id/product_uuid').exists() and 
            self._check_aws_uuid(),
            bool(os.environ.get('AWS_INSTANCE_ID')),
            bool(os.environ.get('EC2_METADATA_TOKEN')),
            # Alibaba Cloud
            Path('/usr/local/cloudmonitor').exists(),
            bool(os.environ.get('ALIYUN_INSTANCE_ID')),
            # General cloud indicators
            self._check_cloud_hypervisor(),
        ]
    
    def _check_aws_uuid(self) -> bool:
        """Check if product UUID matches AWS pattern"""
        try:
            uuid = Path('/sys/class/dmi/id/product_uuid').read_text(encoding='utf-8').strip().lower()
            return uuid.startswith('ec2') or uuid.startswith('i-')
        except OSError:
            return False
    
    def _check_cloud_hypervisor(self) -> bool:
        """Check for cloud hypervisor signatures"""
        try:
            dmi_product_name = Path('/sys/class/dmi/id/product_name').read_text(encoding='utf-8').strip().lower()
            cloud_signatures = ['amazon ec2', 'google compute', 'microsoft azure', 
                               'alibaba cloud', 'oraclecloud', 'digitalocean']
            return any(sig in dmi_product_name for sig in cloud_signatures)
        except OSError:
            return False
    
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.detect() == 'development'
    
    def is_cloud(self) -> bool:
        """Check if running in cloud environment"""
        return self.detect() == 'cloud'
    
    def is_ci_cd(self) -> bool:
        """Check if running in CI/CD environment"""
        return self.detect() == 'ci_cd'
    
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.detect() == 'production'
    
    def reset_cache(self):
        """Reset detection cache (for testing)"""
        self._detected_type = None


# Global detector instance
_detector = EnvironmentDetector()


def get_environment_type() -> str:
    """Get current environment type
    
    Returns:
        str: One of 'development', 'cloud', 'ci_cd', 'production'
    """
    return _detector.detect()


def is_development_env() -> bool:
    """Check if running in development environment"""
    return _detector.is_development()


def is_cloud_env() -> bool:
    """Check if running in cloud environment"""
    return _detector.is_cloud()


def is_ci_cd_env() -> bool:
    """Check if running in CI/CD environment"""
    return _detector.is_ci_cd()


def is_production_env() -> bool:
    """Check if running in production environment"""
    return _detector.is_production()


def reset_environment_cache():
    """Reset environment detection cache (for testing)"""
    _detector.reset_cache()
