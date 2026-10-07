"""ConfigVerifier - Verify configuration-related alerts

Verifies:
- System configuration baselines
- Permission configurations
- Known safe configuration patterns
- Environment-specific configurations
- SSH security baseline
- Bastion host detection
"""
import os
import logging
from typing import Dict, Optional, Set

from ..evidence import Evidence

logger = logging.getLogger("sec-userspace")


class ConfigVerifier:
    """Verify configuration-related security alerts"""
    
    def __init__(self, collected_data: Optional[Dict] = None):
        """Initialize config verifier
        
        Args:
            collected_data: Collected data from collectors
        """
        self.collected_data = collected_data or {}
        self.safe_configs = self._get_safe_config_patterns()
        self.environment = self._detect_environment()
        self.ssh_baseline = self._get_ssh_baseline()
    
    def _get_safe_config_patterns(self) -> Dict[str, list]:
        """Get known safe configuration patterns
        
        Returns:
            Dict mapping config type to safe patterns
        """
        return {
            'ssh_ports': [22],  # Standard SSH port
            'web_ports': [80, 443, 8080, 8443],
            'db_ports': [3306, 5432, 6379, 27017],
            'safe_permissions': [0o644, 0o600, 0o755, 0o700],
        }
    
    def _get_ssh_baseline(self) -> Dict[str, Set[str]]:
        """Get SSH security baseline configurations
        
        Returns:
            Dict mapping environment type to acceptable SSH settings
        """
        return {
            'production': {
                'PERMIT_ROOT_LOGIN': {'no', 'prohibit-password', 'without-password'},
                'PASSWORD_AUTHENTICATION': {'no'},
                'PERMIT_EMPTY_PASSWORDS': {'no'},
                'X11_FORWARDING': {'no'},
                'ALLOW_TCP_FORWARDING': {'no'},
                'MAX_AUTH_TRIES': {'3', '4', '5'},
            },
            'development': {
                'PERMIT_ROOT_LOGIN': {'yes', 'no', 'prohibit-password'},
                'PASSWORD_AUTHENTICATION': {'yes', 'no'},
                'PERMIT_EMPTY_PASSWORDS': {'no'},
                'X11_FORWARDING': {'yes', 'no'},
                'ALLOW_TCP_FORWARDING': {'yes', 'no'},
                'MAX_AUTH_TRIES': {'3', '4', '5', '6'},
            },
            'bastion': {
                'PERMIT_ROOT_LOGIN': {'no'},
                'PASSWORD_AUTHENTICATION': {'no'},  # Key-only for bastion
                'PERMIT_EMPTY_PASSWORDS': {'no'},
                'X11_FORWARDING': {'no'},
                'ALLOW_TCP_FORWARDING': {'yes'},  # Required for bastion
                'MAX_AUTH_TRIES': {'2', '3'},
            },
            'ci': {
                'PERMIT_ROOT_LOGIN': {'yes', 'no'},
                'PASSWORD_AUTHENTICATION': {'yes', 'no'},
                'PERMIT_EMPTY_PASSWORDS': {'no'},
                'X11_FORWARDING': {'no'},
                'ALLOW_TCP_FORWARDING': {'yes', 'no'},
                'MAX_AUTH_TRIES': {'3', '4', '5', '6'},
            },
        }
    
    def _detect_environment(self) -> str:
        """Detect the running environment type
        
        Returns:
            str: Environment type (development/production/ci/container/bastion)
        """
        # Check for CI/CD environment
        ci_indicators = [
            'CI' in os.environ,
            'GITLAB_CI' in os.environ,
            'GITHUB_ACTIONS' in os.environ,
            'JENKINS_URL' in os.environ,
            os.path.exists('/.dockerenv'),
            os.path.exists('/var/run/docker.sock'),
        ]
        
        if any(ci_indicators):
            return 'ci'
        
        # Check for container
        if os.path.exists('/.dockerenv') or os.path.exists('/var/run/containerd'):
            return 'container'
        
        # Check for development environment (scan all home dirs for AI tool configs)
        ai_tool_dirs = ['.qoder', '.claude', '.cursor', '.vscode']
        home_base = '/home'
        dev_indicators = [os.path.exists('/workspace')]
        if os.path.isdir(home_base):
            for user_dir in os.listdir(home_base):
                user_home = os.path.join(home_base, user_dir)
                if os.path.isdir(user_home):
                    for tool_dir in ai_tool_dirs:
                        if os.path.exists(os.path.join(user_home, tool_dir)):
                            dev_indicators.append(True)
                            break
        
        if any(dev_indicators):
            return 'development'
        
        # Check for bastion/jump host
        if self._is_bastion_host():
            return 'bastion'
        
        return 'production'
    
    def _is_bastion_host(self) -> bool:
        """Check if this host appears to be a bastion/jump host
        
        Returns:
            bool: Whether this is a bastion host
        """
        # Check for bastion-specific indicators
        bastion_indicators = [
            # Hostname patterns
            any(pattern in os.uname().nodename.lower() 
                for pattern in ['bastion', 'jump', 'gateway', 'proxy']),
            # Multiple SSH daemon processes (handling many connections)
            os.path.exists('/var/log/bastion'),
            # Common bastion configurations
            self._has_key_only_auth(),
        ]
        
        return any(bastion_indicators)
    
    def _has_key_only_auth(self) -> bool:
        """Check if system uses key-only authentication
        
        Returns:
            bool: Whether key-only auth is configured
        """
        try:
            # Check main sshd config
            sshd_config = '/etc/ssh/sshd_config'
            if os.path.exists(sshd_config):
                with open(sshd_config, 'r', encoding='utf-8') as f:
                    content = f.read().lower()
                    # Key-only auth: password auth disabled
                    if 'passwordauthentication no' in content:
                        return True
        except OSError:
            pass
        
        return False
    
    def verify(self, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify configuration-related evidence
        
        Args:
            evidence: Evidence to verify
            
        Returns:
            VerifyCheckResult: Verification result
        """
        from .process_verifier import VerifyCheckResult
        
        raw_data = evidence.raw_data or {}
        
        # Check by config key
        config_key = raw_data.get('config_key') or raw_data.get('setting')
        if config_key:
            return self._verify_config_key(config_key, raw_data, evidence)
        
        # Check by permission
        permission = raw_data.get('permission') or raw_data.get('mode')
        if permission:
            return self._verify_permission(permission, evidence)
        
        # Check by service/port configuration
        port = raw_data.get('port') or raw_data.get('listening_port')
        if port:
            return self._verify_port_config(port, evidence)
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason="No configuration indicators to verify"
        )
    
    def _verify_config_key(self, config_key: str, raw_data: Dict, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify configuration key
        
        Args:
            config_key: Configuration key name
            raw_data: Raw evidence data
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        from .process_verifier import VerifyCheckResult
        
        # Development environment configurations are typically safe
        dev_configs = [
            'DEBUG', 'DEVELOPMENT', 'FLASK_ENV', 'NODE_ENV',
            'API_KEY', 'SECRET_KEY', 'DATABASE_URL',
        ]
        
        for dev_config in dev_configs:
            if dev_config.lower() in config_key.lower():
                if self.environment == 'development':
                    return VerifyCheckResult(
                        is_false_positive=True,
                        is_confirmed_threat=False,
                        reason=f"Configuration {config_key} is typical for development environment"
                    )
        
        # Check SSH configurations against baseline
        ssh_configs = self.ssh_baseline.get(self.environment, {})
        for ssh_key, acceptable_values in ssh_configs.items():
            if ssh_key.lower() in config_key.lower():
                # Get the actual value from raw_data
                config_value = str(raw_data.get('value', raw_data.get('setting_value', ''))).lower()
                
                # Check if value is in acceptable range
                if config_value in acceptable_values or config_value in {v.lower() for v in acceptable_values}:
                    return VerifyCheckResult(
                        is_false_positive=True,
                        is_confirmed_threat=False,
                        reason=f"SSH config {config_key}={config_value} is acceptable for {self.environment} environment"
                    )
                
                # Special handling for bastion hosts - more lenient on TCP forwarding
                if self.environment == 'bastion' and ssh_key == 'ALLOW_TCP_FORWARDING':
                    return VerifyCheckResult(
                        is_false_positive=True,
                        is_confirmed_threat=False,
                        reason=f"SSH config {config_key} is required for bastion host operation"
                    )
        
        # Check if it's a standard system configuration
        system_configs = [
            'PERMIT_ROOT_LOGIN', 'PASSWORD_AUTH',  # SSH
            'MAX_CONNECTIONS', 'TIMEOUT',  # Service
            'LOG_LEVEL', 'LOG_FORMAT',  # Logging
        ]
        
        for sys_config in system_configs:
            if sys_config.lower() in config_key.lower():
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Configuration {config_key} is a standard system setting"
                )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Configuration {config_key} requires manual review"
        )
    
    def _verify_permission(self, permission: str, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify file/directory permissions
        
        Args:
            permission: Permission string or octal value
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        try:
            # Parse permission
            if isinstance(permission, str):
                # Convert string like "0644" or "-rw-r--r--" to octal
                if permission.startswith('-') or permission.startswith('d') or permission.startswith('l'):
                    perm_map = {'r': 4, 'w': 2, 'x': 1, '-': 0, 's': 1, 'S': 0, 't': 1, 'T': 0}
                    mode = 0
                    perm_chars = permission[1:10]
                    for i, c in enumerate(perm_chars):
                        if c in perm_map:
                            mode += perm_map[c] * (8 ** (2 - i // 3))
                    if len(perm_chars) >= 3 and perm_chars[2] in ('s', 'S'):
                        mode |= 0o4000
                    if len(perm_chars) >= 6 and perm_chars[5] in ('s', 'S'):
                        mode |= 0o2000
                    if len(perm_chars) >= 9 and perm_chars[8] in ('t', 'T'):
                        mode |= 0o1000
                    perm_octal = mode
                else:
                    perm_octal = int(permission, 8)
            else:
                perm_octal = int(permission)
            
            # Check against safe permissions
            for safe_perm in self.safe_configs['safe_permissions']:
                if perm_octal == safe_perm:
                    return VerifyCheckResult(
                        is_false_positive=True,
                        is_confirmed_threat=False,
                        reason=f"Permission {oct(perm_octal)} is a standard safe permission"
                    )
            
            # Check for world-writable (suspicious)
            if perm_octal & 0o002:
                return VerifyCheckResult(
                    is_false_positive=False,
                    is_confirmed_threat=True,
                    reason=f"Permission {oct(perm_octal)} is world-writable"
                )
            
            # Check for SUID/SGID on non-standard files
            if perm_octal & 0o4000 or perm_octal & 0o2000:
                raw_data = evidence.raw_data or {}
                path = raw_data.get('path', '')
                
                # SUID/SGID in system directories is normal
                system_dirs = ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']
                if not any(path.startswith(d) for d in system_dirs):
                    return VerifyCheckResult(
                        is_false_positive=False,
                        is_confirmed_threat=True,
                        reason=f"SUID/SGID bit set on non-system file: {path}"
                    )
            
        except (ValueError, TypeError) as e:
            logger.debug(f"Failed to parse permission {permission}: {e}")
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=False,
                reason=f"Invalid permission format: {permission}"
            )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Permission {oct(perm_octal) if 'perm_octal' in locals() else permission} requires review"
        )
    
    def _verify_port_config(self, port: int, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify port configuration
        
        Args:
            port: Port number
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        # Check against known safe ports
        all_safe_ports = (
            self.safe_configs['ssh_ports'] +
            self.safe_configs['web_ports'] +
            self.safe_configs['db_ports']
        )
        
        if port in all_safe_ports:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Port {port} is a standard service port"
            )
        
        # High ports are typically safe (ephemeral/client ports)
        if port > 1024:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Port {port} is a high/ephemeral port"
            )
        
        # Well-known ports that aren't in our safe list need review
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Port {port} configuration requires review"
        )
