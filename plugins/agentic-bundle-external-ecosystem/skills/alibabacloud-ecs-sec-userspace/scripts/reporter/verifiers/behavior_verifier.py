"""BehaviorVerifier - Verify behavior-related alerts

Verifies:
- Process behavior patterns
- Network connection patterns
- User activity patterns
- Anomaly detection validation
"""
import os
import logging
from typing import Dict, Optional
from dataclasses import dataclass

from ..evidence import Evidence

logger = logging.getLogger("sec-userspace")


@dataclass
class VerifyCheckResult:
    """Result of a single verification check"""
    is_false_positive: bool
    is_confirmed_threat: bool
    reason: str


class BehaviorVerifier:
    """Verify behavior-related security alerts"""
    
    def __init__(self, collected_data: Optional[Dict] = None):
        """Initialize behavior verifier
        
        Args:
            collected_data: Collected data from collectors
        """
        self.collected_data = collected_data or {}
        self.normal_behaviors = self._get_normal_behavior_patterns()
    
    def _get_normal_behavior_patterns(self) -> Dict[str, dict]:
        """Get normal behavior patterns
        
        Returns:
            Dict mapping behavior type to normal patterns
        """
        return {
            'web_server': {
                'processes': ['nginx', 'apache2', 'httpd', 'caddy'],
                'ports': [80, 443],
                'typical_connections': ['outbound_to_any', 'inbound_from_any'],
            },
            'database': {
                'processes': ['mysql', 'mysqld', 'postgres', 'postgresql', 'mongod', 'redis-server'],
                'ports': [3306, 5432, 6379, 27017],
                'typical_connections': ['localhost_only', 'private_network'],
            },
            'container_runtime': {
                'processes': ['dockerd', 'containerd', 'kubelet', 'docker-proxy'],
                'ports': [2375, 2376, 10250],
                'typical_connections': ['unix_socket', 'bridge_network'],
            },
            'development': {
                'processes': ['python', 'python3', 'node', 'npm', 'go', 'rustc', 'cargo'],
                'ports': [3000, 5000, 8000, 8080, 9000],
                'typical_connections': ['outbound_to_any'],
            },
            'ai_tools': {
                'processes': ['claude', 'qoder', 'cursor', 'copilot', 'codeium'],
                'typical_paths': ['.qoder', '.claude', '.cursor', '.vscode'],
                'typical_connections': ['outbound_to_api_servers'],
            },
        }
    
    def verify(self, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify behavior-related evidence
        
        Args:
            evidence: Evidence to verify
            
        Returns:
            VerifyCheckResult: Verification result
        """
        
        module = evidence.module
        raw_data = evidence.raw_data or {}
        
        # Check based on analyzer module
        if module == 'process_analyzer':
            return self._verify_process_behavior(raw_data, evidence)
        
        elif module == 'network_analyzer':
            return self._verify_network_behavior(raw_data, evidence)
        
        elif module == 'auth_analyzer':
            return self._verify_auth_behavior(raw_data, evidence)
        
        # Generic behavior verification
        return self._verify_generic_behavior(raw_data, evidence)
    
    def _verify_process_behavior(self, raw_data: Dict, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify process behavior anomalies
        
        Args:
            raw_data: Raw evidence data
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        process_name = raw_data.get('name') or raw_data.get('process') or raw_data.get('comm') or ''
        cmdline = raw_data.get('cmdline') or ''
        path = raw_data.get('path') or raw_data.get('exe') or ''
        
        process_lower = process_name.lower() if process_name else ''
        cmdline_lower = cmdline.lower() if cmdline else ''
        path_lower = path.lower() if path else ''
        
        # Check for AI tooling (normal behavior)
        ai_tool_patterns = ['claude', 'qoder', 'cursor', 'opencode', 'copilot']
        for pattern in ai_tool_patterns:
            if pattern in process_lower or pattern in cmdline_lower or pattern in path_lower:
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Process behavior matches AI tooling: {pattern}"
                )
        
        # Check for development tools (normal behavior)
        dev_tool_patterns = ['python', 'node', 'npm', 'pip', 'cargo', 'go ', 'rustc']
        for pattern in dev_tool_patterns:
            if pattern in process_lower or pattern in cmdline_lower:
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Process behavior matches development tool: {pattern}"
                )
        
        # Check for container runtime (normal behavior)
        container_patterns = ['docker', 'containerd', 'kubelet', 'kubectl']
        for pattern in container_patterns:
            if pattern in process_lower or pattern in cmdline_lower:
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Process behavior matches container runtime: {pattern}"
                )
        
        # Check for sec-userspace itself
        if 'sec-userspace' in cmdline_lower or 'scripts.main' in cmdline_lower:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason="Process is sec-userspace scanner itself"
            )
        
        # Check CPU usage anomaly (if available)
        cpu_percent = raw_data.get('cpu_percent')
        try:
            cpu_val = float(cpu_percent) if cpu_percent is not None else None
        except (ValueError, TypeError):
            cpu_val = None
        if cpu_val is not None and cpu_val > 90:
            # High CPU could be legitimate (compilation, data processing)
            # Check if it's a known high-CPU legitimate process
            legitimate_high_cpu = ['gcc', 'g++', 'rustc', 'cargo', 'go', 'python', 'node']
            if any(p in process_lower for p in legitimate_high_cpu):
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"High CPU usage is normal for {process_name}"
                )
            
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=True,
                reason=f"High CPU usage ({cpu_percent}%) by {process_name}"
            )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Process behavior requires manual review: {process_name}"
        )
    
    def _verify_network_behavior(self, raw_data: Dict, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify network behavior anomalies
        
        Args:
            raw_data: Raw evidence data
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        # Get connection details and safely convert ports to int
        src_port_raw = raw_data.get('src_port') or raw_data.get('sport')
        dst_port_raw = raw_data.get('dst_port') or raw_data.get('dport') or raw_data.get('port')
        try:
            src_port = int(src_port_raw) if src_port_raw is not None else None
        except (ValueError, TypeError):
            src_port = None
        try:
            dst_port = int(dst_port_raw) if dst_port_raw is not None else None
        except (ValueError, TypeError):
            dst_port = None

        # Check for ephemeral ports (normal client behavior)
        if src_port is not None and src_port > 1024:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Connection from ephemeral port {src_port} is normal client behavior"
            )

        # Check for common legitimate services
        legitimate_service_ports = {80, 443, 22, 53, 25, 587, 993, 995}
        if dst_port is not None and dst_port in legitimate_service_ports:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Connection to standard service port {dst_port}"
            )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Network behavior requires review: port {dst_port or src_port}"
        )
    
    def _verify_auth_behavior(self, raw_data: Dict, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify authentication behavior anomalies
        
        Args:
            raw_data: Raw evidence data
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        user = raw_data.get('user') or raw_data.get('username')
        service = raw_data.get('service') or raw_data.get('daemon')
        ip = raw_data.get('ip') or raw_data.get('source_ip')
        
        # Check for development environment users
        dev_users = ['ecs-user', 'ubuntu', 'admin', 'developer', 'dev']
        if user and user.lower() in dev_users:
            if self._is_development_environment():
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Authentication by development user {user}"
                )
        
        # Check for automated services (normal)
        automated_services = ['cron', 'systemd', 'sshd', 'sudo', 'su']
        if service and service.lower() in automated_services:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Authentication event from system service {service}"
            )
        
        # Check for internal IP addresses
        if ip and self._is_internal_ip(ip):
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Authentication from internal IP {ip}"
            )
        
        # Failed login attempts - check count
        fail_count = raw_data.get('failures') or raw_data.get('attempts')
        if fail_count:
            try:
                count = int(fail_count)
                if count < 5:
                    return VerifyCheckResult(
                        is_false_positive=True,
                        is_confirmed_threat=False,
                        reason=f"{count} failed attempts is within normal range"
                    )
                elif count >= 10:
                    return VerifyCheckResult(
                        is_false_positive=False,
                        is_confirmed_threat=True,
                        reason=f"{count} failed attempts indicates brute force"
                    )
            except (ValueError, TypeError):
                pass
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Authentication behavior requires review: user={user}, service={service}"
        )
    
    def _verify_generic_behavior(self, raw_data: Dict, evidence: Evidence) -> 'VerifyCheckResult':
        """Generic behavior verification for unclassified cases
        
        Args:
            raw_data: Raw evidence data
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        # Check if evidence title contains development/AI keywords
        title_lower = evidence.title.lower() if evidence.title else ''
        
        dev_keywords = ['development', 'debug', 'test', 'example', 'sample']
        for keyword in dev_keywords:
            if keyword in title_lower:
                if self._is_development_environment():
                    return VerifyCheckResult(
                        is_false_positive=True,
                        is_confirmed_threat=False,
                        reason=f"Evidence title suggests development activity: {keyword}"
                    )
        
        ai_keywords = ['claude', 'qoder', 'cursor', 'ai', 'llm', 'model', 'agent']
        for keyword in ai_keywords:
            if keyword in title_lower:
                return VerifyCheckResult(
                    is_false_positive=True,
                    is_confirmed_threat=False,
                    reason=f"Evidence title suggests AI tooling activity: {keyword}"
                )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason="Generic behavior check inconclusive"
        )
    
    def _is_development_environment(self) -> bool:
        """Check if running in development environment
        
        Returns:
            bool: Whether this is a development environment
        """
        ai_tool_dirs = ['.qoder', '.claude', '.cursor', '.vscode']
        home_base = '/home'
        dev_indicators = [
            os.path.exists('/workspace'),
            bool(os.environ.get('VIRTUAL_ENV')),
        ]
        if os.path.isdir(home_base):
            for user_dir in os.listdir(home_base):
                user_home = os.path.join(home_base, user_dir)
                if os.path.isdir(user_home):
                    for tool_dir in ai_tool_dirs:
                        if os.path.exists(os.path.join(user_home, tool_dir)):
                            dev_indicators.append(True)
                            break
        return sum(dev_indicators) >= 2
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        if not ip:
            return False

        # Handle IPv6 loopback and link-local
        if ':' in ip:
            stripped = ip.strip('[]')
            return stripped == '::1' or stripped.startswith('fe80:') or stripped.startswith('fc') or stripped.startswith('fd')

        try:
            octets = [int(x) for x in ip.split('.')]
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            if octets[0] == 127:
                return True
        except (ValueError, IndexError):
            pass

        return False
