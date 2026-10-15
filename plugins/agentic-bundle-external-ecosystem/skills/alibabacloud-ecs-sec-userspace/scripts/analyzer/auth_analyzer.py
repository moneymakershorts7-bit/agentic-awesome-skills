"""User Authentication Anomaly Analyzer"""
import os
import re
import stat
import bisect
import threading
from collections import defaultdict
from typing import List
from ..reporter.severity import Severity
from ..reporter.evidence import Evidence, EvidenceDetail
from .base import BaseAnalyzer
from ..utils.sensitive_words_encoder import decode_sensitive_word

_NOPASSWD = decode_sensitive_word("Tk9QQVNTV0Q=")  # "NOPASSWD"

_lazy_init_lock = threading.Lock()

_logger = None

_datetime_cache = {}
_datetime_cache_lock = threading.Lock()

def _get_datetime_module():
    """Lazy import datetime module and compat fromisoformat."""
    if 'datetime' not in _datetime_cache:
        with _datetime_cache_lock:
            if 'datetime' not in _datetime_cache:
                from ..utils.datetime_compat import fromisoformat as _fromisoformat
                from datetime import datetime as _dt
                _datetime_cache['datetime'] = _dt
                _datetime_cache['fromisoformat'] = _fromisoformat
    return _datetime_cache['datetime']


def _fromisoformat(ts: str):
    """Parse ISO timestamp using compat layer."""
    return _datetime_cache['fromisoformat'](ts)


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

_lazy_cache = {}
_lazy_cache_lock = threading.Lock()

def _get_attack_tactic_name(attack_id: str) -> str:
    """Lazy import get_attack_tactic_name from i18n module."""
    if 'gatn' not in _lazy_cache:
        with _lazy_cache_lock:
            if 'gatn' not in _lazy_cache:
                from ..utils.i18n import get_attack_tactic_name as _gatn
                _lazy_cache['gatn'] = _gatn
    return _lazy_cache['gatn'](attack_id)

def _get_environment_type():
    """Lazy import environment module."""
    if 'environment' not in _lazy_cache:
        with _lazy_cache_lock:
            if 'environment' not in _lazy_cache:
                from ..utils.environment import get_environment_type
                _lazy_cache['environment'] = get_environment_type
    return _lazy_cache['environment']

class AuthAnalyzer(BaseAnalyzer):
    """User Authentication Anomaly Analyzer"""
    name = "auth_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    required_collectors = ["user", "log"]
    
    # Smart scheduling attributes
    estimated_time = 3.0  # Fast auth log analysis
    analyzer_type = BaseAnalyzer.CRITICAL  # Critical security check
    
    # Pre-compiled regex patterns
    SHELL_WHITELIST = {"root", "sync"}
    LOGIN_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish"}
    
    # SSH backdoor key detection patterns
    SUSPICIOUS_KEY_PATTERNS = [
        re.compile(r"attacker", re.IGNORECASE),
        re.compile(r"backdoor", re.IGNORECASE),
        re.compile(r"malware", re.IGNORECASE),
        re.compile(r"hack", re.IGNORECASE),
        re.compile(r"exploit", re.IGNORECASE),
        re.compile(r"payload", re.IGNORECASE),
        re.compile(r"c2server", re.IGNORECASE),
        re.compile(r"reverse", re.IGNORECASE),
    ]

    # Suspicious command= prefix patterns in SSH keys
    SUSPICIOUS_COMMAND_PATTERNS = [
        re.compile(r'command=".*(/bin/bash|/bin/sh|nc\s|ncat\s|socat\s|curl\s|wget\s)', re.IGNORECASE),
        re.compile(r'command=".*\|.*sh"', re.IGNORECASE),
    ]
    
    # Brute force attack detection
    BRUTE_FORCE_THRESHOLD = 5  # 5 failures within 5 minutes
    BRUTE_FORCE_WINDOW = 300  # 5 minutes (seconds)

    # Abnormal login time period (0-6 AM)
    ABNORMAL_LOGIN_HOURS = set(range(0, 6))
    # SSH tunnel detection pattern
    SSH_TUNNEL_PATTERN = re.compile(r'\s-[LRD]\s')
    
    # SSH lateral movement detection patterns
    SSH_AGENT_FORWARD_PATTERN = re.compile(r'-A\s|AgentForwarding\s*=\s*yes', re.IGNORECASE)
    SSH_KEY_INJECTION_PATTERNS = [
        re.compile(r'ssh-copy-id|ssh-keygen.*-f', re.IGNORECASE),  # Key distribution tools
        re.compile(r'echo.*>>.*authorized_keys', re.IGNORECASE),  # Direct key injection
        re.compile(r'cat.*\.pub\s+>>.*authorized_keys', re.IGNORECASE),  # Public key addition
    ]
    SSH_LATERAL_MOVEMENT_TOOLS = [
        'sshpass',  # Password-based SSH automation
        'clusterssh',  # Cluster SSH tool
        'pssh',  # Parallel SSH
        'ansible',  # Configuration management (can be used for lateral movement)
    ]

    def should_skip(self) -> tuple:
        """Run lightweight auth check in quick mode"""
        # Quick mode runs basic checks only (UID 0, abnormal users)
        return False, ""

    def analyze(self, collected_data: dict) -> list:
        """Analyze user authentication anomalies"""
        evidences = []
        
        user_data = self._get_data(collected_data, "user", default={}, strict=False)
        log_data = self._get_data(collected_data, "log", default={}, strict=False)
        
        if not user_data:
            return evidences
        
        # Quick mode: lightweight checks only
        # Full mode: comprehensive analysis
        # 1. Abnormal user account detection
        evidences.extend(self._check_abnormal_users(user_data))
        
        # 2. SSH backdoor key detection (enhanced)
        evidences.extend(self._check_ssh_backdoor_keys(user_data))
        
        # 3. SSH key deep analysis (newly added)
        evidences.extend(self._check_ssh_key_advanced(user_data))
        
        # 4. SSH config risk detection (enhanced: including tunnel/forwarding detection)
        evidences.extend(self._check_ssh_config_risks(user_data))
        
        # 5. Brute force pattern detection (requires log data)
        if log_data:
            evidences.extend(self._check_brute_force(log_data))
        
        # 6. Abnormal login time detection (requires log data)
        if log_data:
            evidences.extend(self._check_abnormal_login_time(log_data))
        
        # 7. SSH tunnel process detection (newly added)
        process_data = self._get_data(collected_data, "process", default={}, strict=False)
        if process_data:
            evidences.extend(self._check_ssh_tunnel_processes(process_data))

        # 8. Abnormal sudo rule detection
        evidences.extend(self._check_sudo_rules(user_data))

        # 9. SSH lateral movement detection (newly added)
        if process_data:
            evidences.extend(self._check_ssh_lateral_movement(process_data))
        
        # 10. Sudo abuse detection (AN0142)
        evidences.extend(self._check_sudo_abuse(user_data))
        
        return evidences
    def _check_abnormal_users(self, user_data: dict) -> list:
        """Detect abnormal user accounts"""
        evidences = []
        
        for user in user_data.get("users", []):
            username = user.get("username", "")
            uid = user.get("uid", -1)
            shell = user.get("shell", "")
            
            # UID=0 but not root
            if uid == 0 and username != "root":
                evidence_detail = EvidenceDetail(
                    user=username,
                    content=f"UID={uid}, shell={shell}" if uid is not None else None,
                    permission_level="root",
                )
                remediation_cmds = [
                    f"usermod -u 1000 {username}",
                    f"grep '{username}' /etc/passwd",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.CRITICAL,
                    attack_id="T1136.001",
                    title=f"异常 UID=0 账户：{username}",
                    description=f"用户 {username} 具有 UID=0（root 权限），但不是 root 账户",
                    confidence=0.9,
                    raw_data={"username": username, "uid": uid, "shell": shell},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
            
            # System user has login shell and not in whitelist
            if uid < 1000 and uid > 0 and shell in self.LOGIN_SHELLS:
                if username not in self.SHELL_WHITELIST:
                    evidence_detail = EvidenceDetail(
                        user=username,
                        content=f"UID={uid}, shell={shell}",
                        permission_level="system_user",
                    )
                    remediation_cmds = [
                        f"usermod -s /usr/sbin/nologin {username}",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1136.001",
                        title=f"系统用户异常 shell: {username}",
                        description=f"系统用户 {username} (UID={uid}) 拥有可登录 shell: {shell}",
                        confidence=0.6,
                        raw_data={"username": username, "uid": uid, "shell": shell},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
        
        return evidences
    
    def _check_ssh_backdoor_keys(self, user_data: dict) -> list:
        """Detect SSH backdoor keys"""
        evidences = []
        
        for ssh_key_info in user_data.get("ssh_authorized_keys", []):
            user = ssh_key_info.get("user", "")
            key_count = ssh_key_info.get("key_count", 0)
            keys = ssh_key_info.get("keys", [])
            
            # Root user: check suspicious comments
            if user == "root" and key_count > 0:
                for key in keys:
                    comment = key.get("comment", "")
                    key_path = key.get("path", "")
                    raw_line = key.get("raw_line", "")
                    for pattern in self.SUSPICIOUS_KEY_PATTERNS:
                        if pattern.search(comment):
                            evidence_detail = EvidenceDetail(
                                file_path=key_path if key_path else None,
                                user=user,
                                content=raw_line[:200] if raw_line else None,
                                permission_level="root",
                            )
                            remediation_cmds = [
                                f"rm -f {key_path}" if key_path else "rm -f suspicious_key",
                                f"cat {key_path}" if key_path else "cat suspicious_key",
                                "ssh-keygen -R $(hostname)",
                            ]
                            evidences.append(self._create_evidence(
                                severity=Severity.HIGH,
                                attack_id="T1098.004",
                                title=f"SSH 后门密钥：{user}",
                                description=f"root 用户的 SSH 密钥包含可疑 comment: {comment}",
                                confidence=0.7,
                                raw_data={"user": user, "comment": comment},
                                evidence_details=evidence_detail,
                                remediation_commands=remediation_cmds,
                            ))
                            break
            
            # Regular user: key count > 5
            elif user != "root" and key_count > 5:
                # Get first key path for evidence
                first_key = keys[0] if keys else {}
                key_path = first_key.get("path", "")
                raw_line = first_key.get("raw_line", "")
                evidence_detail = EvidenceDetail(
                    file_path=key_path if key_path else None,
                    user=user,
                    content=raw_line[:200] if raw_line else None,
                )
                remediation_cmds = [
                    f"rm -f {key_path}" if key_path else f"# Review SSH keys for {user}",
                    f"chmod 600 {key_path}" if key_path else f"# Fix permissions for {user}",
                    f"chown {user}:{user} {key_path}" if key_path else f"# Fix ownership for {user}",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1098.004",
                    title=f"SSH 密钥数量异常：{user}",
                    description=f"用户 {user} 有 {key_count} 个 SSH 密钥（阈值：5）",
                    confidence=0.5,
                    raw_data={"user": user, "key_count": key_count},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        return evidences
    
    def _check_ssh_config_risks(self, user_data: dict) -> list:
        """Detect SSH configuration risks (including tunnel/port forwarding)
        
        Environment-aware detection: In development/cloud environments,
        certain SSH configurations are common and should have lower severity.
        """
        evidences = []
        
        sshd_config = user_data.get("sshd_config", {})
        if not sshd_config:
            return evidences
        
        # Detect environment type for context-aware alerting
        # Use both EnvironmentDetector (broad) and CloudEnvDetector (cloud-specific)
        env_type = _get_environment_type()
        is_non_production = env_type in ['development', 'cloud', 'ci_cd']

        permit_root = sshd_config.get("permit_root_login", "no").lower()
        password_auth = sshd_config.get("password_authentication", "yes").lower()
        port = sshd_config.get("port", "22")
        
        # PermitRootLogin yes - Environment-aware severity
        if permit_root == "yes":
            # Default values for production environment
            severity = Severity.HIGH
            confidence = 0.6
            
            # Lower severity in non-production environments
            if is_non_production:
                severity = Severity.INFO
                confidence = 0.2
            
            # Build description
            description = "SSH 允许 root 直接登录"
            
            # Higher risk if password authentication is also enabled
            if password_auth == "yes":
                description += ", with password authentication enabled (combined risk)"
                # In production, keep HIGH severity when password auth is enabled
                if not is_non_production:
                    severity = Severity.HIGH
                    confidence = 0.7
                else:
                    # Development environment: still low severity but slightly higher confidence
                    severity = Severity.INFO
                    confidence = 0.3
            else:
                # Key-only auth is safer, lower severity
                description += " (key-based auth only)"
                if is_non_production:
                    severity = Severity.INFO
                    confidence = 0.2
                else:
                    severity = Severity.MEDIUM
                    confidence = 0.4
            
            # Skip evidence creation in development environments for SSH config issues
            # These are expected configurations in dev/cloud/CI environments
            if is_non_production and severity == Severity.INFO:
                # Log for debugging but don't add to evidence list
                pass
            else:
                evidence_detail = EvidenceDetail(
                    file_path="/etc/ssh/sshd_config",
                    content=f"PermitRootLogin={permit_root}, PasswordAuth={password_auth}",
                )
                remediation_cmds = [
                    "vi /etc/ssh/sshd_config  # Fix configuration",
                    "systemctl restart sshd",
                ]
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1556.004",
                    title="SSH 配置风险：PermitRootLogin yes",
                    description=description,
                    confidence=confidence,
                    raw_data={
                        "permit_root_login": permit_root,
                        "password_authentication": password_auth,
                        "environment": env_type
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        # Non-standard port
        if port and port != "22":
            evidence_detail = EvidenceDetail(
                file_path="/etc/ssh/sshd_config",
                content=f"Port={port}",
            )
            remediation_cmds = [
                "vi /etc/ssh/sshd_config  # Fix configuration",
                "systemctl restart sshd",
            ]
            evidences.append(self._create_evidence(
                severity=Severity.INFO,
                attack_id="T1556.004",
                title=f"SSH 非 standard 端口：{port}",
                description=f"SSH 运行在非 standard 端口：{port}",
                confidence=1.0,
                raw_data={"port": port},
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))

        # SSH tunnel/port forwarding config detection
        allow_tcp_fwd = sshd_config.get("allow_tcp_forwarding", "").lower()
        gateway_ports = sshd_config.get("gateway_ports", "").lower()
        permit_tunnel = sshd_config.get("permit_tunnel", "").lower()

        # AllowTcpForwarding - Environment-aware severity
        if allow_tcp_fwd == "yes":
            severity = Severity.MEDIUM
            confidence = 0.5
            
            # Lower severity in development environments where TCP forwarding is common
            if is_non_production:
                severity = Severity.INFO
                confidence = 0.2
            
            # Skip evidence creation in non-production environments
            # TCP forwarding is a common and necessary feature in dev/cloud/CI
            if is_non_production and severity == Severity.INFO:
                pass  # Silent skip to avoid noise
            else:
                evidence_detail = EvidenceDetail(
                    file_path="/etc/ssh/sshd_config",
                    content=f"AllowTcpForwarding={allow_tcp_fwd}",
                )
                remediation_cmds = [
                    "vi /etc/ssh/sshd_config  # Fix configuration",
                    "systemctl restart sshd",
                ]
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1572",
                    title="SSH 配置风险：AllowTcpForwarding yes",
                    description="SSH 允许 TCP 端口转发，可能被用于隧道代理" +
                              (" (开发/云环境常见配置)" if is_non_production else ""),
                    confidence=confidence,
                    raw_data={"AllowTcpForwarding": allow_tcp_fwd, "environment": env_type},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))

        # GatewayPorts - Still report as HIGH in all environments (more risky)
        if gateway_ports == "yes":
            severity = Severity.HIGH
            confidence = 0.7
            
            # Slightly lower in non-production but still significant risk
            if is_non_production:
                severity = Severity.MEDIUM
                confidence = 0.5
            
            evidences.append(self._create_evidence(
                severity=severity,
                attack_id="T1572",
                title="SSH 配置风险：GatewayPorts yes",
                description="SSH GatewayPorts 已启用，允许远程主机连接转发端口" +
                          (" (开发环境可能必要)" if is_non_production else ""),
                confidence=confidence,
                raw_data={"GatewayPorts": gateway_ports, "environment": env_type},
                evidence_details=EvidenceDetail(
                    file_path="/etc/ssh/sshd_config",
                    content=f"GatewayPorts={gateway_ports}",
                ),
                remediation_commands=[
                    "vi /etc/ssh/sshd_config  # Fix configuration",
                    "systemctl restart sshd",
                ],
            ))

        # PermitTunnel - Environment-aware severity
        if permit_tunnel in ("yes", "point-to-point", "ethernet"):
            severity = Severity.MEDIUM
            confidence = 0.6
            
            if is_non_production:
                severity = Severity.INFO
                confidence = 0.2
            
            # Skip evidence creation in non-production environments
            # PermitTunnel is common in dev/cloud for VPN-like setups
            if is_non_production and severity == Severity.INFO:
                pass  # Silent skip to avoid noise
            else:
                evidence_detail = EvidenceDetail(
                    file_path="/etc/ssh/sshd_config",
                    content=f"PermitTunnel={permit_tunnel}",
                )
                remediation_cmds = [
                    "vi /etc/ssh/sshd_config  # Fix configuration",
                    "systemctl restart sshd",
                ]
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1572",
                    title=f"SSH 配置风险：PermitTunnel {permit_tunnel}",
                    description=f"SSH PermitTunnel set to {permit_tunnel}, allows tunnel device forwarding" +
                              (" (dev/cloud common)" if is_non_production else ""),
                    confidence=confidence,
                    raw_data={"PermitTunnel": permit_tunnel, "environment": env_type},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        # SSH hardening baseline checks (new)
        evidences.extend(self._check_ssh_config_hardening(sshd_config, env_type))
        
        return evidences
    
    def _check_ssh_config_hardening(self, sshd_config: dict, env_type: str) -> List[Evidence]:
        """Check SSH configuration against security hardening baseline
        
        This method implements comprehensive SSH security baseline checks based on
        CIS Benchmark and industry best practices. All checks support environment-aware
        severity adjustment to reduce false positives in development/cloud environments.
        
        Args:
            sshd_config: SSH daemon configuration dictionary
            env_type: Environment type ('production', 'development', 'cloud', 'ci_cd')
            
        Returns:
            List of Evidence objects for detected security issues
            
        Hardening checks:
        - PasswordAuthentication: Should be disabled in favor of key-based auth
        - PermitEmptyPasswords: Must always be disabled (CRITICAL)
        - X11Forwarding: Should be disabled unless required
        - MaxAuthTries: Should be 3-6 to prevent brute force
        - HostbasedAuthentication: Should be disabled (lateral movement risk)
        - IgnoreRhosts: Should be enabled (ignore legacy rhosts files)
        """
        evidences = []
        is_production = env_type == 'production'
        
        # Check PasswordAuthentication
        password_auth = sshd_config.get("password_authentication", "yes").lower()
        if password_auth == "yes":
            severity = Severity.MEDIUM if is_production else Severity.INFO
            confidence = 0.6 if is_production else 0.2
            
            # Skip evidence creation in non-production environments
            # Password authentication is acceptable in development/test environments
            if not is_production:
                pass  # Silent skip to avoid noise in dev/cloud/CI
            else:
                description = "建议使用密钥认证替代密码认证 (生产环境推荐禁用)"
                evidence_detail = EvidenceDetail(
                    file_path="/etc/ssh/sshd_config",
                    content=f"PasswordAuthentication={password_auth}",
                )
                remediation_cmds = [
                    "vi /etc/ssh/sshd_config  # Fix configuration",
                    "systemctl restart sshd",
                ]
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1556.004",
                    title="SSH 密码认证已启用",
                    description=description,
                    confidence=confidence,
                    raw_data={"password_authentication": password_auth, "environment": env_type},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        # Check PermitEmptyPasswords - ALWAYS CRITICAL
        empty_passwords = sshd_config.get("permit_empty_passwords", "no").lower()
        if empty_passwords == "yes":
            evidence_detail = EvidenceDetail(
                file_path="/etc/ssh/sshd_config",
                content=f"PermitEmptyPasswords={empty_passwords}",
            )
            remediation_cmds = [
                "vi /etc/ssh/sshd_config  # Fix configuration",
                "systemctl restart sshd",
            ]
            evidences.append(self._create_evidence(
                severity=Severity.CRITICAL,
                attack_id="T1556.004",
                title="SSH 允许空密码认证",
                description="严重安全风险：SSH 配置允许空密码登录",
                confidence=0.9,
                raw_data={"permit_empty_passwords": empty_passwords},
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))
        
        # Check X11Forwarding
        x11_forwarding = sshd_config.get("x11_forwarding", "no").lower()
        if x11_forwarding == "yes":
            severity = Severity.LOW if is_production else Severity.INFO
            confidence = 0.4 if is_production else 0.3
            description = "X11 转发可能被用于图形界面攻击"
            if is_production:
                description += " (生产环境推荐禁用)"
            else:
                description += " (开发环境常用)"
            
            evidences.append(self._create_evidence(
                severity=severity,
                attack_id="T1556.004",
                title="SSH X11 转发已启用",
                description=description,
                confidence=confidence,
                raw_data={"x11_forwarding": x11_forwarding, "environment": env_type},
                evidence_details=EvidenceDetail(
                    file_path="/etc/ssh/sshd_config",
                    content=f"X11Forwarding={x11_forwarding}",
                ),
                remediation_commands=[
                    "vi /etc/ssh/sshd_config  # Fix configuration",
                    "systemctl restart sshd",
                ],
            ))
        
        # Check MaxAuthTries (brute force protection)
        max_auth_tries = sshd_config.get("max_auth_tries", "6")
        try:
            if int(max_auth_tries) > 6:
                severity = Severity.LOW
                confidence = 0.5
                evidence_detail = EvidenceDetail(
                    file_path="/etc/ssh/sshd_config",
                    content=f"MaxAuthTries={max_auth_tries}",
                )
                remediation_cmds = [
                    "vi /etc/ssh/sshd_config  # Fix configuration",
                    "systemctl restart sshd",
                ]
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1110",
                    title=f"SSH MaxAuthTries 过高：{max_auth_tries}",
                    description="较高的 MaxAuthTries 值可能增加暴力破解风险，推荐设置为 3-6",
                    confidence=confidence,
                    raw_data={"max_auth_tries": max_auth_tries},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        except ValueError:
            pass
        
        # Check HostbasedAuthentication
        hostbased_auth = sshd_config.get("hostbased_authentication", "no").lower()
        if hostbased_auth == "yes":
            severity = Severity.MEDIUM if is_production else Severity.INFO
            confidence = 0.5 if is_production else 0.3
            description = "HostbasedAuthentication 可能被用于横向移动"
            if is_production:
                description += " (生产环境推荐禁用)"
            
            evidence_detail = EvidenceDetail(
                file_path="/etc/ssh/sshd_config",
                content=f"HostbasedAuthentication={hostbased_auth}",
            )
            remediation_cmds = [
                "vi /etc/ssh/sshd_config  # Fix configuration",
                "systemctl restart sshd",
            ]
            evidences.append(self._create_evidence(
                severity=severity,
                attack_id="T1556.004",
                title="SSH 基于主机的认证已启用",
                description=description,
                confidence=confidence,
                raw_data={"hostbased_authentication": hostbased_auth, "environment": env_type},
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))
        
        # Check IgnoreRhosts
        ignore_rhosts = sshd_config.get("ignore_rhosts", "yes").lower()
        if ignore_rhosts == "no":
            severity = Severity.MEDIUM if is_production else Severity.INFO
            confidence = 0.5 if is_production else 0.3
            description = "IgnoreRhosts 未启用，可能信任遗留的 rhosts 文件"
            if is_production:
                description += " (生产环境推荐启用)"
            
            evidence_detail = EvidenceDetail(
                file_path="/etc/ssh/sshd_config",
                content=f"IgnoreRhosts={ignore_rhosts}",
            )
            remediation_cmds = [
                "vi /etc/ssh/sshd_config  # Fix configuration",
                "systemctl restart sshd",
            ]
            evidences.append(self._create_evidence(
                severity=severity,
                attack_id="T1556.004",
                title="SSH IgnoreRhosts 未启用",
                description=description,
                confidence=confidence,
                raw_data={"ignore_rhosts": ignore_rhosts, "environment": env_type},
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))
        
        return evidences
    
    def _check_brute_force(self, log_data: dict) -> list:
        """Detect brute force attack patterns"""
        evidences = []
        
        failed_logins = log_data.get("auth_log", {}).get("failed_logins", [])
        successful_logins = log_data.get("auth_log", {}).get("successful_logins", [])
        
        if not failed_logins:
            return evidences
        
        datetime_cls = _get_datetime_module()
        bisect_right = bisect.bisect_right
        
        # Group failed logins by source_ip
        ip_failures = defaultdict(list)
        for login in failed_logins:
            ip_hash = login.get("source_ip_hash", "")
            timestamp_str = login.get("timestamp", "")
            if ip_hash and timestamp_str:
                try:
                    timestamp = _fromisoformat(timestamp_str)
                    ip_failures[ip_hash].append(timestamp)
                except ValueError:
                    pass
        
        # Check failure count per IP
        for ip_hash, timestamps in ip_failures.items():
            timestamps.sort()
            
            # Sliding window detection - optimized to O(n log n) using bisect
            for i, ts in enumerate(timestamps):
                window_end = ts.timestamp() + self.BRUTE_FORCE_WINDOW
                # Use binary search to find window end position
                j = bisect_right(timestamps, datetime_cls.fromtimestamp(window_end), lo=i)
                count = j - i
                
                if count >= self.BRUTE_FORCE_THRESHOLD:
                    # Check if this IP has successful logins
                    ip_success = any(
                        login.get("source_ip_hash") == ip_hash
                        for login in successful_logins
                    )
                    
                    severity = Severity.HIGH if ip_success else Severity.MEDIUM
                    title = f"Brute force attack{'成功' if ip_success else '尝试'}: IP (hash:{ip_hash[:8]}...)"
                    description = f"IP (hash:{ip_hash[:8]}...) 在 5 分钟窗口内失败{count}次"
                    if ip_success:
                        description += "，且该 IP 有成功登录记录"
                    
                    evidence_detail = EvidenceDetail(
                        content=f"Failed attempts: {count} from {ip_hash[:8]}...",
                    )
                    remediation_cmds = [
                        f"fail2ban-client set sshd banip {ip_hash}",
                        f"iptables -A INPUT -s {ip_hash} -j DROP",
                    ]
                    evidences.append(self._create_evidence(
                        severity=severity,
                        attack_id="T1110",
                        title=title,
                        description=description,
                        confidence=0.8,
                        raw_data={"source_ip_hash": ip_hash, "failure_count": count, "success_login": ip_success},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break  # Report once per IP
        
        return evidences
    
    def _is_truly_broad_permission(self, rule: str) -> bool:
        """Check if sudo rule is actually broad or has meaningful restrictions
        
        Args:
            rule: sudoers rule string
            
        Returns:
            True if the rule is truly broad (unrestricted), False if it has restrictions
        """
        # Safe restrictions that indicate this is NOT a broad permission
        safe_restrictions = [
            r'!SHELLS',      # Shell execution prohibited
            r'!SUDOEXEC',    # Sudo execution prohibited  
            r'!/bin/(?:ba)?sh\b(?!.*\*)',  # Specific shell denial (not wildcard)
            r'NOEXEC',       # Command execution restricted
            r'SETENV:',      # Only specific env vars allowed
        ]
        
        for restriction in safe_restrictions:
            if re.search(restriction, rule, re.IGNORECASE):
                return False
        
        # Check for specific command whitelists (NOT broad)
        # Match patterns like "NOPASSWD: /usr/bin/systemctl" (specific commands)
        specific_cmd_match = re.search(rf'{_NOPASSWD}:\s*(.+?)(?:\s*,\s*\S+\s*$|$)', rule, re.IGNORECASE)
        if specific_cmd_match:
            cmds = specific_cmd_match.group(1).strip()
            # If it's a comma-separated list of specific commands (not wildcards, not ALL)
            if ',' in cmds and 'ALL' not in cmds and '*' not in cmds:
                return False
            # Single specific command (not ALL, not wildcard)
            if cmds and cmds != 'ALL' and '*' not in cmds and '/' in cmds and not cmds.endswith('/*'):
                return False
        
        # Check for broad permissions: ANY user spec with NOPASSWD: ALL or wildcards
        # Matches: ALL=(ALL) ALL, ALL=(root) ALL, user=(ANY) NOPASSWD: ALL, etc.
        if re.search(rf'ALL=\([^)]+\)\s*({_NOPASSWD}:\s*)?ALL\s*$', rule.strip(), re.IGNORECASE):
            return True
        
        # Check for wildcard patterns like /bin/*, /usr/bin/*
        if re.search(rf'({_NOPASSWD}:\s*)?/\w+/[*]', rule, re.IGNORECASE):
            return True
        
        # Check for specific shell access via NOPASSWD
        if re.search(rf'{_NOPASSWD}:\s*/bin/(?:ba)?sh(?:\s|$)', rule, re.IGNORECASE):
            return True
        
        return False

    def _check_sudo_rules(self, user_data: dict) -> list:
        """Detect abnormal sudo rules with environment context awareness
        
        In development and cloud environments, NOPASSWD rules are common
        configurations and should not trigger alerts to reduce false positives.
        In production environments, all suspicious sudo rules are still reported.
        Enhanced to recognize restricted sudo rules (!SHELLS, !SUDOEXEC, etc.)
        and avoid false positives on legitimately constrained configurations.
        """
        evidences = []
        
        sudoers_entries = user_data.get("sudoers_entries", [])
        
        # Detect environment type for context-aware alerting
        # Use both EnvironmentDetector (broad) and CloudEnvDetector (cloud-specific)
        env_type = _get_environment_type()
        is_non_production = env_type in ['development', 'cloud', 'ci_cd']

        # Standard sudo rules that are typically benign (FP prevention)
        standard_sudo_patterns = [
            r'%admin\s+ALL=\(ALL\)\s+ALL',  # Standard admin group
            r'%sudo\s+ALL=\(ALL:ALL\)\s+ALL',  # Debian/Ubuntu sudo group
            r'root\s+ALL=',  # Root user rules
        ]
        
        for entry in sudoers_entries:
            # Skip standard sudo rules (FP prevention)
            is_standard = any(re.search(pattern, entry) for pattern in standard_sudo_patterns)
            if is_standard:
                continue
            
            # Check NOPASSWD - skip in non-production environments
            if _NOPASSWD in entry:
                if is_non_production:
                    # Log but don't alert in development/cloud/CI environments
                    pass  # Silent skip to avoid noise
                else:
                    # Production environment: report as risk
                    evidence_detail = EvidenceDetail(
                        file_path="/etc/sudoers",
                        content=entry[:500] if entry else None,
                    )
                    remediation_cmds = [
                        f"visudo  # Review {_NOPASSWD} rule",
                        f"grep '{_NOPASSWD}' /etc/sudoers",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.LOW,
                        attack_id="T1548.003",
                        title=f"sudo {_NOPASSWD} rule",
                        description=f"Found {_NOPASSWD} sudo rule in production: {entry}",
                        confidence=0.5,
                        raw_data={"entry": entry, "environment": env_type},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
            
            # Check ALL=(ALL) ALL - only report if truly broad (no restrictions)
            if re.search(r"ALL=\(ALL\)\s+ALL", entry):
                # Skip if the rule has meaningful restrictions
                if not self._is_truly_broad_permission(entry):
                    # Rule has restrictions like !SHELLS or !SUDOEXEC, skip FP
                    continue
                    
                evidences.append(self._create_evidence(
                    severity=Severity.LOW,
                    attack_id="T1548.003",
                    title="sudo broad permission rule",
                    description=f"Found broad permission sudo rule: {entry}",
                    confidence=0.5,
                    raw_data={"entry": entry, "environment": env_type},
                    evidence_details=EvidenceDetail(
                        file_path="/etc/sudoers",
                        content=entry[:500] if entry else None,
                    ),
                    remediation_commands=[
                        "visudo  # Remove broad permission rule",
                        f"grep '{entry[:50]}' /etc/sudoers" if entry else "grep 'ALL=(ALL) ALL' /etc/sudoers",
                    ],
                ))
        
        return evidences

    def _check_ssh_key_advanced(self, user_data: dict) -> list:
        """SSH key deep analysis: command= options, file permission anomalies, recent modifications"""
        evidences = []

        for ssh_key_info in user_data.get("ssh_authorized_keys", []):
            user = ssh_key_info.get("user", "")
            path = ssh_key_info.get("path", "")
            keys = ssh_key_info.get("keys", [])

            # Detect suspicious commands in command= options
            for key in keys:
                raw_line = key.get("raw_line", "")
                if raw_line.startswith("command="):
                    for pattern in self.SUSPICIOUS_COMMAND_PATTERNS:
                        if pattern.search(raw_line):
                            evidence_detail = EvidenceDetail(
                                file_path=path if path else None,
                                user=user,
                                content=raw_line[:200] if raw_line else None,
                            )
                            remediation_cmds = [
                                f"rm -f {path}" if path else f"# Review SSH key for {user}",
                                f"chmod 600 {path}" if path else f"# Fix permissions for {user}",
                                f"chown {user}:{user} {path}" if path else f"# Fix ownership for {user}",
                            ]
                            evidences.append(self._create_evidence(
                                severity=Severity.HIGH,
                                attack_id="T1098.004",
                                title=f"SSH 密钥可疑 command 选项：{user}",
                                description=f"用户 {user} 的 SSH 密钥包含可疑的 command=选项",
                                confidence=0.8,
                                source_path=path,
                                raw_data={
                                    "user": user,
                                    "path": path,
                                    "command_line": raw_line[:200],
                                },
                                evidence_details=evidence_detail,
                                remediation_commands=remediation_cmds,
                            ))
                            break

                # Detect no-pty option + command combination (can be used for backdoor)
                if "no-pty" in raw_line and "command=" in raw_line:
                    evidence_detail = EvidenceDetail(
                        file_path=path if path else None,
                        user=user,
                        content=raw_line[:200] if raw_line else None,
                    )
                    remediation_cmds = [
                        f"rm -f {path}" if path else f"# Review SSH key for {user}",
                        f"chmod 600 {path}" if path else f"# Fix permissions for {user}",
                        f"chown {user}:{user} {path}" if path else f"# Fix ownership for {user}",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1098.004",
                        title=f"SSH 密钥 no-pty+command 组合：{user}",
                        description=f"用户 {user} 的 SSH 密钥同时包含 no-pty 和 command 限制",
                        confidence=0.6,
                        source_path=path,
                        raw_data={"user": user, "path": path},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))

            # Detect authorized_keys file permission anomalies
            if path:
                try:
                    datetime_cls = _get_datetime_module()
                    
                    st = os.stat(path)
                    mode = stat.S_IMODE(st.st_mode)
                    # Permissions should be 600 or 644
                    if mode not in (0o600, 0o644, 0o640):
                        evidence_detail = EvidenceDetail(
                            file_path=path,
                            user=user,
                            content=f"Permissions: {oct(mode)} (expected 0600/0644)",
                        )
                        remediation_cmds = [
                            f"chmod 600 {path}",
                            f"chown {user}:{user} {path}",
                        ]
                        evidences.append(self._create_evidence(
                            severity=Severity.MEDIUM,
                            attack_id="T1098.004",
                            title=f"authorized_keys 权限异常：{user}",
                            description=f"User {user} {path} permissions are {oct(mode)}，"
                                        f"应为 0600 或 0644",
                            confidence=0.6,
                            source_path=path,
                            raw_data={
                                "user": user,
                                "path": path,
                                "permissions": oct(mode),
                            },
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))

                    # Detect recent modifications (within 7 days)
                    mtime = datetime_cls.fromtimestamp(st.st_mtime)
                    days_ago = (datetime_cls.now() - mtime).days
                    if days_ago <= 7:
                        evidence_detail = EvidenceDetail(
                            file_path=path,
                            user=user,
                            content=f"Modified {days_ago} days ago ({mtime.isoformat()})",
                        )
                        remediation_cmds = [
                            f"ls -la {path}",
                            f"stat {path}",
                        ]
                        evidences.append(self._create_evidence(
                            severity=Severity.MEDIUM,
                            attack_id="T1098.004",
                            title=f"authorized_keys 近期修改：{user}",
                            description=f"User {user} {path} was modified {days_ago} days ago",
                            confidence=0.5,
                            source_path=path,
                            raw_data={
                                "user": user,
                                "path": path,
                                "mtime": mtime.isoformat(),
                                "days_ago": days_ago,
                            },
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))
                except OSError:
                    pass

        return evidences

    def _check_abnormal_login_time(self, log_data: dict) -> list:
        """Detect abnormal time period logins (midnight 0-6 AM)"""
        evidences = []

        successful_logins = log_data.get("auth_log", {}).get("successful_logins", [])
        if not successful_logins:
            return evidences

        datetime_cls = _get_datetime_module()
        abnormal_logins = []
        for login in successful_logins:
            timestamp_str = login.get("timestamp", "")
            if not timestamp_str:
                continue
            try:
                ts = None
                try:
                    ts = _fromisoformat(timestamp_str)
                except ValueError:
                    try:
                        ts = datetime_cls.strptime(timestamp_str, "%b %d %H:%M:%S")
                        ts = ts.replace(year=datetime_cls.now().year)
                    except ValueError:
                        continue

                if ts and ts.hour in self.ABNORMAL_LOGIN_HOURS:
                    abnormal_logins.append({
                        "timestamp": timestamp_str,
                        "user": login.get("user", ""),
                        "source_ip": login.get("source_ip", ""),
                        "method": login.get("method", ""),
                        "hour": ts.hour,
                    })
            except (ValueError, TypeError):
                continue

        if abnormal_logins:
            login_summaries = []
            for l in abnormal_logins[:3]:
                login_summaries.append(l.get("user", "") + "@" + l.get("source_ip", ""))
            evidence_detail = EvidenceDetail(
                content=f"Abnormal logins: {len(abnormal_logins)} times in 0-6 AM",
            )
            remediation_cmds = []
            for l in abnormal_logins[:3]:
                username = l.get("user", "")
                if username:
                    remediation_cmds.append(f"last | grep {username}")
                    remediation_cmds.append(f"lastb | grep {username}")
            if not remediation_cmds:
                remediation_cmds = ["last | grep -i login", "lastb | head -20"]
            evidences.append(self._create_evidence(
                severity=Severity.MEDIUM,
                attack_id="T1078",
                title=f"Abnormal login time detected: {len(abnormal_logins)}次",
                description="检测到 {} 次凌晨 (0-6 点) 成功登录：{}".format(
                    len(abnormal_logins), ", ".join(login_summaries)),
                confidence=0.5,
                raw_data={"abnormal_logins": abnormal_logins[:10]},
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))

        return evidences

    def _check_ssh_tunnel_processes(self, process_data: dict) -> list:
        """Detect SSH tunnel/port forwarding processes"""
        evidences = []

        for proc in process_data.get("processes", []):
            comm = proc.get("comm", "")
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)

            if comm != "ssh" or not cmdline:
                continue

            # Detect -L (local forwarding) / -R (remote forwarding) / -D (dynamic SOCKS forwarding)
            if self.SSH_TUNNEL_PATTERN.search(cmdline):
                evidence_detail = EvidenceDetail(
                    pid=pid,
                    cmdline=cmdline[:500] if cmdline else None,
                )
                remediation_cmds = [
                    f"kill -9 {pid}",
                    "ps aux | grep ssh",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1572",
                    title=f"SSH 隧道/端口转发：PID {pid}",
                    description=f"检测到 SSH 隧道进程 (PID {pid}): {cmdline[:200]}",
                    confidence=0.7,
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cmdline": cmdline[:500],
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))

        
        return evidences

    def _check_ssh_lateral_movement(self, process_data: dict) -> list:
        """Detect SSH-based lateral movement techniques
        
        Detects:
        - SSH agent forwarding abuse
        - SSH key injection/distribution
        - Lateral movement tools (sshpass, clusterssh, etc.)
        - Mass SSH scanning/connection attempts
        
        ATT&CK: T1021.004, T1572
        """
        evidences = []
        
        for proc in process_data.get("processes", []):
            comm = proc.get("comm", "")
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            
            # Detect SSH agent forwarding
            if comm == "ssh" and self.SSH_AGENT_FORWARD_PATTERN.search(cmdline):
                evidence_detail = EvidenceDetail(
                    pid=pid,
                    cmdline=cmdline[:500] if cmdline else None,
                )
                remediation_cmds = [
                    f"kill -9 {pid}",
                    "ps aux | grep ssh",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1021.004",
                    title=f"SSH Agent Forwarding: PID {pid}",
                    description=f"Detected SSH agent forwarding (PID {pid}): {cmdline[:200]}",
                    confidence=0.7,
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cmdline": cmdline[:500],
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
            
            # Detect SSH key injection attempts
            for pattern in self.SSH_KEY_INJECTION_PATTERNS:
                if pattern.search(cmdline):
                    evidence_detail = EvidenceDetail(
                        pid=pid,
                        cmdline=cmdline[:500] if cmdline else None,
                    )
                    remediation_cmds = [
                        f"kill -9 {pid}",
                        "ps aux | grep ssh",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1098.004",
                        title=f"SSH Key Injection: PID {pid}",
                        description=f"Detected SSH key injection attempt (PID {pid}): {cmdline[:200]}",
                        confidence=0.75,
                        raw_data={
                            "pid": pid,
                            "cmdline": cmdline[:500],
                        },
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break
            
            # Detect lateral movement tools
            for tool in self.SSH_LATERAL_MOVEMENT_TOOLS:
                if tool in cmdline.lower() or tool in comm.lower():
                    # ansible is common admin tool, lower severity
                    severity = Severity.MEDIUM if tool == "ansible" else Severity.HIGH
                    confidence = 0.6 if tool == "ansible" else 0.8
                    
                    evidence_detail = EvidenceDetail(
                        pid=pid,
                        cmdline=cmdline[:500] if cmdline else None,
                    )
                    remediation_cmds = [
                        f"kill -9 {pid}",
                        f"ps aux | grep {tool}",
                    ]
                    evidences.append(self._create_evidence(
                        severity=severity,
                        attack_id="T1021.004",
                        title=f"Lateral Movement Tool: {tool}",
                        description=f"Detected lateral movement tool {tool} (PID {pid})",
                        confidence=confidence,
                        raw_data={
                            "pid": pid,
                            "tool": tool,
                            "cmdline": cmdline[:500],
                        },
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break
            
            # Detect mass SSH scanning (multiple IPs in command line)
            if comm == "ssh" and cmdline:
                # Count IP-like patterns in cmdline
                ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                ips = ip_pattern.findall(cmdline)
                if len(ips) >= 3:
                    evidence_detail = EvidenceDetail(
                        pid=pid,
                        cmdline=cmdline[:500] if cmdline else None,
                    )
                    remediation_cmds = [
                        f"kill -9 {pid}",
                        "ps aux | grep ssh",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1021.004",
                        title=f"Mass SSH Connection: PID {pid}",
                        description=f"Detected mass SSH connection attempts involving {len(ips)}  IP addresses",
                        confidence=0.65,
                        raw_data={
                            "pid": pid,
                            "ip_count": len(ips),
                            "cmdline": cmdline[:500],
                        },
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
        
        return evidences

    def _check_sudo_abuse(self, user_data: dict) -> list:
        """Detect sudo abuse and misconfiguration.
        
        Detects:
        - NOPASSWD sudo rules for non-root users
        - Sudo rules allowing ALL commands
        - Sudo rules with dangerous commands (shell, editor, etc.)
        - Sudo rules with wildcard patterns
        
        ATT&CK: T1548.003
        """
        evidences = []
        
        sudo_rules = user_data.get("sudo_rules", [])
        if not sudo_rules:
            return evidences
        
        dangerous_commands = {
            'bash', 'sh', 'zsh', 'fish', 'dash',
            'vi', 'vim', 'nano', 'emacs', 'ed',
            'python', 'python3', 'perl', 'ruby', 'php',
            'find', 'awk', 'sed',
            'env', 'nmap', 'tcpdump',
            'docker', 'git',
            'cp', 'mv', 'chmod', 'chown',
            'apt', 'apt-get', 'yum', 'dnf', 'pip', 'pip3',
            'systemctl', 'service',
        }
        
        for rule in sudo_rules:
            user = rule.get("user", "")
            hosts = rule.get("hosts", [])
            run_as = rule.get("run_as", "root")
            commands = rule.get("commands", [])
            tags = rule.get("tags", [])
            
            has_nopasswd = _NOPASSWD in tags
            has_all_commands = any(cmd == "ALL" for cmd in commands)
            has_dangerous = False
            dangerous_found = []
            
            for cmd in commands:
                if cmd == "ALL":
                    continue
                
                cmd_base = cmd.split('/')[-1].split()[0].lower()
                if cmd_base in dangerous_commands:
                    has_dangerous = True
                    dangerous_found.append(cmd)
                
                if '*' in cmd:
                    evidence_detail = EvidenceDetail(
                        user=user,
                        content=f"Wildcard rule: {cmd}",
                    )
                    remediation_cmds = [
                        "visudo  # Review wildcard sudo rules",
                        f"grep '{user}' /etc/sudoers",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1548.003",
                        title=f"Wildcard Sudo Rule: {user}",
                        description=f"User '{user}' has sudo rule with wildcard: {cmd}",
                        confidence=0.6,
                        raw_data={
                            "user": user,
                            "rule": cmd,
                            "hosts": hosts,
                            "run_as": run_as,
                        },
                        remediation="Avoid wildcards in sudo rules. Specify exact commands with full paths.",
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
            
            if has_all_commands:
                severity = Severity.HIGH if has_nopasswd else Severity.MEDIUM
                evidence_detail = EvidenceDetail(
                    user=user,
                    content=f"{_NOPASSWD}={has_nopasswd}, commands=ALL",
                )
                remediation_cmds = [
                    "visudo  # Restrict sudo commands",
                    f"grep '{user}' /etc/sudoers",
                ]
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1548.003",
                    title=f"Unrestricted Sudo Access: {user}",
                    description=(
                        f"User '{user}' can run ALL commands"
                        f"{' without password' if has_nopasswd else ''}. "
                        f"This allows full privilege escalation."
                    ),
                    confidence=0.8,
                    raw_data={
                        "user": user,
                        "nopasswd": has_nopasswd,
                        "commands": "ALL",
                        "hosts": hosts,
                        "run_as": run_as,
                    },
                    remediation=(
                        f"Restrict sudo access for '{user}' to specific commands only. "
                        f"Use 'visudo' to edit sudo rules."
                    ),
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
            
            if has_nopasswd and not has_all_commands:
                evidence_detail = EvidenceDetail(
                    user=user,
                    content=f"{_NOPASSWD} commands: {', '.join(commands[:5])}",
                )
                remediation_cmds = [
                    f"visudo  # Review {_NOPASSWD} rules",
                    f"grep '{user}' /etc/sudoers",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.LOW,
                    attack_id="T1548.003",
                    title=f"{_NOPASSWD} Sudo Rule: {user}",
                    description=f"User '{user}' has {_NOPASSWD} sudo for: {', '.join(commands[:5])}",
                    confidence=0.5,
                    raw_data={
                        "user": user,
                        "commands": commands[:10],
                        "hosts": hosts,
                        "run_as": run_as,
                    },
                    remediation="Consider requiring password for sudo operations.",
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
            
            if has_dangerous:
                evidence_detail = EvidenceDetail(
                    user=user,
                    content=f"Dangerous commands: {', '.join(dangerous_found[:5])}",
                )
                remediation_cmds = [
                    "visudo  # Remove dangerous commands from sudo rules",
                    f"grep '{user}' /etc/sudoers",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1548.003",
                    title=f"Dangerous Sudo Command: {user}",
                    description=(
                        f"User '{user}' can run dangerous commands via sudo: "
                        f"{', '.join(dangerous_found[:5])}"
                    ),
                    confidence=0.7,
                    raw_data={
                        "user": user,
                        "dangerous_commands": dangerous_found,
                        "hosts": hosts,
                        "run_as": run_as,
                    },
                    remediation="Remove dangerous commands from sudo rules. Use restricted alternatives.",
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        return evidences
