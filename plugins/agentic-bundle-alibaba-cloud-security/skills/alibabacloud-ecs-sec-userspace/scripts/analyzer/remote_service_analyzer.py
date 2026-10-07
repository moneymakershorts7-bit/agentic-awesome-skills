"""External Remote Service Anomaly Detection Analyzer - T1133"""
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List
from ..reporter.severity import Severity
from ..reporter.evidence import Evidence, EvidenceDetail
from .base import BaseAnalyzer
from ..utils.environment import is_development_env
from ..utils.remediation_generator import generate_generic_remediation, generate_process_remediation

class RemoteServiceAnalyzer(BaseAnalyzer):
    """External Remote Service Anomaly Detection Analyzer (T1133)
    
    Design intent:
        Detect signs of attackers using external remote services for initial access and lateral movement
    
    Detection dimensions:
        1. SSH anomaly detection
           - Off-hours login (23:00-06:00)
           - authorized_keys anomalous modification
           - SSH configuration risks (PermitRootLogin, PasswordAuthentication)
           - Brute force attack traces
           
        2. RDP/VNC anomaly detection
           - xrdp/vncserver anomalous startup
           - Non-standard port listening
           - Unknown remote desktop processes
           
        3. Remote tunnel tool detection
           - ngrok/frp/reGeorg and other tunnel tools
           - Reverse SSH tunnels
           - Hidden proxy tools
           
        4. Other remote services
           - TeamViewer/AnyDesk unauthorized installation
           - Suspicious remote control processes
    
    ATT&CK mapping:
        - T1133 - External Remote Services
        - T1021 - Remote Services
        - T1021.004 - SSH
        - T1021.007 - Cloud Services
        - T1563.002 - RDP Session Hijacking
        - T1572 - Protocol Tunneling
    
    False positive mitigation:
        - Distinguish operations automation tools (Ansible, etc.)
        - Consider container environment specifics
        - Combine with time pattern analysis
    """
    name = 'remote_service_analyzer'
    timeout = 45
    required_collectors = ['process', 'network', 'log', 'user']
    ABNORMAL_HOURS = set(range(0, 7)) | set(range(23, 24))
    SUSPICIOUS_KEY_PATTERNS = [re.compile('attacker', re.IGNORECASE), re.compile('backdoor', re.IGNORECASE), re.compile('hack', re.IGNORECASE), re.compile('exploit', re.IGNORECASE), re.compile('reverse', re.IGNORECASE), re.compile('c2', re.IGNORECASE)]
    AGENT_FORWARDING_PATTERNS = [(re.compile('\\bSSH_AUTH_SOCK\\b', re.IGNORECASE), 'SSH agent socket environment'), (re.compile('\\bssh-agent\\s+-[sL]\\b', re.IGNORECASE), 'SSH agent with listening mode'), (re.compile('\\bssh\\s+.*-A\\b', re.IGNORECASE), 'SSH with agent forwarding enabled'), (re.compile('/tmp/ssh-.*/agent\\.\\d+', re.IGNORECASE), 'SSH agent socket path')]
    KEY_INJECTION_INDICATORS = [(re.compile('\\bauthorized_keys\\b.*\\b(newly|added|modified)\\b', re.IGNORECASE), 'Authorized keys file modification'), (re.compile('echo\\s+.*>>\\s*.*authorized_keys', re.IGNORECASE), 'Direct append to authorized_keys'), (re.compile('cat\\s+.*\\.pub\\s*>>\\s*.*authorized_keys', re.IGNORECASE), 'Public key append to authorized_keys'), (re.compile('ssh-keygen\\s+.*-f\\s+.*authorized_keys', re.IGNORECASE), 'Key generation targeting authorized_keys')]
    SSH_RISK_CONFIGS = [('PermitRootLogin', 'permit_root_login', 'yes', Severity.HIGH, '允许 root 直接登录'), ('PasswordAuthentication', 'password_authentication', 'yes', Severity.MEDIUM, '允许密码认证'), ('AllowTcpForwarding', 'allow_tcp_forwarding', 'yes', Severity.MEDIUM, '允许 TCP 转发'), ('GatewayPorts', 'gateway_ports', 'yes', Severity.HIGH, '允许网关端口')]
    TUNNEL_TOOLS = {'ngrok': ('ngrok 隧道工具', Severity.HIGH, 'T1572'), 'frpc': ('frp 客户端', Severity.HIGH, 'T1572'), 'frps': ('frp 服务端', Severity.HIGH, 'T1572'), 'regeorg': ('reGeorg 隧道', Severity.CRITICAL, 'T1572'), 'nps': ('nps 代理', Severity.HIGH, 'T1572'), 'npc': ('nps 客户端', Severity.HIGH, 'T1572'), 'chisel': ('chisel 隧道', Severity.HIGH, 'T1572'), 'gost': ('gost 代理', Severity.HIGH, 'T1572'), 'earthworm': ('ew 隧道', Severity.HIGH, 'T1572'), 'lcx': ('lcx 转发', Severity.HIGH, 'T1572'), 'htran': ('htran 传输', Severity.HIGH, 'T1572')}
    REMOTE_CONTROL_TOOLS = {'teamviewer': ('TeamViewer 远控', Severity.MEDIUM, 'T1021'), 'anydesk': ('AnyDesk 远控', Severity.MEDIUM, 'T1021'), 'rustdesk': ('RustDesk 远控', Severity.MEDIUM, 'T1021'), 'xrdp': ('xrdp RDP 服务', Severity.MEDIUM, 'T1021.007'), 'vncserver': ('VNC 服务', Severity.MEDIUM, 'T1021'), 'tightvnc': ('TightVNC 服务', Severity.MEDIUM, 'T1021')}
    SSH_TUNNEL_PORTS = {22, 2222, 22222}

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Analyze remote service anomalies
        
        Args:
            collected_data: Collected data dictionary
            
        Returns:
            evidences: Evidence list sorted by severity
        """
        evidences = []
        process_data = self._get_data_safe(collected_data, 'process')
        network_data = self._get_data_safe(collected_data, 'network')
        log_data = self._get_data_safe(collected_data, 'log')
        user_data = self._get_data_safe(collected_data, 'user')
        filesystem_data = self._get_data_safe(collected_data, 'filesystem')
        if log_data:
            evidences.extend(self._check_ssh_brute_force(log_data))
            evidences.extend(self._check_abnormal_login_time(log_data))
        if user_data:
            evidences.extend(self._check_ssh_backdoor_keys(user_data))
            evidences.extend(self._check_ssh_config_risks(user_data))
        if process_data:
            evidences.extend(self._check_tunnel_tools(process_data))
            evidences.extend(self._check_remote_control_tools(process_data))
            evidences.extend(self._check_ssh_tunnel_processes(process_data))
            evidences.extend(self._check_ssh_agent_forwarding(process_data))
        if network_data:
            evidences.extend(self._check_rdp_vnc_listeners(network_data))
            evidences.extend(self._check_port_tunneling(process_data, network_data))
        if log_data and filesystem_data:
            evidences.extend(self._check_ssh_key_injection(log_data, filesystem_data))
        return sorted(evidences, key=lambda e: e.severity.score, reverse=True)

    def _check_ssh_brute_force(self, log_data: dict) -> List[Evidence]:
        """Detect SSH brute force traces
        
        Uses LogCollector pre-parsed failed_logins data
        """
        evidences = []
        auth_log = log_data.get('auth_log', {})
        if not isinstance(auth_log, dict):
            return evidences
        failed_logins = auth_log.get('failed_logins', [])
        if not failed_logins:
            return evidences
        ip_counts: Dict[str, int] = {}
        for entry in failed_logins:
            if not isinstance(entry, dict):
                continue
            ip_hash = entry.get('source_ip_hash', '')
            if ip_hash:
                ip_counts[ip_hash] = ip_counts.get(ip_hash, 0) + 1
        for ip_hash, count in ip_counts.items():
            if count >= 5:
                evidences.append(self._create_evidence(severity=Severity.HIGH, attack_id='T1110', title=f'SSH 暴力破解痕迹：{ip_hash[:16]}', description=f'检测到来自同一来源的 {count} 次 SSH 登录失败尝试', confidence=0.85, raw_data={'failed_count': count, 'source_ip_hash': ip_hash}, remediation='配置 fail2ban、使用密钥认证、限制登录来源 IP', evidence_details=EvidenceDetail(service_type='ssh', credential_type='password'), remediation_commands=[
                        "Block brute force source IPs and enforce fail2ban",
                        "Audit SSH authorized_keys and remove unauthorized entries",
                        "Enforce key-based authentication and disable password auth",
                        "Review SSH configuration and disable root login"
                    ]))
        return evidences

    def _check_abnormal_login_time(self, log_data: dict) -> List[Evidence]:
        """Detect off-hours logins
        
        Uses LogCollector pre-parsed successful_logins data
        Default off-hours: 23:00-06:00
        """
        evidences = []
        auth_log = log_data.get('auth_log', {})
        if not isinstance(auth_log, dict):
            return evidences
        successful_logins = auth_log.get('successful_logins', [])
        for login in successful_logins:
            if not isinstance(login, dict):
                continue
            timestamp = login.get('timestamp', '')
            if not timestamp:
                continue
            try:
                hour_match = re.search('(\\d{2}):\\d{2}:\\d{2}', timestamp)
                if hour_match:
                    hour = int(hour_match.group(1))
                    if hour in self.ABNORMAL_HOURS:
                        user_hash = login.get('user_hash', 'unknown')
                        method = login.get('method', 'unknown')
                        evidences.append(self._create_evidence(severity=Severity.MEDIUM, attack_id='T1078', title='非工作时间 SSH 登录', description=f'用户在非工作时间段 (23:00-06:00) 通过 {method} 登录系统', confidence=0.7, raw_data={'user_hash': user_hash, 'timestamp': timestamp, 'method': method}, remediation='确认是否为授权运维操作，考虑配置登录时间限制', evidence_details=EvidenceDetail(service_type='ssh', user=user_hash, start_time=timestamp), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'remote_service_analyzer'})))
            except (ValueError, AttributeError):
                continue
        return evidences

    def _check_ssh_backdoor_keys(self, user_data: dict) -> List[Evidence]:
        """Detect backdoor keys in SSH authorized_keys
        
        Uses UserCollector collected ssh_keys data
        """
        evidences = []
        ssh_key_entries = user_data.get('ssh_keys', [])
        for key_entry in ssh_key_entries:
            if not isinstance(key_entry, dict):
                continue
            key_path = key_entry.get('path', '')
            keys = key_entry.get('keys', [])
            for key_info in keys:
                if not isinstance(key_info, dict):
                    continue
                comment = key_info.get('comment', '')
                for pattern in self.SUSPICIOUS_KEY_PATTERNS:
                    if pattern.search(comment):
                        evidences.append(self._create_evidence(severity=Severity.CRITICAL, attack_id='T1098.004', title=f'SSH 后门密钥：{os.path.basename(key_path)}', description=f"文件 {key_path} 包含可疑注释关键词 '{pattern.pattern}'", confidence=0.9, raw_data={'path': key_path, 'comment': comment[:100]}, remediation='立即删除可疑密钥，调查入侵来源，轮换所有凭据', evidence_details=EvidenceDetail(file_path=key_path, credential_type='ssh_key'), remediation_commands=[
                        "Block brute force source IPs and enforce fail2ban",
                        "Audit SSH authorized_keys and remove unauthorized entries",
                        "Enforce key-based authentication and disable password auth",
                        "Review SSH configuration and disable root login"
                    ]))
                        break
        return evidences

    def _check_ssh_config_risks(self, user_data: dict) -> List[Evidence]:
        """Detect SSH configuration file risk items
        
        Uses UserCollector pre-parsed sshd_config data
        
        Environment-aware adjustments:
        - Development environment: Suppress SSH config warnings entirely
          (dev environments commonly need these settings)
        - Production environment: Full severity
        """
        evidences = []
        sshd_config = user_data.get('sshd_config', {})
        if not isinstance(sshd_config, dict):
            return evidences
        config_path = sshd_config.get('raw_path', '/etc/ssh/sshd_config')
        is_dev = is_development_env()
        if is_dev:
            return evidences
        for directive, config_key, bad_value, severity, desc in self.SSH_RISK_CONFIGS:
            actual_value = sshd_config.get(config_key, '')
            if actual_value.lower() == bad_value.lower():
                evidences.append(self._create_evidence(severity=severity, attack_id='T1021.004', title=f'SSH 配置风险：{directive}', description=f"{config_path}: {directive} 设置为 '{bad_value}' - {desc}", confidence=0.95, raw_data={'path': config_path, 'directive': directive, 'value': bad_value, 'environment': 'production'}, remediation=f'将 {directive} 设置为更安全的值或禁用', evidence_details=self._create_evidence_details(service_type='remote_service'), remediation_commands=generate_generic_remediation(attack_id='1021.004', context={'analyzer': 'remote_service_analyzer'})))
        return evidences

    def _check_tunnel_tools(self, process_data: dict) -> List[Evidence]:
        """Detect tunnel/proxy tools"""
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            comm = proc.get('comm', '').lower()
            cmdline = proc.get('cmdline', '').lower()
            pid = proc.get('pid', 0)
            for tool_name, (desc, severity, attack_id) in self.TUNNEL_TOOLS.items():
                if tool_name in comm or tool_name in cmdline:
                    evidences.append(self._create_evidence(severity=severity, attack_id=attack_id, title=f'检测到隧道工具：{tool_name}', description=f'进程 {comm} (PID {pid}) 是已知的隧道/代理工具：{desc}', confidence=0.9, raw_data={'pid': pid, 'comm': comm, 'cmdline': cmdline[:200]}, remediation='确认是否为授权工具，如未授权立即终止并调查', evidence_details=EvidenceDetail(pid=pid), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'remote_service'})))
                    break
        return evidences

    def _check_remote_control_tools(self, process_data: dict) -> List[Evidence]:
        """Detect remote control tools"""
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            comm = proc.get('comm', '').lower()
            cmdline = proc.get('cmdline', '').lower()
            pid = proc.get('pid', 0)
            for tool_name, (desc, severity, attack_id) in self.REMOTE_CONTROL_TOOLS.items():
                if tool_name in comm or tool_name in cmdline:
                    listening = proc.get('listening_ports', [])
                    evidences.append(self._create_evidence(severity=severity, attack_id=attack_id, title=f'检测到远控工具：{tool_name}', description=f'进程 {comm} (PID {pid}) 是远程控制工具：{desc}', confidence=0.85, raw_data={'pid': pid, 'comm': comm, 'cmdline': cmdline[:200], 'listening_ports': listening}, remediation='确认是否为授权安装，check监听端口和网络连接', evidence_details=EvidenceDetail(pid=pid,), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'remote_service'})))
                    break
        return evidences

    def _check_ssh_tunnel_processes(self, process_data: dict) -> List[Evidence]:
        """Detect SSH tunnel processes
        
        Detect -L/-R/-D parameters in ssh commands (local/remote/dynamic port forwarding)
        """
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            comm = proc.get('comm', '')
            cmdline = proc.get('cmdline', '')
            pid = proc.get('pid', 0)
            if comm == 'ssh' or 'ssh ' in cmdline:
                tunnel_match = re.search('\\s-[LRD]\\s+\\d+', cmdline)
                if tunnel_match:
                    evidences.append(self._create_evidence(severity=Severity.MEDIUM, attack_id='T1572', title=f'SSH 隧道进程：PID {pid}', description=f'进程执行 SSH 隧道/端口转发：{cmdline[:100]}', confidence=0.8, raw_data={'pid': pid, 'cmdline': cmdline[:200]}, remediation='确认隧道用途，check目标主机是否可信', evidence_details=EvidenceDetail(pid=pid), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'remote_service'})))
        return evidences

    def _check_rdp_vnc_listeners(self, network_data: dict) -> List[Evidence]:
        """Detect RDP/VNC listening ports"""
        evidences = []
        listeners = network_data.get('listeners', [])
        rdp_ports = {3389, 3390}
        vnc_ports = {5900, 5901, 5902, 5903, 5904, 5905}
        for listener in listeners:
            port = listener.get('local_port', 0)
            proto = listener.get('protocol', '').upper()
            process = listener.get('process', {})
            pid = process.get('pid', 0) if process else 0
            comm = process.get('comm', '') if process else ''
            if port in rdp_ports:
                if comm.lower() not in ['xrdp', 'rdesktop']:
                    evidences.append(self._create_evidence(severity=Severity.HIGH, attack_id='T1021.007', title=f'可疑 RDP 监听：端口 {port}', description=f'进程 {comm} (PID {pid}) 在端口 {port} 监听 RDP 连接', confidence=0.75, raw_data={'port': port, 'pid': pid, 'comm': comm, 'protocol': proto}, remediation='确认是否为授权的远程桌面服务', evidence_details=EvidenceDetail(pid=pid,), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'remote_service'})))
            elif port in vnc_ports:
                if comm.lower() not in ['vncserver', 'Xvnc', 'tightvnc']:
                    evidences.append(self._create_evidence(severity=Severity.HIGH, attack_id='T1021', title=f'可疑 VNC 监听：端口 {port}', description=f'进程 {comm} (PID {pid}) 在端口 {port} 监听 VNC 连接', confidence=0.75, raw_data={'port': port, 'pid': pid, 'comm': comm, 'protocol': proto}, remediation='确认是否为授权的 VNC 服务', evidence_details=EvidenceDetail(pid=pid,), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'remote_service'})))
        return evidences

    def _check_ssh_agent_forwarding(self, process_data: dict) -> List[Evidence]:
        """Detect SSH agent forwarding abuse
        
        ATT&CK: T1021.004 - SSH, T1572 - Protocol Tunneling
        """
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            pid = proc.get('pid', 0)
            comm = proc.get('comm', '')
            for pattern, description in self.AGENT_FORWARDING_PATTERNS:
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(severity=Severity.MEDIUM, attack_id='T1021.004', title=f'SSH Agent Forwarding Detected: PID {pid}', description=f'Process {comm} shows agent forwarding indicator: {description}', confidence=0.65, raw_data={'pid': pid, 'comm': comm, 'cmdline': cmdline[:200], 'indicator': description}, remediation='Verify if agent forwarding is authorized. Check SSH_AUTH_SOCK environment variable usage.', evidence_details=EvidenceDetail(pid=pid,), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'remote_service'})))
                    break
        return evidences

    def _check_ssh_key_injection(self, log_data: dict, filesystem_data: dict) -> List[Evidence]:
        """Detect SSH key injection attempts
        
        ATT&CK: T1098.004 - Account Manipation: SSH Authorized Keys
        """
        evidences = []
        auth_log = log_data.get('auth_log', {})
        if isinstance(auth_log, dict):
            messages = auth_log.get('messages', [])
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                message_text = (msg.get('message') or '').lower()
                timestamp = msg.get('timestamp', '')
                for pattern, description in self.KEY_INJECTION_INDICATORS:
                    if pattern.search(message_text):
                        evidences.append(self._create_evidence(severity=Severity.HIGH, attack_id='T1098.004', title='SSH Key Injection Attempt', description=f'Log entry indicates {description}: {message_text[:100]}', confidence=0.75, raw_data={'timestamp': timestamp, 'log_message': message_text[:200], 'indicator': description}, remediation='Review authorized_keys files immediately. Remove unauthorized keys. Audit recent login activity.', evidence_details=EvidenceDetail(credential_type='ssh_key', start_time=timestamp), remediation_commands=[
                        "Block brute force source IPs and enforce fail2ban",
                        "Audit SSH authorized_keys and remove unauthorized entries",
                        "Enforce key-based authentication and disable password auth",
                        "Review SSH configuration and disable root login"
                    ]))
                        break
        files = filesystem_data.get('recent_files', [])
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            filepath = file_info.get('path', '')
            if 'authorized_keys' in filepath:
                evidences.append(self._create_evidence(severity=Severity.MEDIUM, attack_id='T1098.004', title=f'Authorized Keys File Accessed: {os.path.basename(filepath)}', description=f'Recent access to SSH authorized_keys file: {filepath}', confidence=0.6, raw_data={'path': filepath, 'file_info': file_info}, remediation='Verify authorized_keys content matches expected keys. Remove any unrecognized entries.', evidence_details=EvidenceDetail(file_path=filepath, credential_type='ssh_key'), remediation_commands=[
                        "Block brute force source IPs and enforce fail2ban",
                        "Audit SSH authorized_keys and remove unauthorized entries",
                        "Enforce key-based authentication and disable password auth",
                        "Review SSH configuration and disable root login"
                    ]))
        return evidences

    def _check_port_tunneling(self, process_data: dict, network_data: dict) -> List[Evidence]:
        """Detect port tunneling for lateral movement
        
        ATT&CK: T1572 - Protocol Tunneling
        """
        evidences = []
        tunnel_ports = {8080, 8443, 9000, 9999, 1080, 10800, 4444, 5555, 6666, 7777}
        listeners = network_data.get('listeners', [])
        for listener in listeners:
            port = listener.get('local_port', 0)
            process = listener.get('process', {})
            pid = process.get('pid', 0) if process else 0
            comm = process.get('comm', '') if process else ''
            if port in tunnel_ports and comm.lower() not in ['java', 'node', 'python', 'nginx']:
                evidences.append(self._create_evidence(severity=Severity.LOW, attack_id='T1572', title=f'Suspicious Port Listening: {port}', description=f'Process {comm} (PID {pid}) listening on non-standard port {port} (potential tunnel endpoint)', confidence=0.4, raw_data={'port': port, 'pid': pid, 'comm': comm}, remediation='Investigate process purpose. Check network connections for tunneling patterns.', evidence_details=EvidenceDetail(pid=pid,), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'remote_service'})))
        return evidences

    def _create_evidence(self, severity: Severity, attack_id: str, title: str, description: str, confidence: float, raw_data: dict, remediation: str, evidence_details=None, remediation_commands=None) -> Evidence:
        """Create evidence object"""
        return Evidence(id=str(uuid.uuid4())[:8], module=self.name, title=title, description=description, severity=severity, confidence=confidence, attack_id=attack_id, attack_tactic='Initial Access / Lateral Movement', source_path='remote_service_analyzer', timestamp=datetime.now(timezone.utc).isoformat(), raw_data=raw_data, remediation=remediation, evidence_details=evidence_details, remediation_commands=remediation_commands or [])