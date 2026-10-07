"""Process Tree Anomaly Detection Analyzer"""
import os
from typing import List, Dict
from collections import defaultdict
from ..reporter.evidence import Evidence, Severity
from .base import BaseAnalyzer
from ..utils.remediation_generator import generate_generic_remediation
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

class ProcessTreeAnalyzer(BaseAnalyzer):
    """Analyze process tree for anomalous parent-child relationships and execution patterns"""
    name = 'process_tree_analyzer'
    timeout = 30
    required_collectors = ['process']
    estimated_time = 3.0
    analyzer_type = BaseAnalyzer.CRITICAL
    ANOMALOUS_PATTERNS = {'web_server_shell': {'parents': ['nginx', 'apache2', 'httpd', 'lighttpd', 'caddy'], 'children': ['bash', 'sh', 'zsh', 'dash', 'python', 'perl', 'ruby', 'php'], 'description': 'Web server spawning shell interpreter', 'severity': Severity.CRITICAL, 'attack_id': 'T1059.004', 'attack_tactic': 'Execution'}, 'orphan_suspicious': {'parent_pid': 1, 'suspicious_children': ['nc', 'ncat', 'netcat', 'socat', 'meterpreter', 'reverse'], 'description': 'Orphan process with suspicious command under init', 'severity': Severity.HIGH, 'attack_id': 'T1564.001', 'attack_tactic': 'Defense Evasion'}, 'deleted_binary': {'description': 'Process running from deleted binary', 'severity': Severity.CRITICAL, 'attack_id': 'T1070.004', 'attack_tactic': 'Indicator Removal'}, 'privilege_escalation': {'pattern': 'user_process -> sudo -> root_shell', 'description': 'Potential unauthorized privilege escalation chain', 'severity': Severity.CRITICAL, 'attack_id': 'T1548.003', 'attack_tactic': 'Privilege Escalation'}, 'lateral_movement': {'parents': ['sshd'], 'children': ['nc', 'ncat', 'socat', 'curl', 'wget'], 'description': 'SSH session spawning network tools (potential lateral movement)', 'severity': Severity.HIGH, 'attack_id': 'T1021.004', 'attack_tactic': 'Lateral Movement'}}
    CONTAINER_RUNTIME_WHITELIST = {'containerd-shim', 'containerd-shim-runc-v1', 'containerd-shim-runc-v2', 'runc', 'runsc', 'crun', 'dockerd', 'docker-proxy', 'containerd', 'crio', 'conmon'}
    CLOUD_AGENT_PATHS = ['/home/staragent/plugins/', '/usr/local/cloudmonitor/', '/usr/local/aegis/', '/usr/local/assist-daemon/', '/var/lib/cloud/', '/opt/cloud/', '/usr/local/argus/', '/usr/local/tamoor/']
    LEGITIMATE_INIT_CHILDREN = {'systemd', 'init', 'upstart', 'openrc', 'runit', 'cron', 'crond', 'atd', 'anacron', 'rsyslogd', 'syslogd', 'syslog-ng', 'journald', 'dbus-daemon', 'dbus-broker', 'NetworkManager', 'networkd', 'wpa_supplicant', 'dhclient', 'docker', 'dockerd', 'containerd', 'crio', 'kubelet', 'flanneld', 'containerd-shim', 'containerd-shim-runc-v1', 'containerd-shim-runc-v2', 'runc', 'runsc', 'crun', 'conmon', 'supervisord', 's6-svscan', 'runit', 'rpcbind', 'portmap', 'rpc.statd', 'rpc.idmapd', 'rpc.mountd', 'rpc.rquotad', 'rpc.nfsd', 'rpc.lockd', 'rpciod', 'nfsd', 'mountd', 'statd', 'idmapd', 'gssd', 'svcgssd', 'lockd', 'nfsiod', 'nfsdcld', 'sshd', 'dropbear', 'nginx', 'apache2', 'httpd', 'lighttpd', 'caddy', 'openlitespeed', 'mysqld', 'mariadbd', 'postgres', 'postgresql', 'mongod', 'mongos', 'redis-server', 'redis-sentinel', 'memcached', 'couchdb', 'influxd', 'rabbitmq-server', 'kafka', 'zookeeper', 'activemq', 'java', 'node', 'nodejs', 'python3', 'python2', 'ruby', 'php-fpm', 'gunicorn', 'uwsgi', 'pm2', 'forever', 'consul', 'vault', 'nomad', 'etcd', 'etcdctl', 'prometheus', 'grafana', 'alertmanager', 'pushgateway', 'telegraf', 'collectd', 'statsd', 'minio', 'glusterd', 'ceph-osd', 'ceph-mon', 'haproxy', 'traefik', 'envoy', 'pound', 'node_exporter', 'cadvisor', 'blackbox_exporter', 'cloud-init', 'cloud-final', 'amazon-ssm-agent', 'unattended-upgrades', 'update-notifier', 'postfix', 'sendmail', 'dovecot', 'exim4', 'named', 'dnsmasq', 'dhcpd', 'kea-dhcp4', 'ntpd', 'chronyd', 'timesyncd', 'fail2ban-server', 'psad', 'fwsnort', 'restic', 'borg', 'rsync', 'bacula-fd', 'polkitd', 'udisksd', 'accounts-daemon', 'thermald', 'irqbalance', 'multipathd', 'lvmetad', 'lvm2-lvmetad', 'smartd', 'hddtemp', 'lm_sensors', 'cupsd', 'avahi-daemon', 'bluetoothd', 'ModemManager', 'firewalld', 'ufw', 'tuned', 'ksmtuned', 'ksmd', 'auditd', 'audispd', 'login', 'agetty', 'getty', 'screen', 'tmux', 'bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'dfget', 'dfdaemon', 'dragonfly', 'nydus', 'bittorrent', 'transmission', 'aria2c'}
    SYSTEM_BINARY_PATHS = {'/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin', '/usr/local/sbin'}
    DEV_ENVIRONMENT_CHAINS = {'qodercli': {'dev.sh', 'build.sh', 'test.sh', 'run.sh', 'qoder'}, 'qoder': {'dev.sh', 'build.sh', 'test.sh', 'run.sh'}, 'claude': {'run.sh', 'execute.sh', 'build.sh', 'claude'}, 'cursor': {'build.sh', 'dev.sh', 'start.sh', 'cursor'}, 'code': {'dev.sh', 'build.sh', 'test.sh'}, 'vscode': {'code', 'extension'}, 'idea': {'idea', 'idea64'}, 'pycharm': {'pycharm', 'pycharm64'}, 'git': {'git', 'git-annex'}, 'python3': {'setup.py', 'manage.py', 'pytest', 'pip'}, 'node': {'package.json', 'webpack', 'babel', 'eslint'}}
    DEPTH_CONFIG = {'default_threshold': 12, 'dev_threshold': 20, 'server_threshold': 10, 'min_interpreters_for_alert': 4, 'interpreters': {'python', 'perl', 'ruby', 'php', 'bash', 'sh', 'zsh', 'dash', 'ksh'}, 'suspicious_in_deep_chain': {'nc', 'ncat', 'netcat', 'socat', 'nmap', 'curl', 'wget', 'meterpreter', 'reverse', 'bind', 'shell', 'exploit'}}

    DEV_ENVIRONMENT_MARKERS = {'.git': 'git_repo', 'node_modules': 'node_project', 'package.json': 'node_project', 'requirements.txt': 'python_project', 'setup.py': 'python_project', 'pyproject.toml': 'python_project', 'Cargo.toml': 'rust_project', 'go.mod': 'go_project', 'pom.xml': 'java_project', 'build.gradle': 'java_project', 'CMakeLists.txt': 'cpp_project', 'Makefile': 'cpp_project', '.vscode': 'vscode_workspace', '.idea': 'jetbrains_workspace'}

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def _is_development_environment(self) -> bool:
        """Detect if current environment is a development environment.
        
        Checks multiple indicators:
        1. Filesystem markers (.git, node_modules, IDE config files)
        2. Environment variables (VIRTUAL_ENV, NODE_ENV, etc.)
        3. Running processes (IDEs, dev tools)
        """
        dev_score = 0
        
        # Check filesystem markers
        check_paths = ['/', '/data/work', '/home', '/opt', os.getcwd()]
        for base_path in check_paths:
            if not os.path.exists(base_path):
                continue
            try:
                for entry in os.listdir(base_path):
                    if entry in self.DEV_ENVIRONMENT_MARKERS:
                        dev_score += 1
                        if dev_score >= 2:
                            return True
            except OSError:
                continue
        
        # Check environment variables
        dev_env_vars = ['VIRTUAL_ENV', 'NODE_ENV', 'GOPATH', 'CARGO_HOME', 'JAVA_HOME']
        for env_var in dev_env_vars:
            if env_var in os.environ:
                dev_score += 1
                if dev_score >= 2:
                    return True
        
        # Check if running common dev tool processes
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f'/proc/{pid_dir}/comm', 'r', encoding='utf-8') as f:
                        comm = f.read().strip().lower()
                    if comm in ['qodercli', 'qoder', 'code', 'cursor', 'claude', 'node', 'npm', 'yarn', 'docker', 'python3', 'go']:
                        dev_score += 1
                        if dev_score >= 2:
                            return True
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    continue
        except OSError:
            pass
        
        return dev_score >= 2

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze process tree for anomalies"""
        evidences = []
        processes = self._get_data(collected_data, 'process')
        if not processes:
            _get_logger().warning(f'[{self.name}] No process data available')
            return evidences
        try:
            process_list = processes.get('processes', [])
            if not process_list:
                _get_logger().info(f'[{self.name}] Empty process list')
                return evidences
            process_map = self._build_process_map(process_list)
            process_tree = self._build_process_tree(process_map)
            for pid, proc_info in process_map.items():
                pattern_evidences = self._check_anomalous_patterns(pid, proc_info, process_map, process_tree)
                evidences.extend(pattern_evidences)
                deleted_evidences = self._check_deleted_binary(pid, proc_info)
                evidences.extend(deleted_evidences)
                orphan_evidences = self._check_orphan_processes(pid, proc_info, process_map)
                evidences.extend(orphan_evidences)
                depth_evidences = self._check_deep_process_chain(pid, proc_info, process_map)
                evidences.extend(depth_evidences)
            priv_esc_evidences = self._check_privilege_escalation_chains(process_map, process_tree)
            evidences.extend(priv_esc_evidences)
            if evidences:
                _get_logger().info(f'[{self.name}] Found {len(evidences)} anomalous process tree patterns')
            else:
                _get_logger().info(f'[{self.name}] No process tree anomalies detected')
        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().error(f'[{self.name}] Error during analysis: {e}', exc_info=True)
        return evidences

    def _build_process_map(self, process_list: List[Dict]) -> Dict[str, Dict]:
        """Build process map keyed by PID"""
        process_map = {}
        for proc in process_list:
            pid = str(proc.get('pid', ''))
            if pid:
                process_map[pid] = {'pid': pid, 'ppid': str(proc.get('ppid', '0')), 'name': proc.get('comm') or proc.get('name') or '', 'cmdline': proc.get('cmdline', ''), 'exe': proc.get('exe', ''), 'cwd': proc.get('cwd', ''), 'uid': proc.get('uid', -1), 'gid': proc.get('gid', -1), 'username': proc.get('username', '')}
        return process_map

    def _build_process_tree(self, process_map: Dict[str, Dict]) -> Dict[str, List[str]]:
        """Build parent-child relationship tree"""
        tree = defaultdict(list)
        for pid, info in process_map.items():
            ppid = info['ppid']
            if ppid in process_map:
                tree[ppid].append(pid)
        return dict(tree)

    def _check_anomalous_patterns(self, pid: str, proc_info: Dict, process_map: Dict[str, Dict], process_tree: Dict[str, List[str]]) -> List[Evidence]:
        """Check for known anomalous parent-child patterns"""
        evidences = []
        parent_pid = proc_info['ppid']
        if parent_pid not in process_map:
            return evidences
        parent_info = process_map[parent_pid]
        parent_name = os.path.basename(parent_info.get('name', '')).lower()
        child_name = os.path.basename(proc_info.get('name', '')).lower()
        child_cmdline = proc_info.get('cmdline', '').lower()
        for pattern_name, pattern_config in self.ANOMALOUS_PATTERNS.items():
            if pattern_name in ['deleted_binary', 'orphan_suspicious']:
                continue
            matched = False
            if 'parents' in pattern_config and 'children' in pattern_config:
                parent_match = any((p in parent_name for p in pattern_config['parents']))
                child_match = any((c in child_name or c in child_cmdline for c in pattern_config['children']))
                matched = parent_match and child_match
            if matched:
                evidence = self._create_evidence(title=f"Suspicious Process Tree: {pattern_config['description']}", description=f"Detected anomalous parent-child relationship:\n  Parent: {parent_info.get('name')} (PID: {parent_pid})\n  Child: {proc_info.get('name')} (PID: {pid})\n  Command: {proc_info.get('cmdline')}\n  Pattern: {pattern_name}", severity=pattern_config['severity'], confidence=0.85, attack_id=pattern_config['attack_id'], attack_tactic=pattern_config['attack_tactic'], source_path=f'/proc/{pid}', raw_data={'parent_pid': parent_pid, 'parent_name': parent_info.get('name'), 'child_pid': pid, 'child_name': proc_info.get('name'), 'child_cmdline': proc_info.get('cmdline'), 'pattern': pattern_name}, remediation='Investigate the process chain. If unauthorized, terminate the processes and identify the entry point. Review web server configurations to restrict shell access.', evidence_details=self._create_evidence_details(pid=int(pid) if pid.isdigit() else 0, cmdline=proc_info.get('cmdline', ''), executable=proc_info.get('exe', ''), parent_pid=int(parent_pid) if parent_pid.isdigit() else 0, user=proc_info.get('username', '')), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'process_tree_analyzer'}))
                evidences.append(evidence)
                _get_logger().warning(f"[{self.name}] Detected {pattern_name}: {parent_info.get('name')} -> {proc_info.get('name')}")
        return evidences

    def _check_deleted_binary(self, pid: str, proc_info: Dict) -> List[Evidence]:
        """Check if process is running from a deleted binary"""
        evidences = []
        exe_path = proc_info.get('exe', '')
        if not exe_path:
            return evidences
        try:
            if '(deleted)' in exe_path:
                cmdline = proc_info.get('cmdline', 'N/A')
                evidence = self._create_evidence(title='Process Running from Deleted Binary', description=f"Process is executing from a deleted binary file:\n  PID: {pid}\n  Process: {proc_info.get('name')}\n  Executable: {exe_path}\n  Command: {cmdline}\n  User: {proc_info.get('username', 'N/A')}", severity=Severity.CRITICAL, confidence=0.9, attack_id='T1070.004', attack_tactic='Indicator Removal', source_path=f'/proc/{pid}/exe', raw_data={'pid': pid, 'name': proc_info.get('name'), 'exe': exe_path, 'cmdline': cmdline}, remediation='This often indicates malware attempting to hide. Capture memory dump for forensics, then terminate the process. Investigate how the binary was executed and check for persistence mechanisms.', evidence_details=self._create_evidence_details(pid=int(pid) if pid.isdigit() else 0, cmdline=cmdline, executable=exe_path, user=proc_info.get('username', '')), remediation_commands=generate_generic_remediation(attack_id='1070.004', context={'analyzer': 'process_tree_analyzer'}))
                evidences.append(evidence)
        except OSError:
            pass
        return evidences

    def _is_container_runtime(self, proc: Dict) -> bool:
        """Check if process is a container runtime component."""
        cmdline = proc.get('cmdline', '').lower()
        exe = proc.get('exe', '').lower()
        name = proc.get('name', '').lower()
        for binary in self.CONTAINER_RUNTIME_WHITELIST:
            if binary in name or binary in cmdline or binary in exe:
                return True
        return False

    def _is_cloud_agent_plugin(self, proc: Dict) -> bool:
        """Check if process is a cloud agent plugin."""
        cmdline = proc.get('cmdline', '').lower()
        exe = proc.get('exe', '').lower()
        cwd = proc.get('cwd', '').lower()
        for agent_path in self.CLOUD_AGENT_PATHS:
            agent_path_lower = agent_path.lower()
            if agent_path_lower in exe or agent_path_lower in cmdline or agent_path_lower in cwd:
                return True
        return False

    def _is_scanner_process(self, pid: str, proc_info: Dict, process_map: Dict) -> bool:
        """Check if process is the scanner itself or its child processes."""
        current_pid = str(os.getpid())
        if pid == current_pid:
            return True
        if proc_info.get('ppid') == current_pid:
            return True
        ancestors = self._get_ancestors(pid, process_map)
        for ancestor in ancestors:
            if ancestor['pid'] == current_pid:
                return True
        cmdline = proc_info.get('cmdline', '').lower()
        scanner_indicators = ['sec-userspace', 'scripts.main', 'process_tree_analyzer']
        if any((indicator in cmdline for indicator in scanner_indicators)):
            return True
        return False

    def _check_orphan_processes(self, pid: str, proc_info: Dict, process_map: Dict[str, Dict]) -> List[Evidence]:
        """Check for suspicious orphan processes (re-parented to init/PID 1)"""
        evidences = []
        parent_pid = proc_info.get('ppid', '0')
        if parent_pid != '1':
            return evidences
        if self._is_scanner_process(pid, proc_info, process_map):
            _get_logger().debug(f"[{self.name}] Skipping scanner orphan process: {proc_info.get('name')} (PID: {pid})")
            return evidences
        if self._is_container_runtime(proc_info):
            _get_logger().debug(f"[{self.name}] Skipping container runtime orphan process: {proc_info.get('name')} (PID: {pid})")
            return evidences
        if self._is_cloud_agent_plugin(proc_info):
            _get_logger().debug(f"[{self.name}] Skipping cloud agent plugin orphan process: {proc_info.get('name')} (PID: {pid})")
            return evidences
        proc_name = os.path.basename(proc_info.get('name', '')).lower()
        cmdline = proc_info.get('cmdline', '').lower()
        exe_path = proc_info.get('exe', '')
        if proc_name in self.LEGITIMATE_INIT_CHILDREN:
            return evidences
        if exe_path and '(deleted)' not in exe_path:
            real_exe_path = os.path.realpath(exe_path.split(' ')[0])
            if any((real_exe_path.startswith(sys_path) for sys_path in self.SYSTEM_BINARY_PATHS)):
                _get_logger().debug(f'[{self.name}] Orphan process from system path (reducing confidence): {proc_name} at {real_exe_path}')
        suspicious_indicators = ['nc', 'ncat', 'netcat', 'socat', 'meterpreter', 'reverse', 'bind', 'shell', 'backdoor', 'rootkit', 'exploit']
        is_suspicious = any((indicator in proc_name or indicator in cmdline for indicator in suspicious_indicators))
        if is_suspicious:
            confidence = 0.75
            if exe_path and '(deleted)' not in exe_path:
                real_exe_path = os.path.realpath(exe_path.split(' ')[0])
                if any((real_exe_path.startswith(sys_path) for sys_path in self.SYSTEM_BINARY_PATHS)):
                    confidence = 0.5
            evidence = self._create_evidence(title='Suspicious Orphan Process Under Init', description=f"Potentially malicious orphan process re-parented to init:\n  PID: {pid}\n  Process: {proc_info.get('name')}\n  Command: {proc_info.get('cmdline')}\n  Executable: {exe_path}\n  User: {proc_info.get('username', 'N/A')}\n  Working Dir: {proc_info.get('cwd', 'N/A')}", severity=Severity.HIGH, confidence=confidence, attack_id='T1564.001', attack_tactic='Defense Evasion', source_path=f'/proc/{pid}', raw_data={'pid': pid, 'name': proc_info.get('name'), 'cmdline': proc_info.get('cmdline'), 'exe': exe_path, 'ppid': parent_pid}, remediation='Orphan processes may indicate parent was killed to hide activity. Investigate the process origin and check for related IOCs. Consider terminating if unauthorized.', evidence_details=self._create_evidence_details(pid=int(pid) if pid.isdigit() else 0, cmdline=proc_info.get('cmdline', ''), executable=exe_path, parent_pid=1, user=proc_info.get('username', '')), remediation_commands=generate_generic_remediation(attack_id='1564.001', context={'analyzer': 'process_tree_analyzer'}))
            evidences.append(evidence)
        return evidences

    def _check_privilege_escalation_chains(self, process_map: Dict[str, Dict], process_tree: Dict[str, List[str]]) -> List[Evidence]:
        """Detect potential privilege escalation chains"""
        evidences = []
        for pid, children in process_tree.items():
            if pid not in process_map:
                continue
            parent_info = process_map[pid]
            parent_name = os.path.basename(parent_info.get('name', '')).lower()
            parent_uid = parent_info.get('uid', -1)
            if parent_name not in ['sudo', 'su']:
                continue
            for child_pid in children:
                if child_pid not in process_map:
                    continue
                child_info = process_map[child_pid]
                child_name = os.path.basename(child_info.get('name', '')).lower()
                child_uid = child_info.get('uid', -1)
                if child_name in ['bash', 'sh', 'zsh', 'root'] and child_uid == 0 and (parent_uid != 0):
                    grandparent_pid = parent_info.get('ppid', '0')
                    grandparent_info = process_map.get(grandparent_pid, {})
                    grandparent_name = grandparent_info.get('name', 'unknown')
                    evidence = self._create_evidence(title='Potential Unauthorized Privilege Escalation', description=f"Detected privilege escalation chain:\n  Grandparent: {grandparent_name} (PID: {grandparent_pid})\n  Parent: {parent_info.get('name')} (PID: {pid}, UID: {parent_uid})\n  Child: {child_info.get('name')} (PID: {child_pid}, UID: {child_uid})\n  Command: {child_info.get('cmdline')}", severity=Severity.CRITICAL, confidence=0.8, attack_id='T1548.003', attack_tactic='Privilege Escalation', source_path=f'/proc/{child_pid}', raw_data={'grandparent_pid': grandparent_pid, 'grandparent_name': grandparent_name, 'sudo_pid': pid, 'shell_pid': child_pid, 'shell_cmdline': child_info.get('cmdline')}, remediation='Verify if this privilege escalation is authorized. Check sudo logs (/var/log/auth.log) for authentication details. If unauthorized, investigate the originating process and user.', evidence_details=self._create_evidence_details(pid=int(child_pid) if child_pid.isdigit() else 0, cmdline=child_info.get('cmdline', ''), executable=child_info.get('exe', ''), parent_pid=int(pid) if pid.isdigit() else 0, user=child_info.get('username', '')), remediation_commands=generate_generic_remediation(attack_id='1548.003', context={'analyzer': 'process_tree_analyzer'}))
                    evidences.append(evidence)
        return evidences

    def _check_deep_process_chain(self, pid: str, proc_info: Dict, process_map: Dict[str, Dict]) -> List[Evidence]:
        """Check for unusually deep process chains with context awareness"""
        evidences = []
        ancestors = self._get_ancestors(pid, process_map)
        chain_comms = [node['comm'].lower() for node in ancestors]
        chain_names = [os.path.basename(node.get('exe', node['comm'])).lower() for node in ancestors]
        env_type = self._detect_environment_type(chain_comms, chain_names)
        threshold = self._get_threshold_for_environment(env_type)
        if len(ancestors) < threshold:
            return evidences
        if self._is_dev_environment_chain(chain_comms, chain_names):
            _get_logger().debug(f"[{self.name}] Skipping dev environment chain (depth={len(ancestors)}): {' -> '.join(chain_comms)}")
            return evidences
        if self._is_ci_cd_environment(chain_comms, chain_names):
            _get_logger().debug(f"[{self.name}] Skipping CI/CD environment chain (depth={len(ancestors)}): {' -> '.join(chain_comms)}")
            return evidences
        interpreter_count = sum((1 for comm in chain_comms if comm in self.DEPTH_CONFIG['interpreters']))
        has_suspicious = any((cmd in comm or cmd in ' '.join(chain_names) for cmd in self.DEPTH_CONFIG['suspicious_in_deep_chain'] for comm in chain_comms))
        should_alert = interpreter_count >= self.DEPTH_CONFIG['min_interpreters_for_alert'] or has_suspicious or len(ancestors) >= threshold + 4
        if not should_alert:
            _get_logger().debug(f"[{self.name}] Deep chain but no suspicious indicators (depth={len(ancestors)}, threshold={threshold}, env={env_type}, interpreters={interpreter_count}): {' -> '.join(chain_comms)}")
            return evidences
        severity = Severity.MEDIUM
        confidence = 0.65
        if has_suspicious:
            severity = Severity.HIGH
            confidence = 0.85
        elif len(ancestors) >= threshold + 6:
            severity = Severity.HIGH
            confidence = 0.75
        elif interpreter_count >= 5:
            confidence = 0.75
        evidence = self._create_evidence(title='Unusually Deep Process Chain', description=f"Detected abnormally deep process execution chain:\n  Environment: {env_type}\n  Depth: {len(ancestors)} levels (threshold: {threshold})\n  Interpreters in chain: {interpreter_count}\n  Chain: {' -> '.join(chain_comms[-15:])}\n  Suspicious indicators: {('Yes' if has_suspicious else 'No')}\n  Target process: {proc_info.get('name')} (PID: {pid})", severity=severity, confidence=confidence, attack_id='T1059', attack_tactic='Execution', source_path=f'/proc/{pid}', raw_data={'pid': pid, 'depth': len(ancestors), 'threshold': threshold, 'environment': env_type, 'chain': chain_comms, 'interpreter_count': interpreter_count, 'has_suspicious': has_suspicious}, remediation='Deep process chains may indicate exploit frameworks or multi-stage attacks. Investigate the full chain and verify if all processes are legitimate. Check for code injection or command execution vulnerabilities.', evidence_details=self._create_evidence_details(pid=int(pid) if pid.isdigit() else 0, cmdline=proc_info.get('cmdline', ''), executable=proc_info.get('exe', ''), user=proc_info.get('username', '')), remediation_commands=generate_generic_remediation(attack_id='1059', context={'analyzer': 'process_tree_analyzer'}))
        evidences.append(evidence)
        _get_logger().warning(f"[{self.name}] Detected deep process chain (depth={len(ancestors)}, threshold={threshold}, env={env_type}, interpreters={interpreter_count}): {proc_info.get('name')}")
        return evidences

    def _detect_environment_type(self, chain_comms: List[str], chain_names: List[str]) -> str:
        """Detect the environment type from process chain"""
        all_items = set(chain_comms + chain_names)
        dev_indicators = {'qodercli', 'qoder', 'claude', 'cursor', 'code', 'codium', 'vscodium', 'vscode', 'idea', 'pycharm', 'webstorm', 'goland', 'clion', 'vim', 'nvim', 'emacs', 'nano', 'node', 'npm', 'yarn', 'pnpm', 'pip', 'python3', 'python2', 'git', 'docker', 'make', 'cmake', 'gcc', 'g++'}
        desktop_indicators = {'gnome', 'kde', 'xfce', 'lxde', 'mate', 'cinnamon', 'chrome', 'firefox', 'chromium', 'brave', 'edge', 'spotify', 'slack', 'discord', 'telegram', 'whatsapp'}
        dev_count = sum((1 for item in all_items if item in dev_indicators))
        desktop_count = sum((1 for item in all_items if item in desktop_indicators))
        if dev_count >= 2:
            return 'dev'
        elif desktop_count >= 2:
            return 'desktop'
        else:
            return 'server'

    def _get_threshold_for_environment(self, env_type: str) -> int:
        """Get appropriate threshold for environment type"""
        thresholds = {'dev': self.DEPTH_CONFIG['dev_threshold'], 'desktop': self.DEPTH_CONFIG['default_threshold'], 'server': self.DEPTH_CONFIG['server_threshold']}
        return thresholds.get(env_type, self.DEPTH_CONFIG['default_threshold'])

    def _get_ancestors(self, pid: str, process_map: Dict[str, Dict]) -> List[Dict]:
        """Get ancestor chain for a process"""
        ancestors = []
        current_pid = pid
        visited = set()
        while current_pid in process_map and current_pid != '0':
            if current_pid in visited:
                break
            visited.add(current_pid)
            proc = process_map[current_pid]
            ancestors.append({'pid': current_pid, 'ppid': proc.get('ppid', '0'), 'comm': os.path.basename(proc.get('name', '')).lower(), 'exe': proc.get('exe', ''), 'cmdline': proc.get('cmdline', '')})
            current_pid = proc.get('ppid', '0')
        ancestors.reverse()
        return ancestors

    def _is_dev_environment_chain(self, chain_comms: List[str], chain_names: List[str]) -> bool:
        """Check if chain matches known development environment patterns"""
        all_items = set(chain_comms + chain_names)
        for dev_tool, dev_scripts in self.DEV_ENVIRONMENT_CHAINS.items():
            if dev_tool in all_items:
                if any((script in all_items for script in dev_scripts)):
                    return True
        
        # Broader AI tool detection - any chain containing these tools is likely dev
        ai_tools = {'qodercli', 'qoder', 'claude', 'cursor', 'code', 'codium', 'vscodium', 'copilot'}
        if any((tool in all_items for tool in ai_tools)):
            return True
        
        # Broader dev tool detection
        dev_tools = {'node', 'npm', 'yarn', 'pnpm', 'python3', 'python2', 'pip', 'pip3', 'go', 'cargo', 'rustc', 'ruby', 'gem', 'java', 'javac', 'mvn', 'gradle', 'gcc', 'g++', 'cc', 'c++', 'make', 'cmake'}
        dev_count = sum((1 for item in all_items if item in dev_tools))
        if dev_count >= 2:
            return True
        
        # Check for shell script chains common in dev
        shell_scripts = {'sh', 'bash', 'zsh', 'dash'}
        script_indicators = {'.sh', '.py', '.js', '.ts', '.rb', '.go'}
        has_shell = any((item in shell_scripts for item in all_items))
        has_script = any((any(item.endswith(ext) for ext in script_indicators) for item in all_items))
        if has_shell and has_script:
            return True
        
        return False

    def _is_ci_cd_environment(self, chain_comms: List[str], chain_names: List[str]) -> bool:
        """Check if chain matches CI/CD pipeline patterns"""
        all_items = set(chain_comms + chain_names)
        ci_patterns = {'jenkins', 'gitlab-runner', 'github-actions', 'circleci', 'travis', 'bamboo', 'teamcity', 'azure-pipelines', 'drone', 'concourse', 'spinnaker', 'argo'}
        if any((pattern in all_items for pattern in ci_patterns)):
            return True
        ci_script_indicators = {'ci-build.sh', 'pipeline.sh', 'ci.sh', 'build-ci.sh'}
        if any((script in all_items for script in ci_script_indicators)):
            return True
        return False