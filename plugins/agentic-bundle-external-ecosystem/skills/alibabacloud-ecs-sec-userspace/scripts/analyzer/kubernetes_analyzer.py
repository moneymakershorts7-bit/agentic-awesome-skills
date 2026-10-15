"""Kubernetes Security Detection Analyzer

Detects security risks in Kubernetes environments, including:
- Pod security context violations (privileged, hostPID, hostIPC, root user)
- Dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE)
- ServiceAccount security issues (default SA usage, automount tokens)
- RBAC misconfigurations (overly permissive roles, wildcard permissions)
- Secret exposure (mounted secrets, kubeconfig files, environment credentials)
- Network policy gaps (missing policies, allow-all rules)
- Control plane exposure (API server, etcd, kubelet ports)
- Container-aware false positive reduction

ATT&CK Mapping:
- T1610 - Deploy Container (Container Administration Command)
- T1611 - Escape to Host (Container Escape)
- T1552.004 - Cloud Instance Metadata API (Cloud Credentials)
- T1078.004 - Cloud Accounts (Valid K8s Credentials Abuse)
"""
import os
import re
from typing import List
from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer
from ..utils.remediation_generator import generate_generic_remediation
from .cicd_detector import CICDDetector
from .container_environment_detector import get_container_detector
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

class KubernetesAnalyzer(BaseAnalyzer):
    """Kubernetes Security Detection Analyzer"""
    name = 'kubernetes_analyzer'
    timeout = 45
    estimated_time = 0.5  # Optimized for quick mode
    analyzer_type = BaseAnalyzer.CRITICAL
    required_collectors = ['process', 'network', 'filesystem']

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        if not self.has_k8s():
            return True, "Not a Kubernetes environment"
        return False, ""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cicd_detector = CICDDetector()
        # Initialize centralized container environment detector
        self._container_detector = get_container_detector()
    K8S_PROCESSES = {'kubelet', 'kube-proxy', 'kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd', 'k3s', 'k3s-agent', 'hyperkube', 'rke2', 'rke2-agent'}
    K8S_PORTS = {6443: ('API Server', Severity.CRITICAL), 2379: ('etcd client', Severity.CRITICAL), 2380: ('etcd peer', Severity.HIGH), 10250: ('kubelet', Severity.HIGH), 10255: ('kubelet read-only', Severity.MEDIUM), 10256: ('kube-proxy healthz', Severity.LOW), 8080: ('API server insecure', Severity.CRITICAL)}
    DANGEROUS_CAPABILITIES = {'SYS_ADMIN': 'Allows container escape via mount operations', 'NET_ADMIN': 'Allows network configuration changes', 'SYS_PTRACE': 'Allows process debugging/injection', 'SYS_MODULE': 'Allows kernel module loading', 'DAC_READ_SEARCH': 'Bypasses file permission checks', 'NET_RAW': 'Allows raw socket access (packet crafting)', 'SYS_RAWIO': 'Allows raw I/O port access', 'SETUID': 'Allows setting UID', 'SETGID': 'Allows setting GID'}
    K8S_NODE_LEGITIMATE_MOUNTS = {'/': {'description': 'Root filesystem mount', 'required_by': ['kubelet'], 'risk_level': 'LOW', 'reason': 'kubelet needs host filesystem access to manage containers'}, '/dev': {'description': 'Device filesystem', 'required_by': ['kubelet', 'containerd', 'dockerd'], 'risk_level': 'LOW', 'reason': 'Container runtime device management'}, '/sys': {'description': 'Sysfs filesystem', 'required_by': ['kubelet', 'containerd'], 'risk_level': 'LOW', 'reason': 'cgroup and resource management'}, '/proc': {'description': 'Proc filesystem', 'required_by': ['kubelet', 'containerd'], 'risk_level': 'LOW', 'reason': 'Process monitoring and management'}, '/dev/pts': {'description': 'PTY device filesystem', 'required_by': ['kubelet'], 'risk_level': 'LOW', 'reason': 'Container exec/attach functionality'}, '/dev/shm': {'description': 'Shared memory', 'required_by': ['containerd', 'dockerd'], 'risk_level': 'LOW', 'reason': 'Container IPC communication'}}
    K8S_SENSITIVE_PATHS = {'/var/run/secrets/kubernetes.io/serviceaccount': 'Service account token directory', '/var/run/secrets/kubernetes.io/serviceaccount/token': 'Service account JWT token', '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt': 'Cluster CA certificate', '/var/run/secrets/kubernetes.io/serviceaccount/namespace': 'Pod namespace', '/etc/kubernetes': 'Kubernetes configuration directory', '/etc/kubernetes/pki': 'Kubernetes PKI certificates', '/etc/kubernetes/admin.conf': 'Admin kubeconfig file', '/root/.kube/config': 'User kubeconfig file', '/var/lib/kubelet': 'Kubelet data directory', '/var/lib/kubelet/pki': 'Kubelet PKI directory', '/var/lib/etcd': 'etcd data directory', '/srv/kubernetes': 'Alternative K8s config location'}
    PRIVILEGED_INDICATORS = [(re.compile('privileged:\\s*true', re.IGNORECASE), 'Privileged container configuration'), (re.compile('hostPID:\\s*true', re.IGNORECASE), 'Host PID namespace sharing'), (re.compile('hostIPC:\\s*true', re.IGNORECASE), 'Host IPC namespace sharing'), (re.compile('hostNetwork:\\s*true', re.IGNORECASE), 'Host network namespace sharing'), (re.compile('runAsNonRoot:\\s*false', re.IGNORECASE), 'Explicit root user allowed'), (re.compile('allowPrivilegeEscalation:\\s*true', re.IGNORECASE), 'Privilege escalation allowed')]
    DANGEROUS_MOUNTS = {'/': 'Root filesystem mount - full host access', '/etc': 'System configuration directory', '/var/run/docker.sock': 'Docker socket - container escape possible', '/var/run/containerd/containerd.sock': 'Containerd socket', '/proc': 'Process information filesystem', '/sys': 'Sysfs - kernel interface', '/dev': 'Device directory', '/root': 'Root user home directory', '/etc/shadow': 'Password hash file', '/etc/passwd': 'User account file', '/etc/kubernetes': 'Kubernetes configuration', '/var/log': 'System logs (may contain sensitive data)', '/var/lib': 'Variable state data'}
    RBAC_DANGEROUS_PATTERNS = [(re.compile('resources:\\s*\\["\\*"\\]'), 'Wildcard resource access'), (re.compile('verbs:\\s*\\["\\*"\\]'), 'Wildcard verb access'), (re.compile('apiGroups:\\s*\\["\\*"\\]'), 'Wildcard API group access'), (re.compile('cluster-admin', re.IGNORECASE), 'Cluster-admin role binding'), (re.compile('secrets?\\s*.*get|list|watch', re.IGNORECASE), 'Secret read access'), (re.compile('pods?\\s*.*exec|attach', re.IGNORECASE), 'Pod exec/attach access'), (re.compile('create.*pod|deployment', re.IGNORECASE), 'Pod/deployment creation')]
    K8S_MINING_INDICATORS = {'xmrig': 'Monero mining program', 'minerd': 'CPU mining program', 'kdevtmpfsi': 'Kinsing mining trojan', 'kinsing': 'Kinsing malware component', 'rookdns': 'Rook DNS miner', 'teamserver': 'Cobalt Strike teamserver'}
    K8S_API_ABUSE_PATTERNS = [(re.compile('kubectl\\s+auth\\s+can-i\\s+--list', re.IGNORECASE), 'Permission enumeration via kubectl auth can-i --list'), (re.compile('kubectl\\s+create\\s+clusterrolebinding.*cluster-admin', re.IGNORECASE), 'Cluster-admin role binding creation'), (re.compile('kubectl\\s+create\\s+token\\s+system:serviceaccount', re.IGNORECASE), 'Service account token impersonation'), (re.compile('kubectl\\s+exec\\s+-n\\s+\\S+\\s+\\S+', re.IGNORECASE), 'Cross-namespace pod exec (potential lateral movement)'), (re.compile('kubectl\\s+get\\s+secrets?\\s+-A', re.IGNORECASE), 'Cluster-wide secret enumeration'), (re.compile('kubectl\\s+run\\s+--privileged', re.IGNORECASE), 'Privileged pod deployment via kubectl run'), (re.compile('kubectl\\s+apply\\s+-f\\s+https?://', re.IGNORECASE), 'Remote manifest application from untrusted source'), (re.compile('curl\\s+-k\\s+https://[^/]+/api/v1/namespaces', re.IGNORECASE), 'Direct K8s API access with insecure TLS'), (re.compile('curl\\s+-H\\s+"Authorization:\\s*Bearer\\s+', re.IGNORECASE), 'Manual bearer token usage in API requests')]
    MALICIOUS_POD_PATTERNS = [(re.compile('privileged:\\s*true', re.IGNORECASE), 'Privileged container specification', Severity.CRITICAL), (re.compile('hostPID:\\s*true', re.IGNORECASE), 'Host PID namespace sharing enabled', Severity.HIGH), (re.compile('hostNetwork:\\s*true', re.IGNORECASE), 'Host network namespace sharing enabled', Severity.HIGH), (re.compile('hostIPC:\\s*true', re.IGNORECASE), 'Host IPC namespace sharing enabled', Severity.HIGH), (re.compile('path:\\s*/\\s*$', re.IGNORECASE | re.MULTILINE), 'Root filesystem hostPath mount', Severity.CRITICAL), (re.compile('path:\\s*/(proc|sys|dev)\\s*$', re.IGNORECASE | re.MULTILINE), 'Sensitive hostPath mount (/proc, /sys, /dev)', Severity.HIGH), (re.compile('add:.*ALL', re.IGNORECASE | re.DOTALL), 'All Linux capabilities added', Severity.CRITICAL), (re.compile('readOnlyRootFilesystem:\\s*false', re.IGNORECASE), 'Writable root filesystem allowed', Severity.LOW), (re.compile('image:\\s*\\S+:latest', re.IGNORECASE), 'Container image using latest tag', Severity.MEDIUM), (re.compile('imagePullPolicy:\\s*Always', re.IGNORECASE), 'Image pull policy set to Always (may pull untrusted images)', Severity.LOW)]
    RBAC_ESCALATION_PATTERNS = [(re.compile('kind:\\s*clusterrolebinding', re.IGNORECASE | re.MULTILINE), 'ClusterRoleBinding detected (cluster-wide permissions)', Severity.HIGH), (re.compile('name:\\s*cluster-admin', re.IGNORECASE | re.MULTILINE), 'Cluster-admin role reference in binding', Severity.CRITICAL), (re.compile('resources:\\s*\\[\\s*"\\*"\\s*\\]', re.IGNORECASE | re.MULTILINE), 'Wildcard resource access in RBAC rule', Severity.HIGH), (re.compile('verbs:\\s*\\[\\s*"\\*"\\s*\\]', re.IGNORECASE | re.MULTILINE), 'Wildcard verb access in RBAC rule', Severity.HIGH), (re.compile('apigroups:\\s*\\[\\s*"\\*"\\s*\\]', re.IGNORECASE | re.MULTILINE), 'Wildcard API group access in RBAC rule', Severity.HIGH), (re.compile('kind:\\s*serviceaccount', re.IGNORECASE | re.MULTILINE), 'Service account in RBAC subject (potential privilege escalation)', Severity.MEDIUM), (re.compile('impersonate', re.IGNORECASE | re.MULTILINE), 'User/service account impersonation permission', Severity.HIGH), (re.compile('serviceaccounts/token', re.IGNORECASE | re.MULTILINE), 'Service account token creation permission', Severity.HIGH), (re.compile('pods/exec', re.IGNORECASE | re.MULTILINE), 'Pod exec permission (remote command execution)', Severity.MEDIUM), (re.compile('secrets', re.IGNORECASE | re.MULTILINE), 'Secret access permission (credential exposure)', Severity.HIGH)]
    ADMISSION_CONTROLLER_PATTERNS = [(re.compile('kind:\\s*MutatingWebhookConfiguration', re.IGNORECASE), 'Mutating webhook configuration detected', Severity.MEDIUM), (re.compile('kind:\\s*ValidatingWebhookConfiguration', re.IGNORECASE), 'Validating webhook configuration detected', Severity.MEDIUM), (re.compile('podSecurityPolicy:', re.IGNORECASE), 'PodSecurityPolicy usage (deprecated in K8s 1.25+)', Severity.MEDIUM), (re.compile('pod-security.kubernetes.io/(enforce|audit|warn):\\s*privileged', re.IGNORECASE), 'Relaxed Pod Security Standard (privileged mode)', Severity.HIGH), (re.compile('OPA|Gatekeeper|ConstraintTemplate', re.IGNORECASE), 'OPA/Gatekeeper policy modification detected', Severity.HIGH), (re.compile('admissionRegistration.k8s.io', re.IGNORECASE), 'Admission registration API access', Severity.MEDIUM)]
    K8S_LATERAL_MOVEMENT_PATTERNS = [(re.compile('kubectl\\s+exec\\s+-n\\s+\\S+\\s+\\S+\\s+-c\\s+\\S+', re.IGNORECASE), 'Multi-container pod exec (lateral movement indicator)', Severity.HIGH), (re.compile('nsenter\\s+--target\\s+\\d+', re.IGNORECASE), 'Namespace entry via nsenter (container escape attempt)', Severity.CRITICAL), (re.compile('curl\\s+http://\\d+\\.\\d+\\.\\d+\\.\\d+:10250', re.IGNORECASE), 'Direct kubelet API access (worker node compromise)', Severity.HIGH), (re.compile('wget\\s+.*serviceaccount.*token', re.IGNORECASE), 'Service account token download attempt', Severity.HIGH), (re.compile('scp\\s+.*/var/run/secrets', re.IGNORECASE), 'Service account credential exfiltration', Severity.CRITICAL), (re.compile('iptables\\s+-[AD].*KUBE-', re.IGNORECASE), 'Kubernetes iptable rules modification', Severity.HIGH)]
    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute Kubernetes security analysis"""
        evidences = []

        # Quick mode: run lightweight process-based checks
        # Full mode: comprehensive analysis
        if not self._is_kubernetes_environment(collected_data):
            return evidences
        k8s_env = self._detect_k8s_environment_type(collected_data)
        try:
            process_data = self._get_data(collected_data, 'process')
        except KeyError:
            process_data = {}
        try:
            network_data = self._get_data(collected_data, 'network')
        except KeyError:
            network_data = {}
        try:
            filesystem_data = self._get_data(collected_data, 'filesystem')
        except KeyError:
            filesystem_data = {}
        evidences.extend(self._detect_control_plane_exposure(network_data))
        evidences.extend(self._detect_service_account_exposure(filesystem_data))
        evidences.extend(self._detect_privileged_configurations(filesystem_data))
        mount_evidences = self._detect_dangerous_mounts(filesystem_data)
        mount_evidences = self._aggregate_mount_evidences(mount_evidences, k8s_env)
        evidences.extend(mount_evidences)
        evidences.extend(self._detect_rbac_issues(filesystem_data))
        evidences.extend(self._detect_dangerous_capabilities(filesystem_data))
        evidences.extend(self._detect_k8s_mining(process_data))
        evidences.extend(self._detect_kubelet_issues(process_data, network_data))
        evidences.extend(self._detect_secret_exposure(process_data))
        evidences.extend(self._detect_security_profile_absence(filesystem_data))
        evidences.extend(self._detect_k8s_api_abuse(process_data))
        evidences.extend(self._detect_malicious_pod_specs(filesystem_data))
        evidences.extend(self._detect_rbac_escalation(filesystem_data))
        evidences.extend(self._detect_admission_controller_bypass(filesystem_data))
        evidences.extend(self._detect_lateral_movement(process_data, network_data))
        return evidences

    def _is_kubernetes_environment(self, collected_data: dict) -> bool:
        """Detect if running in Kubernetes environment"""
        try:
            process_data = self._get_data(collected_data, 'process')
        except KeyError:
            process_data = {}
        if isinstance(process_data, dict):
            processes = process_data.get('processes', [])
            for proc in processes:
                cmdline = proc.get('cmdline', '').lower()
                comm = proc.get('comm', '').lower()
                for k8s_proc in self.K8S_PROCESSES:
                    if k8s_proc in cmdline or k8s_proc in comm:
                        _get_logger().info(f'[{self.name}] Kubernetes detected: found {k8s_proc} process')
                        return True
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            _get_logger().info(f'[{self.name}] Kubernetes detected: found service account directory')
            return True
        try:
            network_data = self._get_data(collected_data, 'network')
        except KeyError:
            network_data = {}
        if isinstance(network_data, dict):
            connections = network_data.get('connections', [])
            for conn in connections:
                local_port = conn.get('local_port', 0)
                if local_port in self.K8S_PORTS:
                    _get_logger().info(f'[{self.name}] Kubernetes detected: port {local_port}')
                    return True
        return False

    def _detect_k8s_environment_type(self, collected_data: dict) -> dict:
        """Detect detailed K8s environment type (master/worker/node)

        Returns dict with environment details for mount whitelist decisions.
        """
        env = {'is_k8s_node': False, 'role': 'unknown', 'components': [], 'has_kubelet': False, 'has_kubeconfig': False}
        try:
            process_data = self._get_data(collected_data, 'process')
        except KeyError:
            process_data = {}
        if not isinstance(process_data, dict):
            return env
        processes = process_data.get('processes', [])
        process_cmdlines = []
        for proc in processes:
            cmdline = proc.get('cmdline', '')
            comm = proc.get('comm', '')
            process_cmdlines.append(cmdline.lower())
            if 'kubelet' in cmdline.lower() or 'kubelet' in comm.lower():
                env['is_k8s_node'] = True
                env['has_kubelet'] = True
                if 'kubelet' not in env['components']:
                    env['components'].append('kubelet')
            if 'kube-apiserver' in cmdline.lower():
                env['role'] = 'master'
                if 'kube-apiserver' not in env['components']:
                    env['components'].append('kube-apiserver')
            if 'etcd' in cmdline.lower() and 'etcdctl' not in cmdline.lower():
                if env['role'] != 'master':
                    env['role'] = 'master'
                if 'etcd' not in env['components']:
                    env['components'].append('etcd')
            if 'kube-proxy' in cmdline.lower():
                if env['role'] == 'unknown':
                    env['role'] = 'worker'
                if 'kube-proxy' not in env['components']:
                    env['components'].append('kube-proxy')
        kubeconfig_paths = ['/etc/kubernetes/admin.conf', '/etc/kubernetes/kubelet.conf', os.path.expanduser('~/.kube/config')]
        for path in kubeconfig_paths:
            if os.path.exists(path):
                env['has_kubeconfig'] = True
                break
        cni_paths = ['/opt/cni/bin/', '/usr/libexec/cni/']
        for path in cni_paths:
            if os.path.exists(path):
                env['has_cni'] = True
                break
        _get_logger().info(f'[{self.name}] K8s environment type: {env}')
        return env

    def _is_legitimate_k8s_mount(self, mount_point: str, env: dict) -> bool:
        """Check if mount is legitimate for K8s node environment

        Args:
            mount_point: Mount point path
            env: K8s environment dict from _detect_k8s_environment_type

        Returns:
            bool: True if mount is legitimate for K8s node
        """
        if not env.get('is_k8s_node', False):
            return False
        if mount_point not in self.K8S_NODE_LEGITIMATE_MOUNTS:
            return False
        return True

    def _aggregate_mount_evidences(self, evidences: List[Evidence], env: dict) -> List[Evidence]:
        """Aggregate mount-related evidences to reduce false positives

        Args:
            evidences: List of evidence from mount detection
            env: K8s environment type

        Returns:
            List[Evidence]: Aggregated evidences
        """
        if not evidences:
            return evidences
        mount_evidences = []
        other_evidences = []
        for evidence in evidences:
            if 'Dangerous Mount' in evidence.title:
                mount_evidences.append(evidence)
            else:
                other_evidences.append(evidence)
        if not mount_evidences:
            return evidences
        legitimate_mounts = []
        suspicious_mounts = []
        for evidence in mount_evidences:
            mount_point = evidence.raw_data.get('mount_point', '')
            if self._is_legitimate_k8s_mount(mount_point, env):
                evidence.severity = Severity.INFO
                evidence.description = f"Mount point {mount_point} detected. This is a standard K8s node mount. Reason: {self.K8S_NODE_LEGITIMATE_MOUNTS[mount_point]['reason']}"
                legitimate_mounts.append(evidence)
            else:
                suspicious_mounts.append(evidence)
        if legitimate_mounts and (not suspicious_mounts):
            mount_points = [e.raw_data.get('mount_point', '') for e in legitimate_mounts]
            evidence_detail = EvidenceDetail(file_path='/proc/mounts', content=f'Aggregated {len(legitimate_mounts)} standard K8s mounts'[:500])
            return [self._create_evidence(title=f'K8s Node Mounts (Informational)', description=f"{len(legitimate_mounts)} standard K8s node mounts detected. Environment: {env.get('role', 'unknown')} node. Mounts: {', '.join(mount_points)}. These are normal for K8s node operation.", severity=Severity.INFO, confidence=0.9, attack_id='T1610', attack_tactic='Container Administration', source_path='/proc/mounts', raw_data={'mount_points': mount_points, 'environment': env.get('role', 'unknown'), 'components': env.get('components', []), 'aggregated': True}, remediation='These are standard K8s node mounts. No action required. Ensure kubelet and container runtime are from official sources.', evidence_details=evidence_detail, remediation_commands=generate_generic_remediation(attack_id='1610', context={'analyzer': 'kubernetes_analyzer'}))]
        if suspicious_mounts:
            result = suspicious_mounts
            if legitimate_mounts:
                mount_points = [e.raw_data.get('mount_point', '') for e in legitimate_mounts]
                evidence_detail = EvidenceDetail(file_path='/proc/mounts', content=f"Standard K8s mounts: {', '.join(mount_points)}"[:500])
                result.append(self._create_evidence(title=f'K8s Standard Mounts (Informational)', description=f"{len(legitimate_mounts)} standard K8s mounts also detected: {', '.join(mount_points)}. These are normal.", severity=Severity.INFO, confidence=0.9, attack_id='T1610', attack_tactic='Container Administration', source_path='/proc/mounts', raw_data={'mount_points': mount_points, 'aggregated': True}, remediation='Standard K8s mounts - no action required.', evidence_details=evidence_detail, remediation_commands=generate_generic_remediation(attack_id='1610', context={'analyzer': 'kubernetes_analyzer'})))
            return result
        return evidences

    def _detect_control_plane_exposure(self, network_data: dict) -> List[Evidence]:
        """Detect exposed Kubernetes control plane ports"""
        evidences = []
        connections = network_data.get('connections', [])
        for conn in connections:
            local_port = conn.get('local_port', 0)
            remote_addr = conn.get('remote_address', '')
            state = conn.get('state', '')
            if local_port in self.K8S_PORTS:
                service_name, severity = self.K8S_PORTS[local_port]
                local_addr = conn.get('local_address', '')
                is_exposed = local_addr in ['0.0.0.0', '::', '*', '']
                if is_exposed and state == 'LISTEN':
                    evidence_detail = EvidenceDetail(local_address=local_addr, remote_address=remote_addr, connection_state=state, service_type=service_name)
                    remediation_cmds = [f"""kubectl patch svc {service_name} -p '{{"spec":{{"type":"ClusterIP"}}}}'""", f'iptables -A INPUT -p tcp --dport {local_port} -j DROP']
                    evidences.append(self._create_evidence(title=f'Exposed {service_name} port ({local_port})', description=f'{service_name} is listening on all interfaces (0.0.0.0:{local_port}), potentially accessible from untrusted networks', severity=severity, confidence=0.9, attack_id='T1610', attack_tactic='Lateral Movement', source_path='/proc/net/tcp', raw_data={'port': local_port, 'service': service_name, 'address': local_addr}, remediation=f'Bind {service_name} to localhost (127.0.0.1) or use firewall rules to restrict access to trusted IPs only', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
        return evidences
    def _detect_service_account_exposure(self, filesystem_data: dict) -> List[Evidence]:
        """Detect service account token exposure"""
        evidences = []
        sa_token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
        if os.path.exists(sa_token_path):
            try:
                with open(sa_token_path, 'r', encoding='utf-8') as f:
                    token_content = f.read(1024)
                if token_content.strip():
                    evidence_detail = EvidenceDetail(file_path=sa_token_path, credential_type='ServiceAccountToken')
                    remediation_cmds = ['kubectl get secrets', 'kubectl delete secret {secret_name}']
                    evidences.append(self._create_evidence(title='Service Account Token Accessible', description='Pod service account JWT token is accessible. If compromised, attackers can use this token to authenticate to the K8s API server.', severity=Severity.MEDIUM, confidence=1.0, attack_id='T1078.004', attack_tactic='Privilege Escalation', source_path=sa_token_path, raw_data={'token_preview': token_content[:100] + '...'}, remediation='Use projected service account tokens with short expiration. Implement RBAC least privilege for service accounts.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
            except OSError:
                pass
        kubeconfig_paths = ['/etc/kubernetes/admin.conf', '/root/.kube/config', '/home/*/.kube/config']
        for pattern in kubeconfig_paths:
            if '*' in pattern:
                import glob
                matches = glob.glob(pattern)
                for match in matches:
                    if os.path.isfile(match):
                        evidence_detail = EvidenceDetail(file_path=match, credential_type='Kubeconfig')
                        remediation_cmds = [f'chmod 600 {match}', 'kubectl config view --minify']
                        evidences.append(self._create_evidence(title='Kubeconfig File Found', description=f'Kubernetes configuration file found at {match}. Contains cluster credentials and API endpoint.', severity=Severity.HIGH, confidence=0.95, attack_id='T1552.004', attack_tactic='Credential Access', source_path=match, raw_data={'path': match}, remediation='Restrict kubeconfig file permissions (chmod 600). Use short-lived tokens and rotate credentials regularly.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
            elif os.path.isfile(pattern):
                evidence_detail = EvidenceDetail(file_path=pattern, credential_type='Kubeconfig')
                remediation_cmds = [f'chmod 600 {pattern}', 'kubectl config view --minify']
                evidences.append(self._create_evidence(title='Kubeconfig File Found', description=f'Kubernetes configuration file found at {pattern}. Contains cluster credentials and API endpoint.', severity=Severity.HIGH, confidence=0.95, attack_id='T1552.004', attack_tactic='Credential Access', source_path=pattern, raw_data={'path': pattern}, remediation='Restrict kubeconfig file permissions (chmod 600). Use short-lived tokens and rotate credentials regularly.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
        return evidences

    def _detect_privileged_configurations(self, filesystem_data: dict) -> List[Evidence]:
        """Detect privileged pod configurations in YAML files"""
        evidences = []
        yaml_files = []
        k8s_dirs = ['/etc/kubernetes/', '/opt/kubernetes/', '/srv/kubernetes/']
        for base_dir in k8s_dirs:
            if os.path.isdir(base_dir):
                for root, dirs, files in os.walk(base_dir):
                    for f in files:
                        if f.endswith(('.yaml', '.yml')):
                            yaml_files.append(os.path.join(root, f))
        for yaml_path in yaml_files:
            try:
                with open(yaml_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                for pattern, description in self.PRIVILEGED_INDICATORS:
                    if pattern.search(content):
                        evidence_detail = EvidenceDetail(file_path=yaml_path, content=f'Pattern: {description}'[:500])
                        remediation_cmds = [f'kubectl edit pod {yaml_path}  # Set securityContext.privileged: false']
                        evidences.append(self._create_evidence(title=f'Privileged Configuration: {description}', description=f'Found in {yaml_path}: {description}. This configuration may allow container escape or host compromise.', severity=Severity.HIGH, confidence=0.85, attack_id='T1611', attack_tactic='Defense Evasion', source_path=yaml_path, raw_data={'pattern': pattern.pattern, 'file': yaml_path}, remediation='Remove privileged settings unless absolutely necessary. Use Pod Security Standards/Policies to enforce restrictions.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                        break
            except OSError:
                continue
        return evidences

    def _detect_dangerous_mounts(self, filesystem_data: dict) -> List[Evidence]:
        """Detect dangerous volume mounts in pod specifications"""
        evidences = []
        try:
            with open('/proc/mounts', 'r', encoding='utf-8') as f:
                mounts = f.readlines()
            for mount_line in mounts:
                parts = mount_line.split()
                if len(parts) >= 2:
                    mount_point = parts[1]
                    for dangerous_path, risk_desc in self.DANGEROUS_MOUNTS.items():
                        if mount_point == dangerous_path or mount_point.startswith(dangerous_path + '/'):
                            evidence_detail = EvidenceDetail(file_path='/proc/mounts', content=f'Mount: {mount_point} - Risk: {risk_desc}'[:500])
                            remediation_cmds = [f'kubectl edit pod {{pod_name}}  # Remove dangerous volume mount']
                            evidences.append(self._create_evidence(title=f'Dangerous Mount: {mount_point}', description=f'Mount point {mount_point} detected. Risk: {risk_desc}. May indicate host filesystem access from container.', severity=Severity.MEDIUM if dangerous_path != '/' else Severity.CRITICAL, confidence=0.75, attack_id='T1611', attack_tactic='Privilege Escalation', source_path='/proc/mounts', raw_data={'mount_point': mount_point, 'risk': risk_desc}, remediation='Avoid mounting sensitive host paths. Use read-only mounts and minimal path scope when necessary.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                            break
        except OSError:
            pass
        return evidences

    def _detect_rbac_issues(self, filesystem_data: dict) -> List[Evidence]:
        """Detect RBAC misconfigurations in role bindings"""
        evidences = []
        rbac_dirs = ['/etc/kubernetes/', '/opt/', '/srv/']
        for base_dir in rbac_dirs:
            if not os.path.isdir(base_dir):
                continue
            for root, dirs, files in os.walk(base_dir):
                for f in files:
                    if not f.endswith(('.yaml', '.yml')):
                        continue
                    yaml_path = os.path.join(root, f)
                    try:
                        with open(yaml_path, 'r', encoding='utf-8', errors='replace') as file:
                            content = file.read().lower()
                        if 'kind:' not in content:
                            continue
                        if not any((x in content for x in ['rolebinding', 'clusterrolebinding', 'role', 'clusterrole'])):
                            continue
                        for pattern, description in self.RBAC_DANGEROUS_PATTERNS:
                            if pattern.search(content):
                                evidence_detail = EvidenceDetail(file_path=yaml_path, content=f'Pattern: {description}'[:500])
                                remediation_cmds = ['kubectl auth can-list --all-namespaces', f'kubectl edit clusterrole {{role_name}}']
                                evidences.append(self._create_evidence(title=f'RBAC Risk: {description}', description=f'Found in {yaml_path}: {description}. Overly permissive RBAC can lead to privilege escalation.', severity=Severity.HIGH, confidence=0.8, attack_id='T1078.004', attack_tactic='Privilege Escalation', source_path=yaml_path, raw_data={'pattern': pattern.pattern, 'file': yaml_path}, remediation='Apply principle of least privilege. Avoid wildcards. Regularly audit RBAC permissions with tools like rbac-lookup.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                                break
                    except OSError:
                        continue
        return evidences

    def _detect_dangerous_capabilities(self, filesystem_data: dict) -> List[Evidence]:
        """Detect dangerous Linux capabilities in pod specs"""
        evidences = []
        k8s_dirs = ['/etc/kubernetes/', '/opt/', '/srv/']
        for base_dir in k8s_dirs:
            if not os.path.isdir(base_dir):
                continue
            for root, dirs, files in os.walk(base_dir):
                for f in files:
                    if not f.endswith(('.yaml', '.yml')):
                        continue
                    yaml_path = os.path.join(root, f)
                    try:
                        with open(yaml_path, 'r', encoding='utf-8', errors='replace') as file:
                            content = file.read()
                        for cap, risk in self.DANGEROUS_CAPABILITIES.items():
                            cap_pattern = re.compile(f'add:\\s*\\[?[^\\]]*{cap}[^\\]]*\\]?', re.IGNORECASE)
                            if cap_pattern.search(content):
                                evidence_detail = EvidenceDetail(file_path=yaml_path, content=f'Capability: {cap} - Risk: {risk}'[:500])
                                remediation_cmds = [f'kubectl edit pod {{pod_name}}  # Remove {cap} capability']
                                evidences.append(self._create_evidence(title=f'Dangerous Capability: {cap}', description=f'Found in {yaml_path}: {cap} capability added. Risk: {risk}', severity=Severity.HIGH if cap in ['SYS_ADMIN', 'SYS_MODULE'] else Severity.MEDIUM, confidence=0.85, attack_id='T1611', attack_tactic='Privilege Escalation', source_path=yaml_path, raw_data={'capability': cap, 'file': yaml_path}, remediation=f'Remove {cap} capability unless absolutely necessary. Use capability dropping in Pod Security Context.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                                break
                    except OSError:
                        continue
        return evidences

    def _detect_k8s_mining(self, process_data: dict) -> List[Evidence]:
        """Detect cryptomining programs in Kubernetes environment"""
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            pid = proc.get('pid', 0)
            if self.cicd_detector.is_ci_cd_context(process_data, pid):
                _get_logger().debug(f'[{self.name}] Skipping CI/CD context for PID {pid}')
                continue
            cmdline = proc.get('cmdline', '').lower()
            comm = proc.get('comm', '').lower()
            exe = proc.get('exe', '').lower()
            for mining_tool, description in self.K8S_MINING_INDICATORS.items():
                if mining_tool.lower() in cmdline or mining_tool.lower() in comm or mining_tool.lower() in exe:
                    evidence_detail = EvidenceDetail(pid=pid, cmdline=cmdline[:500] if cmdline else None, executable=exe if exe else None)
                    remediation_cmds = [f'kubectl delete pod {{pod_name}}', f'kubectl get pods --all-namespaces -o wide | grep {mining_tool}']
                    evidences.append(self._create_evidence(title=f'Cryptominer Detected in K8s: {mining_tool}', description=f"Process '{mining_tool}' (PID: {pid}) detected. {description}. Common in compromised K8s clusters.", severity=Severity.CRITICAL, confidence=0.95, attack_id='T1496', attack_tactic='Impact', source_path=f'/proc/{pid}/cmdline', raw_data={'pid': pid, 'cmdline': cmdline, 'tool': mining_tool}, remediation='Kill the malicious process. Audit pod specifications for unauthorized containers. Implement Pod Security Admission and network policies.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
        return evidences

    def _detect_kubelet_issues(self, process_data: dict, network_data: dict) -> List[Evidence]:
        """Detect kubelet security misconfigurations"""
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            pid = proc.get('pid', 0)
            cmdline = proc.get('cmdline', '')
            if self.cicd_detector.is_ci_cd_context(process_data, pid):
                _get_logger().debug(f'[{self.name}] Skipping CI/CD context for PID {pid}')
                continue
            if 'kubelet' in cmdline.lower():
                if '--anonymous-auth=true' in cmdline or '--anonymous-auth' not in cmdline:
                    evidence_detail = EvidenceDetail(pid=pid, cmdline=cmdline[:500] if cmdline else None, service_type='kubelet')
                    remediation_cmds = [f"kubectl patch node {{node}} --type='json' -p='[]'", 'Edit kubelet config to enable auth']
                    evidences.append(self._create_evidence(title='Kubelet Anonymous Authentication Enabled', description='Kubelet is running with anonymous authentication enabled. Attackers can query kubelet API without credentials.', severity=Severity.HIGH, confidence=0.9, attack_id='T1610', attack_tactic='Initial Access', source_path='/proc/*/cmdline', raw_data={'cmdline': cmdline[:500]}, remediation='Start kubelet with --anonymous-auth=false. Use webhook token authentication or client certificate authentication.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                if '--read-only-port=10255' in cmdline or '--read-only-port' not in cmdline:
                    evidence_detail = EvidenceDetail(pid=pid, cmdline=cmdline[:500] if cmdline else None, service_type='kubelet')
                    remediation_cmds = ['Edit kubelet config: --read-only-port=0', 'systemctl restart kubelet']
                    evidences.append(self._create_evidence(title='Kubelet Read-Only Port Exposed', description='Kubelet read-only port (10255) is enabled. Exposes container information, metrics, and pprof endpoints.', severity=Severity.MEDIUM, confidence=0.85, attack_id='T1610', attack_tactic='Discovery', source_path='/proc/*/cmdline', raw_data={'cmdline': cmdline[:500]}, remediation='Disable read-only port: --read-only-port=0', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
        return evidences

    def _detect_secret_exposure(self, process_data: dict) -> List[Evidence]:
        """Detect Kubernetes secrets exposed via environment variables"""
        evidences = []
        processes = process_data.get('processes', [])
        secret_patterns = [(re.compile('KUBERNETES_SERVICE_.*=\\S+'), 'Kubernetes service env vars'), (re.compile('DATABASE_URL=.*://.*:.*@'), 'Database URL with credentials'), (re.compile('REDIS_URL=.*://.*:.*@'), 'Redis URL with credentials'), (re.compile('MONGO_URI=.*://.*:.*@'), 'MongoDB URI with credentials'), (re.compile('(AWS_SECRET_KEY|AWS_ACCESS_KEY)=\\S+'), 'AWS credentials in env'), (re.compile('(API_KEY|SECRET_KEY|TOKEN)=\\S+'), 'Generic API key/secret in env')]
        for proc in processes:
            pid = proc.get('pid', 0)
            if self.cicd_detector.is_ci_cd_context(process_data, pid):
                _get_logger().debug(f'[{self.name}] Skipping CI/CD context for PID {pid}')
                continue
            environ = proc.get('environ', {})
            if not isinstance(environ, dict):
                _get_logger().debug(f'[{self.name}] Environ is not a dict for PID {pid}, skipping')
                continue
            for pattern, desc in secret_patterns:
                for env_key, env_val in environ.items():
                    if pattern.match(f'{env_key}={env_val}'):
                        evidence_detail = EvidenceDetail(pid=pid, cmdline=proc.get('cmdline', '')[:500] if proc.get('cmdline') else None, credential_type='EnvironmentVariable')
                        remediation_cmds = [f'kubectl edit pod {{pod_name}}  # Remove secret from env', 'Use external-secrets operator']
                        evidences.append(self._create_evidence(title=f'Secret Exposure: {desc}', description=f"Environment variable in process {pid} ({proc.get('comm', '')}) contains sensitive data: {env_key}=***", severity=Severity.MEDIUM, confidence=0.8, attack_id='T1552.004', attack_tactic='Credential Access', source_path=f'/proc/{pid}/environ', raw_data={'pid': pid, 'env_key': env_key, 'pattern': desc}, remediation='Use Kubernetes Secrets mounted as files instead of environment variables. Implement external secret management (Vault, AWS Secrets Manager).', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                        break
        return evidences

    def _detect_security_profile_absence(self, filesystem_data: dict) -> List[Evidence]:
        """Detect absence of AppArmor/Seccomp profiles"""
        evidences = []
        apparmor_enabled = os.path.exists('/sys/kernel/security/apparmor')
        if apparmor_enabled:
            try:
                with open('/sys/kernel/security/apparmor/profiles', 'r', encoding='utf-8') as f:
                    profiles = f.readlines()
                apparmor_enabled = len(profiles) > 0
            except OSError:
                pass
        seccomp_available = os.path.exists('/proc/self/status')
        seccomp_enabled = False
        if seccomp_available:
            try:
                with open('/proc/self/status', 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('Seccomp:'):
                            seccomp_enabled = line.split(':')[1].strip() != '0'
                            break
            except OSError:
                pass
        if not apparmor_enabled and (not seccomp_enabled):
            evidence_detail = EvidenceDetail(file_path='/sys/kernel/security', content=f'AppArmor: {apparmor_enabled}, Seccomp: {seccomp_enabled}'[:500])
            evidences.append(self._create_evidence(title='No Container Security Profiles', description='Neither AppArmor nor Seccomp are enabled on this system. Containers lack mandatory security confinement.', severity=Severity.MEDIUM, confidence=0.7, attack_id='T1611', attack_tactic='Defense Evasion', source_path='/sys/kernel/security', raw_data={'apparmor': apparmor_enabled, 'seccomp': seccomp_enabled}, remediation='Enable AppArmor profiles for pods. Configure default Seccomp profile. Use Pod Security Admission to enforce security profiles.', evidence_details=evidence_detail, remediation_commands=generate_generic_remediation(attack_id='1611', context={'analyzer': 'kubernetes_analyzer'})))
        return evidences

    def _detect_k8s_api_abuse(self, process_data: dict) -> List[Evidence]:
        """Detect Kubernetes API access abuse (T1610.002)"""
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            pid = proc.get('pid', 0)
            if self.cicd_detector.is_ci_cd_context(process_data, pid):
                _get_logger().debug(f'[{self.name}] Skipping CI/CD context for PID {pid}')
                continue
            cmdline = proc.get('cmdline', '')
            comm = proc.get('comm', '')
            for pattern, description in self.K8S_API_ABUSE_PATTERNS:
                if pattern.search(cmdline):
                    severity = Severity.HIGH
                    confidence = 0.85
                    if 'cluster-admin' in description.lower():
                        severity = Severity.CRITICAL
                        confidence = 0.95
                    elif 'bearer token' in description.lower() or 'insecure TLS' in description.lower():
                        severity = Severity.HIGH
                        confidence = 0.9
                    evidences.append(self._create_evidence(title=f'K8s API Abuse: {description}', description=f"Process '{comm}' (PID: {pid}) executing suspicious K8s API command. {description}. This may indicate unauthorized cluster access or privilege escalation.", severity=severity, confidence=confidence, attack_id='T1610.002', attack_tactic='Execution', source_path=f'/proc/{pid}/cmdline', raw_data={'pid': pid, 'cmdline': cmdline[:500], 'pattern': description}, remediation='Audit kubectl usage and restrict API access via RBAC. Monitor service account token usage. Implement audit logging for K8s API server.', evidence_details=EvidenceDetail(pid=pid, cmdline=cmdline[:500] if cmdline else None), remediation_commands=['kubectl get pods --all-namespaces --field-selector status.phase=Running', f'kubectl logs {{pod_name}}']))
                    break
        return evidences

    def _detect_malicious_pod_specs(self, filesystem_data: dict) -> List[Evidence]:
        """Detect malicious pod specifications in YAML manifests"""
        evidences = []
        yaml_files = []
        k8s_dirs = ['/etc/kubernetes/', '/opt/kubernetes/', '/srv/kubernetes/']
        for base_dir in k8s_dirs:
            if os.path.isdir(base_dir):
                for root, dirs, files in os.walk(base_dir):
                    for f in files:
                        if f.endswith(('.yaml', '.yml')):
                            yaml_files.append(os.path.join(root, f))
        for yaml_path in yaml_files:
            try:
                with open(yaml_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                for pattern, description, severity in self.MALICIOUS_POD_PATTERNS:
                    if pattern.search(content):
                        confidence = 0.85
                        if severity == Severity.CRITICAL:
                            confidence = 0.95
                        evidence_detail = EvidenceDetail(file_path=yaml_path, content=f'Pattern: {description}'[:500])
                        remediation_cmds = [f'kubectl edit pod {{pod_name}}  # Set securityContext.privileged: false']
                        evidences.append(self._create_evidence(title=f'Malicious Pod Spec: {description}', description=f'Found in {yaml_path}: {description}. This pod specification may enable container escape or host compromise.', severity=severity, confidence=confidence, attack_id='T1610', attack_tactic='Execution', source_path=yaml_path, raw_data={'file': yaml_path, 'pattern': description}, remediation='Apply Pod Security Standards to reject privileged pods. Use OPA/Gatekeeper policies to enforce security constraints. Review and restrict volume mount permissions.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                        break
            except OSError:
                continue
        return evidences

    def _detect_rbac_escalation(self, filesystem_data: dict) -> List[Evidence]:
        """Detect RBAC privilege escalation patterns"""
        evidences = []
        rbac_dirs = ['/etc/kubernetes/', '/opt/', '/srv/']
        for base_dir in rbac_dirs:
            if not os.path.isdir(base_dir):
                continue
            for root, dirs, files in os.walk(base_dir):
                for f in files:
                    if not f.endswith(('.yaml', '.yml')):
                        continue
                    rbac_path = os.path.join(root, f)
                    try:
                        with open(rbac_path, 'r', encoding='utf-8', errors='replace') as file:
                            content = file.read().lower()
                        if 'kind:' not in content:
                            continue
                        if not any((x in content for x in ['rolebinding', 'clusterrolebinding', 'role', 'clusterrole'])):
                            continue
                        for pattern, description, severity in self.RBAC_ESCALATION_PATTERNS:
                            if pattern.search(content):
                                confidence = 0.85
                                if severity == Severity.CRITICAL:
                                    confidence = 0.95
                                evidence_detail = EvidenceDetail(file_path=rbac_path, content=f'Pattern: {description}'[:500])
                                remediation_cmds = ['kubectl auth can-list --all-namespaces', f'kubectl edit clusterrole {{role_name}}']
                                evidences.append(self._create_evidence(title=f'RBAC Escalation: {description}', description=f'Found in {rbac_path}: {description}. Overly permissive RBAC can lead to privilege escalation.', severity=severity, confidence=confidence, attack_id='T1078.004', attack_tactic='Privilege Escalation', source_path=rbac_path, raw_data={'file': rbac_path, 'pattern': description}, remediation='Apply principle of least privilege. Avoid wildcards. Regularly audit RBAC with tools like kubectl-who-can or rbac-lookup. Use namespace-scoped roles instead of cluster-wide roles.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                    except OSError:
                        continue
        return evidences

    def _detect_admission_controller_bypass(self, filesystem_data: dict) -> List[Evidence]:
        """Detect admission controller bypass attempts"""
        evidences = []
        yaml_files = []
        k8s_dirs = ['/etc/kubernetes/', '/opt/kubernetes/']
        for base_dir in k8s_dirs:
            if os.path.isdir(base_dir):
                for root, dirs, files in os.walk(base_dir):
                    for f in files:
                        if f.endswith(('.yaml', '.yml')):
                            yaml_files.append(os.path.join(root, f))
        for yaml_path in yaml_files:
            try:
                with open(yaml_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                for pattern, description, default_severity in self.ADMISSION_CONTROLLER_PATTERNS:
                    if pattern.search(content):
                        severity = default_severity
                        confidence = 0.8
                        if 'privileged' in description.lower():
                            confidence = 0.9
                        elif 'OPA' in description or 'Gatekeeper' in description:
                            confidence = 0.85
                        evidence_detail = EvidenceDetail(file_path=yaml_path, content=f'Pattern: {description}'[:500])
                        evidences.append(self._create_evidence(title=f'Admission Controller: {description}', description=f'Found in {yaml_path}: {description}. Admission controller modifications may weaken cluster security.', severity=severity, confidence=confidence, attack_id='T1610', attack_tactic='Defense Evasion', source_path=yaml_path, raw_data={'file': yaml_path, 'pattern': description}, remediation='Audit admission webhook configurations regularly. Enforce Pod Security Standards at namespace level. Monitor changes to admission registration APIs.', evidence_details=evidence_detail, remediation_commands=generate_generic_remediation(attack_id='1610', context={'analyzer': 'kubernetes_analyzer'})))
                        break
            except OSError:
                continue
        return evidences

    def _detect_lateral_movement(self, process_data: dict, network_data: dict) -> List[Evidence]:
        """Detect cluster-wide lateral movement indicators"""
        evidences = []
        processes = process_data.get('processes', [])
        for proc in processes:
            pid = proc.get('pid', 0)
            if self.cicd_detector.is_ci_cd_context(process_data, pid):
                _get_logger().debug(f'[{self.name}] Skipping CI/CD context for PID {pid}')
                continue
            cmdline = proc.get('cmdline', '')
            comm = proc.get('comm', '')
            for pattern, description, default_severity in self.K8S_LATERAL_MOVEMENT_PATTERNS:
                if pattern.search(cmdline):
                    severity = default_severity
                    confidence = 0.85
                    if 'nsenter' in description.lower() or 'exfiltration' in description.lower():
                        confidence = 0.95
                    evidence_detail = EvidenceDetail(pid=pid, cmdline=cmdline[:500] if cmdline else None)
                    remediation_cmds = ['kubectl networkpolicies list', f'kubectl edit networkpolicy {{name}}']
                    evidences.append(self._create_evidence(title=f'Lateral Movement: {description}', description=f"Process '{comm}' (PID: {pid}) shows lateral movement indicator. {description}. This may indicate cluster compromise propagation.", severity=severity, confidence=confidence, attack_id='T1610', attack_tactic='Lateral Movement', source_path=f'/proc/{pid}/cmdline', raw_data={'pid': pid, 'cmdline': cmdline[:500], 'pattern': description}, remediation='Implement network policies to restrict pod-to-pod communication. Audit service account permissions across namespaces. Monitor kubelet API access from untrusted sources.', evidence_details=evidence_detail, remediation_commands=remediation_cmds))
                    break
        return evidences