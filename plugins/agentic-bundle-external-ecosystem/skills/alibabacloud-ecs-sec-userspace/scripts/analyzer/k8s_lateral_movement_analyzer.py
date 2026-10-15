"""Kubernetes eBPF-based Lateral Movement Detection Analyzer

Detects sophisticated lateral movement techniques in Kubernetes clusters using eBPF, including:
- CNI plugin integrity verification (Calico, Cilium, Flannel)
- eBPF network hook detection (tc, XDP, socket operations)
- Network policy audit and unauthorized modifications
- Service mesh security analysis (Istio/Linkerd sidecar tampering)
- Pod escape detection via eBPF program loading from containers

ATT&CK Mapping:
- T1046 - Network Service Scanning (K8s service discovery)
- T1021.007 - Remote Services: Cloud Services (lateral movement via service mesh)
- T1562.008 - Impair Defenses: Disable Security Tools (network policy bypass)
- T1611 - Escape to Host (container breakout via eBPF)
- T1571 - Non-Standard Port (unusual service communication)
"""
import os
import re
import json
from typing import List

from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer
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

class K8sLateralMovementAnalyzer(BaseAnalyzer):
    """Kubernetes eBPF-based Lateral Movement Detection Analyzer"""

    name = "k8s_lateral_movement_analyzer"
    timeout = 60
    required_collectors = ["process", "network", "filesystem"]

    def should_skip(self) -> tuple:
        """Check if should skip in quick mode."""
        return False, ""

    ATTACK_ID = "T1611"
    ATTACK_TACTIC = "Lateral Movement"

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute Kubernetes eBPF lateral movement analysis
        
        In quick mode: only checks for K8s environment and critical indicators.
        In full mode: performs comprehensive CNI, eBPF, network policy, and service mesh analysis.
        """


    # CNI plugin paths and configurations
    CNI_CONFIG_DIRS = [
        '/etc/cni/net.d',
        '/opt/cni/bin',
        '/var/lib/cni',
    ]

    CNI_CONFIG_FILES = [
        '10-calico.conflist',
        '05-cilium.conflist',
        '10-flannel.conflist',
        'CNI_CONF_NAME',
    ]

    CNI_PLUGIN_BINARIES = [
        'calico',
        'cilium-cni',
        'flannel',
        'bridge',
        'ptp',
        'portmap',
        'bandwidth',
    ]

    # Suspicious CNI configuration patterns
    SUSPICIOUS_CNI_PATTERNS = [
        (re.compile(r'"promiscMode"\s*:\s*"?true"?', re.IGNORECASE), 
         "Promiscuous mode enabled in CNI config"),
        (re.compile(r'"mirror"\s*:', re.IGNORECASE),
         "Packet mirroring configured in CNI"),
        (re.compile(r'"redirect"\s*:', re.IGNORECASE),
         "Traffic redirection configured in CNI"),
        (re.compile(r'"tunnel"\s*:\s*"?"vxlan"?"', re.IGNORECASE),
         "VXLAN tunneling configured (potential interception)"),
        (re.compile(r'"type"\s*:\s*"?"portmap"?"', re.IGNORECASE),
         "Port mapping plugin (potential traffic manipulation)"),
    ]

    # eBPF program types for network hooks
    EBPF_PROGRAM_TYPES = {
        'sched_cls': 'Traffic control classifier',
        'sched_act': 'Traffic control action',
        'xdp': 'eXpress Data Path',
        'sock_ops': 'Socket operations',
        'sk_skb': 'Socket skb processing',
        'sk_msg': 'Socket message processing',
        'cgroup_skb': 'Cgroup skb filtering',
    }

    # Suspicious eBPF map names for lateral movement
    SUSPICIOUS_EBPF_MAPS = [
        'conntrack',
        'nat',
        'policy',
        'tunnel',
        'lb',
        'proxymap',
        'events',
        'metrics',
    ]

    # Network policy suspicious patterns
    NETWORK_POLICY_PATTERNS = [
        (re.compile(r'podSelector:\s*\{\}', re.IGNORECASE),
         "Empty pod selector (applies to all pods)"),
        (re.compile(r'ingress:\s*\[\s*\{\s*\}', re.IGNORECASE),
         "Allow-all ingress rule"),
        (re.compile(r'egress:\s*\[\s*\{\s*\}', re.IGNORECASE),
         "Allow-all egress rule"),
        (re.compile(r'cidr:\s*0\.0\.0\.0/0', re.IGNORECASE),
         "Allow traffic from/to any IP (0.0.0.0/0)"),
        (re.compile(r'namespaceSelector:\s*\{\}', re.IGNORECASE),
         "Empty namespace selector (all namespaces)"),
    ]

    # Service mesh sidecar indicators
    SIDECAR_INDICATORS = [
        (re.compile(r'istio-proxy|envoy|pilot-agent', re.IGNORECASE),
         "Istio sidecar proxy detected"),
        (re.compile(r'linkerd-proxy|linkerd-init', re.IGNORECASE),
         "Linkerd sidecar proxy detected"),
        (re.compile(r'sidecar\.istio\.io/inject:\s*"true"', re.IGNORECASE),
         "Sidecar injection annotation"),
        (re.compile(r'proxy\.istio\.io/config', re.IGNORECASE),
         "Istio proxy configuration"),
    ]

    # Service mesh security issues
    MESH_SECURITY_ISSUES = [
        (re.compile(r'mode:\s*DISABLE|PERMISSIVE', re.IGNORECASE),
         "mTLS disabled or in permissive mode", Severity.CRITICAL),
        (re.compile(r'tls:\s*\{\s*mode:\s*DISABLE', re.IGNORECASE),
         "TLS explicitly disabled", Severity.CRITICAL),
        (re.compile(r'authenticationPolicy.*mode:\s*NONE', re.IGNORECASE),
         "Authentication policy disabled", Severity.HIGH),
        (re.compile(r'allowOrigins:\s*\*\s*', re.IGNORECASE),
         "Wildcard origin allowed (CORS misconfiguration)", Severity.MEDIUM),
    ]

    # Pod escape indicators via eBPF
    POD_ESCAPE_INDICATORS = [
        (re.compile(r'CAP_SYS_ADMIN', re.IGNORECASE),
         "SYS_ADMIN capability (container escape risk)"),
        (re.compile(r'CAP_BPF', re.IGNORECASE),
         "BPF capability (eBPF program loading)"),
        (re.compile(r'CAP_NET_ADMIN', re.IGNORECASE),
         "NET_ADMIN capability (network manipulation)"),
        (re.compile(r'hostPID:\s*true', re.IGNORECASE),
         "Host PID namespace sharing"),
        (re.compile(r'hostNetwork:\s*true', re.IGNORECASE),
         "Host network namespace sharing"),
        (re.compile(r'hostIPC:\s*true', re.IGNORECASE),
         "Host IPC namespace sharing"),
        (re.compile(r'/proc\s', re.IGNORECASE),
         "Proc filesystem mount"),
        (re.compile(r'/sys/fs/bpf', re.IGNORECASE),
         "eBPF filesystem mount"),
        (re.compile(r'/var/run/docker\.sock', re.IGNORECASE),
         "Docker socket mount"),
        (re.compile(r'/var/run/containerd', re.IGNORECASE),
         "Containerd socket mount"),
    ]

    # kubectl commands for lateral movement
    LATERAL_MOVEMENT_COMMANDS = [
        (re.compile(r'kubectl\s+exec\s+-it.*--\s*/bin/(bash|sh)', re.IGNORECASE),
         "Interactive shell execution in pod"),
        (re.compile(r'kubectl\s+port-forward', re.IGNORECASE),
         "Port forwarding to pod"),
        (re.compile(r'kubectl\s+run\s+--rm\s+-i\s+--tty', re.IGNORECASE),
         "Ephemeral container execution"),
        (re.compile(r'kubectl\s+cp\s+', re.IGNORECASE),
         "File copy to/from pod"),
        (re.compile(r'istioctl\s+x\s+proxy-config', re.IGNORECASE),
         "Istio proxy configuration access"),
    ]

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute Kubernetes eBPF lateral movement analysis"""
        evidences = []

        if not self._is_kubernetes_environment(collected_data):
            return evidences

        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            process_data = {}

        try:
            self._get_data(collected_data, "network")
        except KeyError:
            pass

        try:
            filesystem_data = self._get_data(collected_data, "filesystem")
        except KeyError:
            filesystem_data = {}

        # 1. Check CNI plugin integrity
        evidences.extend(self._check_cni_integrity(filesystem_data))

        # 2. Detect eBPF network hooks
        evidences.extend(self._detect_ebpf_network_hooks(process_data, filesystem_data))

        # 3. Audit network policies
        evidences.extend(self._audit_network_policies(filesystem_data))

        # 4. Analyze service mesh security
        evidences.extend(self._analyze_service_mesh_security(process_data, filesystem_data))

        # 5. Detect pod escape attempts
        evidences.extend(self._detect_pod_escape_attempts(process_data, filesystem_data))

        # 6. Monitor lateral movement commands
        evidences.extend(self._monitor_lateral_movement_commands(process_data))

        return evidences
    def _is_kubernetes_environment(self, collected_data: dict) -> bool:
        """Detect if running in Kubernetes environment"""
        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            process_data = {}
        if isinstance(process_data, dict):
            processes = process_data.get("processes", [])
            for proc in processes:
                cmdline = proc.get("cmdline", "").lower()
                comm = proc.get("comm", "").lower()
                k8s_indicators = ['kubelet', 'kube-proxy', 'kube-apiserver', 
                                  'etcd', 'k3s', 'istio', 'linkerd']
                for indicator in k8s_indicators:
                    if indicator in cmdline or indicator in comm:
                        _get_logger().info(f"[{self.name}] Kubernetes detected: found {indicator}")
                        return True

        if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount"):
            _get_logger().info(f"[{self.name}] Kubernetes detected: service account directory")
            return True

        for cni_dir in self.CNI_CONFIG_DIRS:
            if os.path.exists(cni_dir):
                _get_logger().info(f"[{self.name}] Kubernetes detected: CNI directory {cni_dir}")
                return True

        return False

    def _check_cni_integrity(self, filesystem_data: dict) -> List[Evidence]:
        """Verify CNI configuration files and binaries for tampering"""
        evidences = []

        for cni_dir in self.CNI_CONFIG_DIRS:
            if not os.path.exists(cni_dir):
                continue

            try:
                for root, dirs, files in os.walk(cni_dir):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        
                        if filename.endswith(('.conflist', '.conf', '.json')):
                            evidences.extend(self._check_cni_config_file(filepath))
                        
                        elif not filename.startswith('.') and filename in self.CNI_PLUGIN_BINARIES:
                            evidences.extend(self._check_cni_binary(filepath))
            except OSError as e:
                _get_logger().warning(f"[{self.name}] Failed to scan {cni_dir}: {e}")

        return evidences

    def _check_cni_config_file(self, filepath: str) -> List[Evidence]:
        """Check individual CNI configuration file for anomalies"""
        evidences = []
        try:
            with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                content = f.read()

            for pattern, description in self.SUSPICIOUS_CNI_PATTERNS:
                if pattern.search(content):
                    evidences.append(self._create_evidence(
                        title=f"Suspicious CNI Configuration: {description}",
                        description=f"CNI config file {filepath} contains suspicious setting: {description}. "
                                   f"This may indicate traffic interception or manipulation.",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        attack_id="T1611",
                        attack_tactic=self.ATTACK_TACTIC,
                        source_path=filepath,
                        raw_data={"file": filepath, "pattern": description},
                        remediation=f"Review CNI configuration {filepath}. Compare against known-good baseline. "
                                   f"Remove unnecessary promiscuous mode, mirroring, or redirection settings.",
                        evidence_details=EvidenceDetail(
                            file_path=indicator.get('file_path', indicator.get('path', '')),
                            remote_address=indicator.get('remote_address', indicator.get('ip', '')),
                            connection_state=indicator.get('state', '')
                        ),
                        remediation_commands=[
                        "Review Kubernetes RBAC policies and service account permissions",
                        "Audit pod security policies and network policies",
                        "Check for unauthorized container images or deployments",
                        "Verify cloud provider IAM roles and workload identity bindings"
                    ]
                    ))
                    break

            try:
                config = json.loads(content)
                if isinstance(config, dict):
                    plugins = config.get('plugins', [])
                    for plugin in plugins:
                        if isinstance(plugin, dict):
                            plugin_type = plugin.get('type', '')
                            if plugin_type in ['portmap', 'bandwidth']:
                                evidences.append(self._create_evidence(
                                    title=f"CNI Plugin Type: {plugin_type}",
                                    description=f"CNI plugin '{plugin_type}' found in {filepath}. "
                                               f"May be used for traffic manipulation.",
                                    severity=Severity.LOW,
                                    confidence=0.6,
                                    attack_id="T1571",
                                    attack_tactic=self.ATTACK_TACTIC,
                                    source_path=filepath,
                                    raw_data={"plugin_type": plugin_type, "file": filepath},
                                    remediation="Verify plugin necessity. Ensure proper RBAC controls on CNI config.",
                                    evidence_details=EvidenceDetail(
                                        content=""
                                    ),
                                    remediation_commands=[
                        "Review Kubernetes RBAC policies and service account permissions",
                        "Audit pod security policies and network policies",
                        "Check for unauthorized container images or deployments",
                        "Verify cloud provider IAM roles and workload identity bindings"
                    ]
                                ))
            except json.JSONDecodeError:
                pass

        except OSError as e:
            _get_logger().debug(f"[{self.name}] Cannot read CNI config {filepath}: {e}")

        return evidences

    def _check_cni_binary(self, filepath: str) -> List[Evidence]:
        """Check CNI binary for tampering"""
        evidences = []
        try:
            stat_info = os.stat(filepath)
            file_size = stat_info.st_size
            
            if file_size == 0:
                evidences.append(self._create_evidence(
                    title="Empty CNI Binary",
                    description=f"CNI binary {filepath} is empty (0 bytes). May indicate tampering.",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    attack_id="T1611",
                    attack_tactic=self.ATTACK_TACTIC,
                    source_path=filepath,
                    raw_data={"file": filepath, "size": file_size},
                    remediation=f"Restore CNI binary from trusted source. Verify package integrity.",
                    evidence_details=EvidenceDetail(
                        content=""
                    ),
                    remediation_commands=[
                        "Review Kubernetes RBAC policies and service account permissions",
                        "Audit pod security policies and network policies",
                        "Check for unauthorized container images or deployments",
                        "Verify cloud provider IAM roles and workload identity bindings"
                    ]
                ))
            
            modified_time = stat_info.st_mtime
            from datetime import datetime
            mod_date = datetime.fromtimestamp(modified_time)
            days_since_mod = (datetime.now() - mod_date).days
            
            if days_since_mod < 7:
                evidences.append(self._create_evidence(
                    title="Recently Modified CNI Binary",
                    description=f"CNI binary {filepath} was modified {days_since_mod} days ago "
                               f"({mod_date.strftime('%Y-%m-%d')}). Recent modification may indicate tampering.",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    attack_id="T1611",
                    attack_tactic=self.ATTACK_TACTIC,
                    source_path=filepath,
                    raw_data={"file": filepath, "modified": mod_date.isoformat(), "days_ago": days_since_mod},
                    remediation="Verify binary modification was part of authorized update. Check package manager logs.",
                    evidence_details=EvidenceDetail(
                        content=""
                    ),
                    remediation_commands=[
                        "Review Kubernetes RBAC policies and service account permissions",
                        "Audit pod security policies and network policies",
                        "Check for unauthorized container images or deployments",
                        "Verify cloud provider IAM roles and workload identity bindings"
                    ]
                ))

        except OSError as e:
            _get_logger().debug(f"[{self.name}] Cannot stat CNI binary {filepath}: {e}")

        return evidences

    def _detect_ebpf_network_hooks(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        """Detect eBPF programs attached to network-related hooks"""
        evidences = []

        bpffs_paths = ['/sys/fs/bpf', '/run/sys/fs/bpf']
        for bpf_path in bpffs_paths:
            if os.path.exists(bpf_path):
                try:
                    for root, dirs, files in os.walk(bpf_path):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            
                            for prog_type, description in self.EBPF_PROGRAM_TYPES.items():
                                if prog_type in filename.lower() or prog_type in filepath.lower():
                                    evidences.append(self._create_evidence(
                                        title=f"eBPF Network Hook Detected: {prog_type}",
                                        description=f"eBPF program found at {filepath}. Type: {description}. "
                                                   f"May be intercepting network traffic.",
                                        severity=Severity.MEDIUM,
                                        confidence=0.7,
                                        attack_id="T1611",
                                        attack_tactic=self.ATTACK_TACTIC,
                                        source_path=filepath,
                                        raw_data={"path": filepath, "type": prog_type, "description": description},
                                        remediation="Verify eBPF program legitimacy. Check if associated with legitimate CNI (Cilium uses eBPF).",
                                        evidence_details=EvidenceDetail(
                                            content=""
                                        ),
                                        remediation_commands=[
                        "Review Kubernetes RBAC policies and service account permissions",
                        "Audit pod security policies and network policies",
                        "Check for unauthorized container images or deployments",
                        "Verify cloud provider IAM roles and workload identity bindings"
                    ]
                                    ))
                except OSError as e:
                    _get_logger().debug(f"[{self.name}] Cannot scan eBPF path {bpf_path}: {e}")

        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            
            ebpf_tools = ['bpftool', 'cilium', 'calico-node', 'tc', 'ip']
            for tool in ebpf_tools:
                if tool in cmdline.lower() or tool in comm.lower():
                    pid = proc.get("pid", 0)
                    evidences.append(self._create_evidence(
                        title=f"eBPF Management Tool Running: {tool}",
                        description=f"Process '{tool}' (PID: {pid}) detected. This tool can manage eBPF programs. "
                                   f"Monitor for unauthorized eBPF operations.",
                        severity=Severity.LOW,
                        confidence=0.6,
                        attack_id="T1611",
                        attack_tactic=self.ATTACK_TACTIC,
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={"pid": pid, "cmdline": cmdline[:200], "tool": tool},
                        remediation="Verify this is a legitimate CNI management process. Check pod specifications.",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            content=proc.get('container_id', '')
                        ),
                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                    ))
                    break

        return evidences

    def _audit_network_policies(self, filesystem_data: dict) -> List[Evidence]:
        """Audit Kubernetes NetworkPolicies for suspicious configurations"""
        evidences = []

        policy_dirs = ['/etc/kubernetes/', '/opt/kubernetes/', '/tmp/', '/home/']
        for base_dir in policy_dirs:
            if not os.path.isdir(base_dir):
                continue

            try:
                for root, dirs, files in os.walk(base_dir):
                    for filename in files:
                        if not filename.endswith(('.yaml', '.yml')):
                            continue
                        
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                                content = f.read()

                            if 'kind: NetworkPolicy' not in content and 'kind: networkpolicy' not in content:
                                continue

                            for pattern, description in self.NETWORK_POLICY_PATTERNS:
                                if pattern.search(content):
                                    severity = Severity.MEDIUM
                                    if '0.0.0.0/0' in description or 'allow-all' in description.lower():
                                        severity = Severity.HIGH

                                    evidences.append(self._create_evidence(
                                        title=f"Network Policy Issue: {description}",
                                        description=f"NetworkPolicy in {filepath}: {description}. "
                                                   f"This may allow unauthorized lateral movement.",
                                        severity=severity,
                                        confidence=0.75,
                                        attack_id="T1562.008",
                                        attack_tactic="Defense Evasion",
                                        source_path=filepath,
                                        raw_data={"file": filepath, "issue": description},
                                        remediation="Apply least-privilege network policies. Avoid allow-all rules. "
                                                   "Use namespace selectors to restrict traffic.",
                                        evidence_details=EvidenceDetail(
                                            content=""
                                        ),
                                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                                    ))
                                    break

                        except OSError:
                            continue
            except OSError:
                continue

        return evidences

    def _analyze_service_mesh_security(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        """Analyze service mesh configurations for security issues"""
        evidences = []

        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        mesh_detected = False
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            
            for pattern, description in self.SIDECAR_INDICATORS:
                if pattern.search(cmdline) or pattern.search(comm):
                    mesh_detected = True
                    pid = proc.get("pid", 0)
                    evidences.append(self._create_evidence(
                        title=f"Service Mesh Component: {description}",
                        description=f"Service mesh component detected in process {pid}: {description}. "
                                   f"Mesh components can be targets for lateral movement.",
                        severity=Severity.LOW,
                        confidence=0.8,
                        attack_id="T1021.007",
                        attack_tactic=self.ATTACK_TACTIC,
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={"pid": pid, "component": description},
                        remediation="Ensure service mesh components are properly secured with mTLS enabled.",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            service_type=proc.get('service', proc.get('timer', ''))
                        ),
                        remediation_commands=[
                        "Stop and disable suspicious service",
                        "Review service configuration and logs",
                        "Check service dependencies and startup order",
                        "Investigate service origin and remove if malicious"
                    ]
                    ))

        if not mesh_detected:
            return evidences

        mesh_config_dirs = ['/etc/istio/', '/etc/linkerd/', '/var/lib/istio/']
        for config_dir in mesh_config_dirs:
            if not os.path.exists(config_dir):
                continue

            try:
                for root, dirs, files in os.walk(config_dir):
                    for filename in files:
                        if not filename.endswith(('.yaml', '.yml', '.json')):
                            continue
                        
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                                content = f.read()

                            for pattern, description, severity in self.MESH_SECURITY_ISSUES:
                                if pattern.search(content):
                                    evidences.append(self._create_evidence(
                                        title=f"Service Mesh Security Issue: {description}",
                                        description=f"Configuration in {filepath}: {description}. "
                                                   f"This weakens service-to-service authentication.",
                                        severity=severity,
                                        confidence=0.8,
                                        attack_id="T1021.007",
                                        attack_tactic=self.ATTACK_TACTIC,
                                        source_path=filepath,
                                        raw_data={"file": filepath, "issue": description},
                                        remediation="Enable strict mTLS mode. Enforce authentication policies. "
                                                   "Disable PERMISSIVE mode in production.",
                                        evidence_details=EvidenceDetail(
                                            content=""
                                        ),
                                        remediation_commands=[
                        "Stop and disable suspicious service",
                        "Review service configuration and logs",
                        "Check service dependencies and startup order",
                        "Investigate service origin and remove if malicious"
                    ]
                                    ))
                                    break

                        except OSError:
                            continue
            except OSError:
                continue

        return evidences

    def _detect_pod_escape_attempts(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        """Detect pod escape attempts via eBPF or privileged configurations"""
        evidences = []

        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)

            for pattern, description in self.POD_ESCAPE_INDICATORS[:3]:
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title=f"Pod Escape Risk: {description}",
                        description=f"Process (PID: {pid}) has {description}. "
                                   f"This capability can be used for container escape.",
                        severity=Severity.CRITICAL if 'SYS_ADMIN' in description else Severity.HIGH,
                        confidence=0.85,
                        attack_id="T1611",
                        attack_tactic=self.ATTACK_TACTIC,
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={"pid": pid, "cmdline": cmdline[:200], "risk": description},
                        remediation="Remove unnecessary capabilities from pod spec. Use securityContext with drop: ALL.",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            content=proc.get('container_id', '')
                        ),
                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                    ))

            sensitive_mounts = ['/proc', '/sys/fs/bpf', '/var/run/docker.sock']
            for mount in sensitive_mounts:
                if mount in cmdline:
                    evidences.append(self._create_evidence(
                        title=f"Sensitive Mount in Container: {mount}",
                        description=f"Process (PID: {pid}) accessing sensitive path {mount}. "
                                   f"This may indicate pod escape attempt.",
                        severity=Severity.CRITICAL if 'docker.sock' in mount else Severity.HIGH,
                        confidence=0.8,
                        attack_id="T1611",
                        attack_tactic=self.ATTACK_TACTIC,
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={"pid": pid, "mount": mount},
                        remediation="Avoid mounting sensitive host paths into containers. Use read-only mounts when necessary.",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            content=proc.get('container_id', '')
                        ),
                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                    ))

        yaml_dirs = ['/etc/kubernetes/', '/opt/', '/tmp/']
        for base_dir in yaml_dirs:
            if not os.path.isdir(base_dir):
                continue

            try:
                for root, dirs, files in os.walk(base_dir):
                    for filename in files:
                        if not filename.endswith(('.yaml', '.yml')):
                            continue
                        
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                                content = f.read()

                            if 'kind: Pod' not in content and 'kind: Deployment' not in content:
                                continue

                            for pattern, description in self.POD_ESCAPE_INDICATORS[3:]:
                                if pattern.search(content):
                                    evidences.append(self._create_evidence(
                                        title=f"Pod Spec Security Issue: {description}",
                                        description=f"Pod specification in {filepath}: {description}. "
                                                   f"This configuration enables pod escape.",
                                        severity=Severity.HIGH,
                                        confidence=0.8,
                                        attack_id="T1611",
                                        attack_tactic=self.ATTACK_TACTIC,
                                        source_path=filepath,
                                        raw_data={"file": filepath, "issue": description},
                                        remediation="Disable host namespace sharing unless absolutely necessary. "
                                                   "Set hostPID/hostNetwork/hostIPC to false.",
                                        evidence_details=EvidenceDetail(
                                            content=""
                                        ),
                                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                                    ))
                                    break

                        except OSError:
                            continue
            except OSError:
                continue

        return evidences

    def _monitor_lateral_movement_commands(self, process_data: dict) -> List[Evidence]:
        """Monitor for kubectl/istioctl commands used for lateral movement"""
        evidences = []

        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)

            for pattern, description in self.LATERAL_MOVEMENT_COMMANDS:
                if pattern.search(cmdline):
                    severity = Severity.MEDIUM
                    if 'exec' in description.lower() or 'cp' in description.lower():
                        severity = Severity.HIGH

                    evidences.append(self._create_evidence(
                        title=f"Lateral Movement Command: {description}",
                        description=f"Command detected in process {pid}: {description}. "
                                   f"Cmdline: {cmdline[:150]}",
                        severity=severity,
                        confidence=0.75,
                        attack_id="T1021.007",
                        attack_tactic=self.ATTACK_TACTIC,
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={"pid": pid, "cmdline": cmdline[:200], "command_type": description},
                        remediation="Audit kubectl command usage. Implement RBAC restrictions. "
                                   "Use audit logging for kubectl exec/port-forward commands.",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            content=proc.get('container_id', '')
                        ),
                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                    ))
                    break

        return evidences

    def _create_evidence(self, title: str, description: str, severity: Severity,
                        confidence: float, attack_id: str, attack_tactic: str,
                        source_path: str, raw_data: dict, remediation: str,
                        evidence_details=None, remediation_commands=None) -> Evidence:
        """Create evidence with consistent formatting"""
        from datetime import datetime, timezone
        
        timestamp = datetime.now(timezone.utc).isoformat()
        
        return Evidence(
            id=f"{self.name}_{self._evidence_counter}",
            module=self.name,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            attack_id=attack_id,
            attack_tactic=attack_tactic,
            source_path=source_path,
            raw_data=raw_data,
            remediation=remediation,
            verified_status="unverified",
            timestamp=timestamp,
            evidence_details=evidence_details,
            remediation_commands=remediation_commands or []
        )
