"""K8s Runtime Behavior Baseline Analyzer

Detects anomalous Kubernetes runtime behavior by analyzing:
- Operation frequency anomalies (sliding window counters with process timestamps)
- API call sequence patterns (attack chain detection with enhanced patterns)
- Time-based anomalies (off-hours operations with CI/CD schedule awareness)
- User behavior deviations from established baselines
- Namespace-level anomaly detection (cross-namespace access, system namespace protection)

ATT&CK Mapping:
- T1611 - Escape to Host (container escape via K8s)
- T1021.008 - Lateral Movement via Kubernetes API
- T1098 - Account Manipulation (service account abuse)
- T1136.003 - Create Account via Kubernetes
- T1078.004 - Valid Accounts: Cloud Accounts
- T1611 - Container Escape via namespace traversal
"""
import re
import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict

from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer

logger = logging.getLogger("sec-userspace")


class SlidingWindowCounter:
    """Sliding window counter for frequency analysis."""

    def __init__(self, window_seconds: int = 600):
        self._window = window_seconds
        self._events: List[float] = []

    def add_event(self, timestamp: float = None):
        if timestamp is None:
            timestamp = time.time()
        self._events.append(timestamp)
        self._cleanup(timestamp)

    def count(self, current_time: float = None) -> int:
        if current_time is None:
            current_time = time.time()
        self._cleanup(current_time)
        return len(self._events)

    def get_events_in_window(self, current_time: float = None) -> List[float]:
        """Get all events within the current window."""
        if current_time is None:
            current_time = time.time()
        self._cleanup(current_time)
        return list(self._events)

    def _cleanup(self, current_time: float):
        cutoff = current_time - self._window
        self._events = [t for t in self._events if t > cutoff]


class K8sOperationClassifier:
    """Classifies K8s operations from process cmdlines."""

    K8S_OPERATIONS = {
        'exec': re.compile(r'kubectl\b.*\bexec\s+', re.IGNORECASE),
        'debug': re.compile(r'kubectl\b.*\bdebug\s+', re.IGNORECASE),
        'apply': re.compile(r'kubectl\b.*\bapply\s+', re.IGNORECASE),
        'create': re.compile(r'kubectl\b.*\bcreate\s+', re.IGNORECASE),
        'delete': re.compile(r'kubectl\b.*\bdelete\s+', re.IGNORECASE),
        'get_secrets': re.compile(r'kubectl\b.*\bget\s+(?:secrets?|secret)\s+', re.IGNORECASE),
        'get_all': re.compile(r'kubectl\b.*\bget\s+(?:all|pods?|deployments?|services?)\s+', re.IGNORECASE),
        'describe': re.compile(r'kubectl\b.*\bdescribe\s+', re.IGNORECASE),
        'logs': re.compile(r'kubectl\b.*\blogs\s+', re.IGNORECASE),
        'port_forward': re.compile(r'kubectl\b.*\bport-forward\s+', re.IGNORECASE),
        'cp': re.compile(r'kubectl\b.*\bcp\s+', re.IGNORECASE),
        'auth_can_i': re.compile(r'kubectl\b.*\bauth\s+can-i\s+', re.IGNORECASE),
        'get_sa': re.compile(r'kubectl\b.*\bget\s+serviceaccounts?\s+', re.IGNORECASE),
        'get_role': re.compile(r'kubectl\b.*\bget\s+(?:cluster)?roles?\b', re.IGNORECASE),
        'get_clusterrolebinding': re.compile(r'kubectl\b.*\bget\s+clusterrolebindings?\s+', re.IGNORECASE),
        'impersonate': re.compile(r'kubectl\b.*--as\s+', re.IGNORECASE),
        'run_privileged': re.compile(r'kubectl\b.*\brun\s+.*--privileged', re.IGNORECASE),
        'token_create': re.compile(r'kubectl\b.*\bcreate\s+token\s+', re.IGNORECASE),
    }

    ATTACK_CHAIN_PATTERNS = [
        {
            'name': 'recon_to_exec',
            'description': 'Reconnaissance followed by pod exec',
            'sequence': ['auth_can_i', 'get_secrets', 'exec'],
            'severity': Severity.CRITICAL,
            'attack_id': 'T1611',
            'tactic': 'Lateral Movement',
        },
        {
            'name': 'credential_access_chain',
            'description': 'Secret enumeration followed by token operations',
            'sequence': ['get_secrets', 'token_create', 'impersonate'],
            'severity': Severity.CRITICAL,
            'attack_id': 'T1098',
            'tactic': 'Credential Access',
        },
        {
            'name': 'debug_escape',
            'description': 'Debug pod creation followed by exec',
            'sequence': ['debug', 'exec', 'cp'],
            'severity': Severity.CRITICAL,
            'attack_id': 'T1611',
            'tactic': 'Execution',
        },
        {
            'name': 'persistence_chain',
            'description': 'Resource creation followed by deployment operations',
            'sequence': ['create', 'apply', 'port_forward'],
            'severity': Severity.HIGH,
            'attack_id': 'T1136.003',
            'tactic': 'Persistence',
        },
        {
            'name': 'rbac_escalation',
            'description': 'RBAC enumeration followed by privilege escalation',
            'sequence': ['get_role', 'get_clusterrolebinding', 'create'],
            'severity': Severity.HIGH,
            'attack_id': 'T1078.004',
            'tactic': 'Privilege Escalation',
        },
        {
            'name': 'secret_exfiltration_chain',
            'description': 'Secret access followed by data transfer operations',
            'sequence': ['get_secrets', 'describe', 'cp'],
            'severity': Severity.CRITICAL,
            'attack_id': 'T1552.004',
            'tactic': 'Credential Access',
        },
        {
            'name': 'namespace_hopping',
            'description': 'Cross-namespace reconnaissance and execution',
            'sequence': ['get_all', 'auth_can_i', 'exec'],
            'severity': Severity.HIGH,
            'attack_id': 'T1021.008',
            'tactic': 'Lateral Movement',
        },
        {
            'name': 'token_theft_chain',
            'description': 'Service account token theft and usage',
            'sequence': ['get_sa', 'token_create', 'exec'],
            'severity': Severity.CRITICAL,
            'attack_id': 'T1552.001',
            'tactic': 'Credential Access',
        },
    ]

    CI_CD_PATTERNS = [
        re.compile(r'jenkins', re.IGNORECASE),
        re.compile(r'gitlab-runner', re.IGNORECASE),
        re.compile(r'argocd', re.IGNORECASE),
        re.compile(r'flux', re.IGNORECASE),
        re.compile(r'tekton', re.IGNORECASE),
        re.compile(r'github-actions', re.IGNORECASE),
        re.compile(r'circleci', re.IGNORECASE),
        re.compile(r'concourse', re.IGNORECASE),
        re.compile(r'drone', re.IGNORECASE),
        re.compile(r'spack', re.IGNORECASE),
    ]

    CI_CD_ENV_PATTERNS = [
        re.compile(r'CI=true', re.IGNORECASE),
        re.compile(r'GITLAB_CI=', re.IGNORECASE),
        re.compile(r'GITHUB_ACTIONS=', re.IGNORECASE),
        re.compile(r'JENKINS_URL=', re.IGNORECASE),
        re.compile(r'CIRCLECI=', re.IGNORECASE),
        re.compile(r'ARGOCD_', re.IGNORECASE),
        re.compile(r'TEKTON_', re.IGNORECASE),
    ]

    K8S_ADMIN_PATTERNS = [
        re.compile(r'kubernetes-admin', re.IGNORECASE),
        re.compile(r'system:admin', re.IGNORECASE),
        re.compile(r'cluster-admin', re.IGNORECASE),
        re.compile(r'--user\s+system:admin', re.IGNORECASE),
    ]

    SUSPICIOUS_USERS = {
        'www-data', 'nobody', 'nginx', 'apache', 'httpd',
        'mysql', 'postgres', 'redis', 'memcache',
        'daemon', 'bin', 'sys', 'sync', 'games',
    }

    def classify_operation(self, cmdline: str) -> List[str]:
        """Classify a cmdline into K8s operation types."""
        operations = []
        for op_name, pattern in self.K8S_OPERATIONS.items():
            if pattern.search(cmdline):
                operations.append(op_name)
        return operations

    def is_cicd_context(self, cmdline: str, environ: str = '') -> bool:
        """Check if operation is from CI/CD pipeline."""
        text = f"{cmdline} {environ}"
        if any(p.search(text) for p in self.CI_CD_PATTERNS):
            return True
        return any(p.search(environ) for p in self.CI_CD_ENV_PATTERNS)

    def is_admin_user(self, cmdline: str) -> bool:
        """Check if operation is from known admin user."""
        return any(p.search(cmdline) for p in self.K8S_ADMIN_PATTERNS)

    def is_suspicious_user(self, cmdline: str) -> bool:
        """Check if operation is from suspicious user."""
        user_match = re.search(r'--user\s+(\S+)', cmdline)
        if user_match:
            user = user_match.group(1)
            return user.lower() in self.SUSPICIOUS_USERS

        runas_match = re.search(r'--run-as-user\s+(\S+)', cmdline)
        if runas_match:
            user = runas_match.group(1)
            return user.lower() in self.SUSPICIOUS_USERS

        return False


class K8sRuntimeBehaviorAnalyzer(BaseAnalyzer):
    """Analyzes K8s runtime behavior for anomalies."""

    name = "k8s_runtime_behavior_analyzer"
    timeout = 45
    estimated_time = 2.0
    analyzer_type = "important"
    required_collectors = ["process"]

    ATTACK_ID = "T1611"
    ATTACK_TACTIC = "Lateral Movement"

    FREQUENCY_THRESHOLDS = {
        'exec': {'warning': 10, 'critical': 30, 'window': 600},
        'debug': {'warning': 5, 'critical': 15, 'window': 600},
        'apply': {'warning': 20, 'critical': 50, 'window': 600},
        'create': {'warning': 15, 'critical': 40, 'window': 600},
        'get_secrets': {'warning': 5, 'critical': 15, 'window': 600},
        'auth_can_i': {'warning': 20, 'critical': 50, 'window': 600},
        'token_create': {'warning': 3, 'critical': 10, 'window': 600},
        'impersonate': {'warning': 3, 'critical': 8, 'window': 600},
        'port_forward': {'warning': 10, 'critical': 25, 'window': 600},
        'cp': {'warning': 5, 'critical': 15, 'window': 600},
    }

    OFF_HOURS_START = 22
    OFF_HOURS_END = 6
    WEEKEND_MULT = 2

    CI_CD_SCHEDULED_NAMESPACES = {
        'ci-cd', 'cicd', 'pipeline', 'build', 'jenkins', 'gitlab',
        'argocd', 'flux-system', 'tekton-pipelines',
    }

    SYSTEM_NAMESPACES = {
        'kube-system', 'kube-public', 'kube-node-lease',
        'istio-system', 'linkerd', 'calico-system', 'tigera-operator',
        'cert-manager', 'ingress-nginx', 'monitoring', 'logging',
    }

    HIGH_RISK_SYSTEM_NS_OPS = {
        'kube-system': {'exec', 'debug', 'create', 'delete', 'apply', 'cp'},
        'istio-system': {'exec', 'debug', 'create', 'delete', 'apply'},
        'calico-system': {'exec', 'debug', 'create', 'delete'},
        'cert-manager': {'exec', 'debug', 'create', 'delete'},
    }

    NAMESPACE_HOP_THRESHOLD = 5
    NAMESPACE_CREATION_THRESHOLD = 10
    SYSTEM_NS_ACCESS_THRESHOLD = 3

    CLUSTER_SIZE_THRESHOLDS = {
        'small': {'max_pods': 50, 'multiplier': 1.0},
        'medium': {'max_pods': 200, 'multiplier': 2.0},
        'large': {'max_pods': 999999, 'multiplier': 3.0},
    }

    OPERATION_INTERVAL_THRESHOLDS = {
        'batch_script_max_interval': 1.0,
        'manual_operation_min_interval': 5.0,
        'batch_confidence_boost': 0.15,
        'manual_confidence_reduction': 0.10,
    }

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        if not self.has_k8s():
            return True, "Not a Kubernetes environment"
        return False, ""

    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Analyze K8s runtime behavior for anomalies."""
        evidences = []

        if not self._is_kubernetes_environment(collected_data):
            return evidences

        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            return evidences

        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        kubectl_processes = self._extract_kubectl_processes(processes)

        if not kubectl_processes:
            return evidences

        classifier = K8sOperationClassifier()

        cluster_size = self._estimate_cluster_size(processes)
        threshold_multiplier = self._get_threshold_multiplier(cluster_size)

        evidences.extend(self._check_frequency_anomalies(kubectl_processes, classifier, cluster_size, threshold_multiplier))
        evidences.extend(self._check_attack_chains(kubectl_processes, classifier))
        evidences.extend(self._check_time_anomalies(kubectl_processes, classifier))
        evidences.extend(self._check_user_behavior(kubectl_processes, classifier))
        evidences.extend(self._check_namespace_anomalies(kubectl_processes, classifier))

        return evidences

    def _parse_process_start_time(self, proc: Dict) -> Optional[float]:
        """Extract process start time from process data.

        Tries multiple fields: start_time, starttime, boot_time, etc.
        Falls back to None if not available.
        """
        for field in ['start_time', 'starttime', 'boot_time', 'start', 'created']:
            if field in proc:
                try:
                    return float(proc[field])
                except (ValueError, TypeError):
                    continue
        return None

    def _estimate_cluster_size(self, processes: List[Dict]) -> str:
        """Estimate cluster size based on process information.
        
        Uses namespace diversity and node indicators to estimate cluster size.
        Returns cluster size category: 'small', 'medium', or 'large'.
        """
        pod_namespaces = set()
        node_indicators = 0
        
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            ns = self._extract_namespace_from_cmdline(cmdline)
            if ns:
                pod_namespaces.add(ns)
            
            if 'kubelet' in cmdline or 'node/' in cmdline.lower():
                node_indicators += 1
        
        unique_namespaces = len(pod_namespaces)
        
        if unique_namespaces <= 5 and node_indicators <= 3:
            return 'small'
        elif unique_namespaces <= 15 and node_indicators <= 10:
            return 'medium'
        else:
            return 'large'

    def _get_threshold_multiplier(self, cluster_size: str) -> float:
        """Get threshold multiplier based on cluster size."""
        return self.CLUSTER_SIZE_THRESHOLDS.get(cluster_size, {}).get('multiplier', 1.0)

    def _analyze_operation_intervals(self, processes: List[Dict]) -> Dict[str, Any]:
        """Analyze operation intervals to distinguish batch scripts from manual operations.
        
        Returns interval analysis results with classification.
        """
        if len(processes) < 2:
            return {'classification': 'insufficient_data', 'avg_interval': 0.0, 'confidence_adjustment': 0.0}
        
        timestamps = []
        for proc in processes:
            ts = self._parse_process_start_time(proc)
            if ts is not None:
                timestamps.append(ts)
        
        if len(timestamps) < 2:
            return {'classification': 'insufficient_data', 'avg_interval': 0.0, 'confidence_adjustment': 0.0}
        
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return {'classification': 'insufficient_data', 'avg_interval': 0.0, 'confidence_adjustment': 0.0}
        
        avg_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
        
        batch_threshold = self.OPERATION_INTERVAL_THRESHOLDS['batch_script_max_interval']
        manual_threshold = self.OPERATION_INTERVAL_THRESHOLDS['manual_operation_min_interval']
        
        if avg_interval < batch_threshold and min_interval < batch_threshold:
            classification = 'batch_script'
            confidence_adjustment = self.OPERATION_INTERVAL_THRESHOLDS['batch_confidence_boost']
        elif avg_interval > manual_threshold:
            classification = 'manual_operation'
            confidence_adjustment = -self.OPERATION_INTERVAL_THRESHOLDS['manual_confidence_reduction']
        else:
            classification = 'unknown'
            confidence_adjustment = 0.0
        
        return {
            'classification': classification,
            'avg_interval': round(avg_interval, 2),
            'min_interval': round(min_interval, 2),
            'confidence_adjustment': confidence_adjustment,
        }

    def _is_kubernetes_environment(self, collected_data: Dict[str, Any]) -> bool:
        """Check if this is a K8s environment."""
        try:
            process_data = self._get_data(collected_data, "process")
            if isinstance(process_data, dict):
                processes = process_data.get("processes", [])
                for proc in processes:
                    cmdline = proc.get("cmdline") or ""
                    if any(k in cmdline for k in ['kubelet', 'kube-apiserver', 'kube-proxy', 'kube-scheduler']):
                        return True
        except KeyError:
            pass
        return False

    def _extract_kubectl_processes(self, processes: List[Dict]) -> List[Dict]:
        """Extract kubectl-related processes."""
        kubectl_procs = []
        kubectl_pattern = re.compile(r'kubectl\s+', re.IGNORECASE)

        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if kubectl_pattern.search(cmdline):
                kubectl_procs.append(proc)

        return kubectl_procs

    def _check_frequency_anomalies(
        self, kubectl_processes: List[Dict], classifier: K8sOperationClassifier,
        cluster_size: str = None, threshold_multiplier: float = None
    ) -> List[Evidence]:
        """Check for frequency anomalies in K8s operations using sliding window.
        
        Uses dynamic thresholds based on cluster size and operation interval
        analysis to distinguish batch scripts from manual operations.
        """
        evidences = []
        operation_counters: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(window_seconds=600)
        )
        operation_procs: Dict[str, List[Dict]] = defaultdict(list)

        current_time = time.time()
        max_start_time = 0.0

        for proc in kubectl_processes:
            start_time = self._parse_process_start_time(proc)
            if start_time is not None and start_time > max_start_time:
                max_start_time = start_time

        reference_time = max_start_time if max_start_time > 0 else current_time

        for proc in kubectl_processes:
            cmdline = proc.get("cmdline", "")
            if classifier.is_cicd_context(cmdline, proc.get("environ", "")):
                continue

            operations = classifier.classify_operation(cmdline)
            start_time = self._parse_process_start_time(proc)

            for op in operations:
                if start_time is not None:
                    operation_counters[op].add_event(timestamp=start_time)
                else:
                    operation_counters[op].add_event(timestamp=reference_time)
                operation_procs[op].append(proc)

        cluster_size = cluster_size or self._estimate_cluster_size(kubectl_processes)
        threshold_multiplier = threshold_multiplier or self._get_threshold_multiplier(cluster_size)
        interval_analysis = self._analyze_operation_intervals(kubectl_processes)

        for op_name, counter in operation_counters.items():
            if op_name not in self.FREQUENCY_THRESHOLDS:
                continue

            base_threshold = self.FREQUENCY_THRESHOLDS[op_name]
            adjusted_warning = int(base_threshold['warning'] * threshold_multiplier)
            adjusted_critical = int(base_threshold['critical'] * threshold_multiplier)
            
            count = counter.count(current_time=reference_time)
            procs = operation_procs[op_name]

            base_confidence_critical = 0.85
            base_confidence_warning = 0.70
            
            if interval_analysis['classification'] == 'batch_script':
                base_confidence_critical = min(base_confidence_critical + interval_analysis['confidence_adjustment'], 0.95)
                base_confidence_warning = min(base_confidence_warning + interval_analysis['confidence_adjustment'], 0.90)
            elif interval_analysis['classification'] == 'manual_operation':
                base_confidence_critical = max(base_confidence_critical + interval_analysis['confidence_adjustment'], 0.60)
                base_confidence_warning = max(base_confidence_warning + interval_analysis['confidence_adjustment'], 0.50)

            if count >= adjusted_critical:
                evidences.append(self._create_evidence(
                    title=f"K8s Critical Frequency Anomaly: {op_name}",
                    description=f"Detected {count} {op_name} operations within {base_threshold['window']}s window, threshold is {adjusted_critical} (cluster: {cluster_size}, multiplier: {threshold_multiplier}x)",
                    severity=Severity.CRITICAL,
                    confidence=base_confidence_critical,
                    attack_id="T1611",
                    attack_tactic="Execution",
                    source_path="/proc/{pid}/cmdline",
                    raw_data={
                        "operation": op_name,
                        "count": count,
                        "threshold": adjusted_critical,
                        "base_threshold": base_threshold['critical'],
                        "cluster_size": cluster_size,
                        "threshold_multiplier": threshold_multiplier,
                        "window_seconds": base_threshold['window'],
                        "interval_classification": interval_analysis.get('classification', 'unknown'),
                        "sample_cmdlines": [p.get("cmdline", "")[:200] for p in procs[:5]],
                    },
                    remediation=f"Investigate high-frequency {op_name} operations. Check for automated attack scripts or compromised credentials.",
                    evidence_details=EvidenceDetail(
                        pid=procs[0].get('pid', 0) if procs else 0,
                        cmdline=procs[0].get('cmdline', '')[:300] if procs else '',
                        executable=procs[0].get('exe', '') if procs else '',
                        file_path=procs[0].get('file_path', procs[0].get('path', '')) if procs else '',
                        remote_address=procs[0].get('remote_address', procs[0].get('ip', '')) if procs else '',
                        connection_state=procs[0].get('state', '') if procs else '',
                        credential_type=procs[0].get('type', 'unknown') if procs else 'unknown'
                    ),
                    remediation_commands=[
                        "Rotate compromised credential immediately",
                        "Review access logs for unauthorized usage",
                        "Audit credential storage and usage patterns",
                        "Check other systems for credential reuse"
                    ]
                ))
            elif count >= adjusted_warning:
                evidences.append(self._create_evidence(
                    title=f"K8s Warning Frequency Anomaly: {op_name}",
                    description=f"Detected {count} {op_name} operations within {base_threshold['window']}s window, warning threshold is {adjusted_warning} (cluster: {cluster_size}, multiplier: {threshold_multiplier}x)",
                    severity=Severity.MEDIUM,
                    confidence=base_confidence_warning,
                    attack_id="T1611",
                    attack_tactic="Execution",
                    source_path="/proc/{pid}/cmdline",
                    raw_data={
                        "operation": op_name,
                        "count": count,
                        "threshold": adjusted_warning,
                        "base_threshold": base_threshold['warning'],
                        "cluster_size": cluster_size,
                        "threshold_multiplier": threshold_multiplier,
                        "window_seconds": base_threshold['window'],
                        "interval_classification": interval_analysis.get('classification', 'unknown'),
                        "sample_cmdlines": [p.get("cmdline", "")[:200] for p in procs[:5]],
                    },
                    remediation=f"Monitor {op_name} operation frequency. May indicate reconnaissance or automated abuse.",
                    evidence_details=EvidenceDetail(
                        pid=procs[0].get('pid', 0) if procs else 0,
                        cmdline=procs[0].get('cmdline', '')[:300] if procs else '',
                        executable=procs[0].get('exe', '') if procs else '',
                        file_path=procs[0].get('file_path', procs[0].get('path', '')) if procs else '',
                        remote_address=procs[0].get('remote_address', procs[0].get('ip', '')) if procs else '',
                        connection_state=procs[0].get('state', '') if procs else ''
                    ),
                    remediation_commands=[
                        "Review Kubernetes RBAC policies and service account permissions",
                        "Audit pod security policies and network policies",
                        "Check for unauthorized container images or deployments",
                        "Verify cloud provider IAM roles and workload identity bindings"
                    ]
                ))

        return evidences

    def _check_attack_chains(
        self, kubectl_processes: List[Dict], classifier: K8sOperationClassifier
    ) -> List[Evidence]:
        """Detect attack chain patterns in K8s API call sequences.

        Uses sliding window approach to detect sequences of operations
        that match known attack patterns. CI/CD operations are excluded.
        """
        evidences = []

        sorted_procs = sorted(kubectl_processes, key=lambda p: p.get("pid", 0))

        filtered_procs = []
        for proc in sorted_procs:
            cmdline = proc.get("cmdline", "")
            if not classifier.is_cicd_context(cmdline, proc.get("environ", "")):
                filtered_procs.append(proc)

        if len(filtered_procs) < 2:
            return evidences

        detected_chains = set()

        for chain_pattern in K8sOperationClassifier.ATTACK_CHAIN_PATTERNS:
            sequence = chain_pattern['sequence']
            seq_len = len(sequence)

            for i in range(len(filtered_procs) - seq_len + 1):
                window = filtered_procs[i:i + seq_len]
                operations = []
                for proc in window:
                    ops = classifier.classify_operation(proc.get("cmdline", ""))
                    operations.extend(ops)

                matched_ops = [op for op in sequence if op in operations]
                if len(matched_ops) >= 2:
                    match_ratio = len(matched_ops) / seq_len
                    if match_ratio >= 0.6:
                        chain_key = chain_pattern['name']
                        if chain_key not in detected_chains:
                            detected_chains.add(chain_key)

                            confidence = 0.80 if match_ratio >= 0.8 else 0.65

                            if classifier.is_suspicious_user(window[0].get("cmdline", "")):
                                confidence = min(confidence + 0.10, 0.95)

                            evidences.append(self._create_evidence(
                                title=f"K8s Attack Chain Detected: {chain_pattern['description']}",
                                description=f"Detected K8s API call sequence matching attack pattern: {', '.join(sequence)}",
                                severity=chain_pattern['severity'],
                                confidence=confidence,
                                attack_id=chain_pattern['attack_id'],
                                attack_tactic=chain_pattern['tactic'],
                                source_path="/proc/{pid}/cmdline",
                                raw_data={
                                    "chain_name": chain_key,
                                    "matched_operations": matched_ops,
                                    "expected_sequence": sequence,
                                    "match_ratio": round(match_ratio, 2),
                                    "sample_cmdlines": [p.get("cmdline", "")[:200] for p in window],
                                },
                                remediation=f"Investigate attack chain pattern: {chain_pattern['description']}. Check for credential compromise and lateral movement.",
                                evidence_details=EvidenceDetail(
                                    pid=window[0].get('pid', 0),
                                    cmdline=window[0].get('cmdline', '')[:300],
                                    executable=window[0].get('exe', ''),
                                    file_path=window[0].get('file_path', window[0].get('path', '')),
                                    remote_address=window[0].get('remote_address', window[0].get('ip', '')),
                                    connection_state=window[0].get('state', ''),
                                    credential_type=window[0].get('type', 'unknown')
                                ),
                                remediation_commands=[
                        "Rotate compromised credential immediately",
                        "Review access logs for unauthorized usage",
                        "Audit credential storage and usage patterns",
                        "Check other systems for credential reuse"
                    ]
                            ))
                        break

        return evidences

    def _check_time_anomalies(
        self, kubectl_processes: List[Dict], classifier: K8sOperationClassifier
    ) -> List[Evidence]:
        """Detect K8s operations during off-hours with CI/CD schedule awareness."""
        evidences = []
        off_hours_ops = []

        current_hour = datetime.now().hour
        current_weekday = datetime.now().weekday()
        is_weekend = current_weekday >= 5

        for proc in kubectl_processes:
            cmdline = proc.get("cmdline", "")
            if classifier.is_cicd_context(cmdline, proc.get("environ", "")):
                continue

            namespace = self._extract_namespace_from_cmdline(cmdline)
            if namespace and namespace.lower() in self.CI_CD_SCHEDULED_NAMESPACES:
                continue

            is_off_hours = (
                current_hour >= self.OFF_HOURS_START or
                current_hour < self.OFF_HOURS_END
            )

            if is_off_hours or is_weekend:
                off_hours_ops.append({
                    "cmdline": cmdline,
                    "pid": proc.get("pid", 0),
                    "time_context": "weekend" if is_weekend else "off_hours",
                    "namespace": namespace,
                })

        if off_hours_ops:
            severity = Severity.HIGH if len(off_hours_ops) > 5 else Severity.MEDIUM
            confidence = 0.75 if len(off_hours_ops) > 10 else 0.60

            has_suspicious_user = any(
                classifier.is_suspicious_user(op["cmdline"])
                for op in off_hours_ops
            )
            if has_suspicious_user:
                confidence = min(confidence + 0.15, 0.95)
                severity = Severity.HIGH

            evidences.append(self._create_evidence(
                title=f"K8s Off-Hours Operation Detected",
                description=f"Detected {len(off_hours_ops)} K8s operations during off-hours ({'weekend' if is_weekend else f'hour {current_hour}'})",
                severity=severity,
                confidence=confidence,
                attack_id="T1611",
                attack_tactic="Lateral Movement",
                source_path="/proc/{pid}/cmdline",
                raw_data={
                    "off_hours_count": len(off_hours_ops),
                    "current_hour": current_hour,
                    "is_weekend": is_weekend,
                    "sample_cmdlines": [op["cmdline"][:200] for op in off_hours_ops[:5]],
                },
                remediation="Verify off-hours K8s operations are authorized. Check change management records for planned maintenance.",
                evidence_details=EvidenceDetail(
                    pid=off_hours_ops[0].get('pid', 0) if off_hours_ops else 0,
                    cmdline=off_hours_ops[0].get('cmdline', '')[:300] if off_hours_ops else '',
                    executable=off_hours_ops[0].get('exe', '') if off_hours_ops else '',
                    file_path=off_hours_ops[0].get('file_path', off_hours_ops[0].get('path', '')) if off_hours_ops else '',
                    remote_address=off_hours_ops[0].get('remote_address', off_hours_ops[0].get('ip', '')) if off_hours_ops else '',
                    connection_state=off_hours_ops[0].get('state', '') if off_hours_ops else ''
                ),
                remediation_commands=[
                        "Review Kubernetes RBAC policies and service account permissions",
                        "Audit pod security policies and network policies",
                        "Check for unauthorized container images or deployments",
                        "Verify cloud provider IAM roles and workload identity bindings"
                    ]
            ))
        return evidences

    def _extract_namespace_from_cmdline(self, cmdline: str) -> Optional[str]:
        """Extract namespace from kubectl command line arguments."""
        match = re.search(r'(?:-n\s+|--namespace[=\s])(\S+)', cmdline)
        if match:
            return match.group(1)
        match = re.search(r'--all-namespaces', cmdline)
        if match:
            return '*'
        return None

    def _check_user_behavior(
        self, kubectl_processes: List[Dict], classifier: K8sOperationClassifier
    ) -> List[Evidence]:
        """Detect suspicious user behavior in K8s operations."""
        evidences = []
        suspicious_ops = []

        for proc in kubectl_processes:
            cmdline = proc.get("cmdline", "")
            if classifier.is_cicd_context(cmdline, proc.get("environ", "")):
                continue

            if classifier.is_suspicious_user(cmdline):
                operations = classifier.classify_operation(cmdline)
                suspicious_ops.append({
                    "cmdline": cmdline,
                    "pid": proc.get("pid", 0),
                    "operations": operations,
                })

        if suspicious_ops:
            has_write_ops = any(
                op in ops_entry["operations"]
                for ops_entry in suspicious_ops
                for op in ['exec', 'create', 'apply', 'delete', 'debug', 'cp']
            )
            severity = Severity.CRITICAL if has_write_ops else Severity.HIGH
            confidence = 0.80 if len(suspicious_ops) > 3 else 0.70

            evidences.append(self._create_evidence(
                title="K8s Suspicious User Activity",
                description=f"Detected {len(suspicious_ops)} K8s operations from suspicious service accounts (e.g., www-data, nobody)",
                severity=severity,
                confidence=confidence,
                attack_id="T1078.004",
                attack_tactic="Privilege Escalation",
                source_path="/proc/{pid}/cmdline",
                raw_data={
                    "suspicious_count": len(suspicious_ops),
                    "has_write_operations": has_write_ops,
                    "sample_cmdlines": [op["cmdline"][:200] for op in suspicious_ops[:5]],
                },
                remediation="Investigate kubectl usage from non-human service accounts. These accounts should not normally interact with the K8s API.",
                evidence_details=EvidenceDetail(
                    pid=suspicious_ops[0].get('pid', 0),
                    cmdline=suspicious_ops[0].get('cmdline', '')[:300],
                ),
                remediation_commands=[
                    "Review RBAC bindings for suspicious service accounts",
                    "Check for compromised pods running kubectl",
                    "Audit service account token mounts in pod specs",
                ]
            ))

        return evidences

    def _check_namespace_anomalies(
        self, kubectl_processes: List[Dict], classifier: K8sOperationClassifier
    ) -> List[Evidence]:
        """Detect namespace-level anomalies: cross-namespace hopping and system namespace access."""
        evidences = []
        namespaces_accessed: Dict[str, List[Dict]] = defaultdict(list)
        system_ns_ops: List[Dict] = []

        for proc in kubectl_processes:
            cmdline = proc.get("cmdline", "")
            if classifier.is_cicd_context(cmdline, proc.get("environ", "")):
                continue

            namespace = self._extract_namespace_from_cmdline(cmdline)
            if not namespace:
                continue

            namespaces_accessed[namespace].append(proc)

            if namespace in self.SYSTEM_NAMESPACES:
                operations = classifier.classify_operation(cmdline)
                high_risk = self.HIGH_RISK_SYSTEM_NS_OPS.get(namespace, set())
                if any(op in high_risk for op in operations):
                    system_ns_ops.append({
                        "cmdline": cmdline,
                        "pid": proc.get("pid", 0),
                        "namespace": namespace,
                        "operations": operations,
                    })

        unique_ns_count = len(namespaces_accessed)
        if unique_ns_count >= self.NAMESPACE_HOP_THRESHOLD:
            evidences.append(self._create_evidence(
                title="K8s Namespace Hopping Detected",
                description=f"Single session accessed {unique_ns_count} distinct namespaces (threshold: {self.NAMESPACE_HOP_THRESHOLD}), possible lateral movement",
                severity=Severity.HIGH,
                confidence=0.70,
                attack_id="T1021.008",
                attack_tactic="Lateral Movement",
                source_path="/proc/{pid}/cmdline",
                raw_data={
                    "unique_namespaces": unique_ns_count,
                    "threshold": self.NAMESPACE_HOP_THRESHOLD,
                    "namespaces": list(namespaces_accessed.keys())[:20],
                },
                remediation="Investigate cross-namespace activity. Legitimate users typically operate within 1-3 namespaces.",
                evidence_details=EvidenceDetail(
                    pid=0,
                    cmdline=f"Accessed namespaces: {', '.join(list(namespaces_accessed.keys())[:10])}",
                ),
                remediation_commands=[
                    "Review RBAC policies for overly broad namespace access",
                    "Implement namespace-scoped service accounts",
                    "Enable Kubernetes audit logging for cross-namespace operations",
                ]
            ))

        if len(system_ns_ops) >= self.SYSTEM_NS_ACCESS_THRESHOLD:
            evidences.append(self._create_evidence(
                title="K8s System Namespace High-Risk Operations",
                description=f"Detected {len(system_ns_ops)} high-risk operations targeting system namespaces (threshold: {self.SYSTEM_NS_ACCESS_THRESHOLD})",
                severity=Severity.CRITICAL,
                confidence=0.85,
                attack_id="T1611",
                attack_tactic="Privilege Escalation",
                source_path="/proc/{pid}/cmdline",
                raw_data={
                    "system_ns_op_count": len(system_ns_ops),
                    "threshold": self.SYSTEM_NS_ACCESS_THRESHOLD,
                    "sample_cmdlines": [op["cmdline"][:200] for op in system_ns_ops[:5]],
                    "affected_namespaces": list({op["namespace"] for op in system_ns_ops}),
                },
                remediation="High-risk operations in system namespaces can compromise cluster integrity. Verify authorization and change management records.",
                evidence_details=EvidenceDetail(
                    pid=system_ns_ops[0].get('pid', 0),
                    cmdline=system_ns_ops[0].get('cmdline', '')[:300],
                ),
                remediation_commands=[
                    "Lock down RBAC for system namespaces (kube-system, istio-system)",
                    "Enable admission controllers to restrict system namespace access",
                    "Review audit logs for unauthorized system namespace modifications",
                ]
            ))

        return evidences
