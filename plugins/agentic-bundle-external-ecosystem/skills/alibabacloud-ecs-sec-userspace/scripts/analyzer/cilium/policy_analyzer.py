"""Policy analysis mixin - CRD audit, CVE-2026-33726, network policy bypass."""
import os
import re
from typing import List
from pathlib import Path

from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity
from .constants import (
    CRD_SUSPICIOUS_PATTERNS_NO_SEV, CRD_SUSPICIOUS_PATTERNS_WITH_SEV,
    CVE_2026_33726_CONFIG, CILIUM_ENV_PATTERNS, ATTACK_IDS,
    CILIUM_CONFIG_PATHS, CRD_LOCATIONS, STANDARD_K8S_PORTS,
    NAMESPACE_CATEGORIES, CRD_SEARCH_DIRS,
)
from .helpers import _get_logger


class PolicyAnalyzerMixin:
    """Mixin providing CRD audit and network policy analysis capabilities."""

    def _audit_cilium_crds(self, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        for base_dir in CRD_SEARCH_DIRS:
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
                            is_cilium_crd = False
                            for pattern, description in CRD_SUSPICIOUS_PATTERNS_NO_SEV:
                                if pattern.search(content):
                                    is_cilium_crd = True
                                    break
                            if not is_cilium_crd:
                                continue
                            namespace = self._extract_namespace_from_crd(content, filepath)
                            for pattern, description in CRD_SUSPICIOUS_PATTERNS_WITH_SEV:
                                if pattern.search(content):
                                    base_severity = Severity.HIGH
                                    severity = self._adjust_severity_for_namespace(base_severity, namespace)
                                    evidences.append(self._create_evidence(
                                        title=f"Cilium CRD Issue: {description}",
                                        description=f"Cilium CRD in {filepath}: {description}. Namespace: {namespace}.",
                                        severity=severity, confidence=0.75, attack_id="T1046",
                                        attack_tactic="Discovery", source_path=filepath,
                                        raw_data={"file": filepath, "issue": description, "namespace": namespace},
                                        remediation="Apply least-privilege network policies. Avoid wildcard rules.",
                                        evidence_details=EvidenceDetail(content=""),
                                        remediation_commands=["Inspect container runtime configuration",
                                            "Review pod security policies and context",
                                            "Check container image provenance and signatures",
                                            "Audit Kubernetes RBAC and network policies"],
                                    ))
                        except OSError:
                            continue
            except OSError:
                continue
        return evidences

    def _validate_crd_integrity(self, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        expected_policies = {'default-deny-ingress': False, 'default-deny-egress': False}
        for crd_dir in CRD_LOCATIONS:
            if not os.path.exists(crd_dir):
                continue
            try:
                for root, dirs, files in os.walk(crd_dir):
                    for filename in files:
                        if not filename.endswith('.yaml'):
                            continue
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                                content = f.read()
                            if 'CiliumClusterwideNetworkPolicy' in content:
                                if 'Ingress' in content and 'deny' in content.lower():
                                    expected_policies['default-deny-ingress'] = True
                                if 'Egress' in content and 'deny' in content.lower():
                                    expected_policies['default-deny-egress'] = True
                                for pattern, description, severity in [
                                    (re.compile(r'enforcement:\s*false', re.IGNORECASE), "Policy enforcement explicitly disabled", Severity.HIGH),
                                    (re.compile(r'toPorts:\s*\[\s*\]', re.IGNORECASE), "Empty port rules (allows all ports)", Severity.MEDIUM),
                                ]:
                                    if pattern.search(content):
                                        evidences.append(self._create_evidence(
                                            title=f"Cilium CRD Integrity Issue: {description}",
                                            description=f"CRD {filepath}: {description}.",
                                            severity=severity, confidence=0.80, attack_id="T1562.008",
                                            attack_tactic="Defense Evasion", source_path=filepath,
                                            raw_data={"file": filepath, "issue": description},
                                            remediation="Restore CRD from known-good backup.",
                                            evidence_details=EvidenceDetail(content=""),
                                            remediation_commands=["Review Cilium network policies and enforce least privilege",
                                                "Audit eBPF program attachments and verify legitimacy",
                                                "Check for unauthorized network connections between pods",
                                                "Monitor for continued policy violations and anomalous traffic"],
                                        ))
                        except OSError:
                            continue
            except OSError:
                continue
        if not expected_policies['default-deny-ingress']:
            evidences.append(self._create_evidence(
                title="Missing Default Deny Ingress Policy",
                description="No default-deny ingress CiliumClusterwideNetworkPolicy found.",
                severity=Severity.MEDIUM, confidence=0.90, attack_id="T1562.008",
                attack_tactic="Defense Evasion", raw_data={"missing_policy": "default-deny-ingress"},
                remediation="Deploy default-deny ingress policy.",
                evidence_details=EvidenceDetail(content='Suspicious eBPF bytecode pattern detected with potential kernel manipulation'),
                remediation_commands=["Review the alert details and investigate related system artifacts",
                    "Review related system logs and configuration",
                    "Check for additional indicators of compromise",
                    "Apply appropriate remediation and monitor"],
            ))
        return evidences

    def _detect_cve_2026_33726_config(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        dangerous_routing = False
        disabled_host_routing = False
        l7_proxy_enabled = False
        for config_path in CILIUM_CONFIG_PATHS:
            if not os.path.exists(config_path):
                continue
            try:
                with open(config_path, 'r', errors='replace', encoding='utf-8') as f:
                    content = f.read()
                if CVE_2026_33726_CONFIG['routing_mode'].search(content):
                    dangerous_routing = True
                if CVE_2026_33726_CONFIG['bpf_host_routing'].search(content):
                    disabled_host_routing = True
                if CVE_2026_33726_CONFIG['l7_proxy_enabled'].search(content):
                    l7_proxy_enabled = True
            except OSError:
                pass
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        proc = {}
        for proc_item in processes:
            cmdline = proc_item.get("cmdline", "")
            pid = proc_item.get("pid", 0)
            if 'cilium-agent' not in cmdline and 'cilium-operator' not in cmdline:
                continue
            proc = proc_item
            environ_path = f"/proc/{pid}/environ"
            if os.path.exists(environ_path):
                try:
                    with open(environ_path, 'rb') as f:
                        env_content = f.read().decode('utf-8', errors='replace')
                    if CILIUM_ENV_PATTERNS['CILIUM_ROUTING_MODE'].search(env_content):
                        dangerous_routing = True
                    if CILIUM_ENV_PATTERNS['CILIUM_ENABLE_BPF_HOST_ROUTING'].search(env_content):
                        disabled_host_routing = True
                except OSError:
                    pass
            if '--routing-mode=per-endpoint' in cmdline or '--routing-mode per-endpoint' in cmdline:
                dangerous_routing = True
            if '--enable-bpf-host-routing=false' in cmdline or '--enable-bpf-host-routing false' in cmdline:
                disabled_host_routing = True
        if dangerous_routing and disabled_host_routing:
            severity = Severity.CRITICAL if l7_proxy_enabled else Severity.HIGH
            evidences.append(self._create_evidence(
                title="CVE-2026-33726: Vulnerable Cilium Configuration Detected",
                description=f"Cilium configuration has dangerous combination enabling NetworkPolicy bypass: routing-mode=per-endpoint + enable-bpf-host-routing=false{' + l7-proxy enabled' if l7_proxy_enabled else ''}.",
                severity=severity, confidence=0.95 if l7_proxy_enabled else 0.85,
                attack_id=ATTACK_IDS['defense_evasion'], attack_tactic="Defense Evasion",
                raw_data={"cve": "CVE-2026-33726", "vulnerability": "Cilium NetworkPolicy Bypass",
                    "configuration": {"routing_mode": "per-endpoint" if dangerous_routing else "unknown",
                        "bpf_host_routing": "disabled" if disabled_host_routing else "enabled",
                        "l7_proxy": "enabled" if l7_proxy_enabled else "unknown/disabled"}},
                remediation="Upgrade to Cilium 1.15.8+ or 1.16.3+. Enable BPF Host Routing.",
                evidence_details=EvidenceDetail(remote_address=proc.get('remote_address', proc.get('ip', '')),
                    connection_state=proc.get('state', ''), content=proc.get('container_id', '')),
                remediation_commands=["Inspect container runtime configuration", "Review pod security policies and context",
                    "Check container image provenance and signatures", "Audit Kubernetes RBAC and network policies"],
            ))
        elif dangerous_routing or disabled_host_routing:
            evidences.append(self._create_evidence(
                title="Potential CVE-2026-33726 Risk Factor Detected",
                description=f"Partial risk factors for CVE-2026-33726: {'routing-mode=per-endpoint' if dangerous_routing else 'enable-bpf-host-routing=false'}.",
                severity=Severity.MEDIUM, confidence=0.70, attack_id=ATTACK_IDS['defense_evasion'],
                attack_tactic="Defense Evasion", raw_data={"cve": "CVE-2026-33726", "partial_risk": True},
                remediation="Review Cilium configuration.", evidence_details=EvidenceDetail(content=""),
                remediation_commands=["Review Cilium network policies and enforce least privilege",
                    "Audit eBPF program attachments and verify legitimacy",
                    "Check for unauthorized network connections between pods",
                    "Monitor for continued policy violations and anomalous traffic"],
            ))
        return evidences

    def _detect_network_policy_bypass(self, network_data: dict, process_data: dict) -> List[Evidence]:
        evidences = []
        endpoints = network_data.get("endpoints", []) if isinstance(network_data, dict) else []
        same_node_connections = []
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            src_node = ep.get("source_node", "")
            dst_node = ep.get("destination_node", "")
            if src_node and dst_node and src_node == dst_node and ep.get("source_pod", "") != ep.get("destination_pod", ""):
                same_node_connections.append({"src_pod": ep.get("source_pod", ""), "dst_pod": ep.get("destination_pod", ""),
                    "src_ip": ep.get("source_ip", ""), "dst_ip": ep.get("destination_ip", ""), "node": src_node,
                    "port": ep.get("destination_port", 0), "protocol": ep.get("protocol", "tcp")})
        if len(same_node_connections) > 10:
            evidences.append(self._create_evidence(
                title="High Volume Same-Node Pod Communication Detected",
                description=f"Detected {len(same_node_connections)} same-node Pod-to-Pod connections. May indicate CVE-2026-33726 exploitation.",
                severity=Severity.HIGH, confidence=0.75, attack_id=ATTACK_IDS['network_discovery'],
                attack_tactic="Discovery", raw_data={"cve": "CVE-2026-33726", "same_node_connection_count": len(same_node_connections)},
                remediation="Verify NetworkPolicy enforcement.", evidence_details=EvidenceDetail(content=""),
                remediation_commands=["Inspect container runtime configuration", "Review pod security policies and context",
                    "Check container image provenance and signatures", "Audit Kubernetes RBAC and network policies"],
            ))
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        envoy_pids = []
        for proc_item in processes:
            cmdline = proc_item.get("cmdline", "").lower()
            if 'envoy' in cmdline or 'envoy' in proc_item.get("comm", "").lower():
                envoy_pids.append(proc_item.get("pid", 0))
        if envoy_pids:
            _get_logger().info(f"[{self.name}] CVE-2026-33726: Detected Envoy L7 proxy (PIDs: {envoy_pids})")
        non_standard_ports = []
        for conn_item in same_node_connections:
            port = conn_item.get("port", 0)
            if port and port not in STANDARD_K8S_PORTS and port > 1024:
                non_standard_ports.append(conn_item)
        if len(non_standard_ports) > 5:
            conn = non_standard_ports[0] if non_standard_ports else {}
            evidences.append(self._create_evidence(
                title="Non-Standard Ports Used in Same-Node Pod Communication",
                description=f"Detected {len(non_standard_ports)} same-node connections using non-standard ports.",
                severity=Severity.MEDIUM, confidence=0.70, attack_id=ATTACK_IDS['non_standard_port'],
                attack_tactic="Command and Control", raw_data={"cve": "CVE-2026-33726",
                    "non_standard_port_count": len(non_standard_ports)},
                remediation="Review NetworkPolicy rules.", evidence_details=EvidenceDetail(
                    remote_address=conn.get('remote_address', conn.get('ip', '')),
                    connection_state=conn.get('state', ''), content=conn.get('container_id', '')),
                remediation_commands=["Inspect container runtime configuration", "Review pod security policies and context",
                    "Check container image provenance and signatures", "Audit Kubernetes RBAC and network policies"],
            ))
        return evidences

    def _extract_namespace_from_crd(self, content: str, filepath: str) -> str:
        ns_match = re.search(r'metadata:\s*\n\s+namespace:\s*(\S+)', content)
        if ns_match:
            return ns_match.group(1)
        path_parts = Path(filepath).parts
        for i, part in enumerate(path_parts):
            if part == 'namespaces' and i + 1 < len(path_parts):
                return path_parts[i + 1]
        return "unknown"

    def _adjust_severity_for_namespace(self, base_severity: Severity, namespace: str) -> Severity:
        ns_lower = namespace.lower()
        env_category = 'unknown'
        for category, patterns in NAMESPACE_CATEGORIES.items():
            if any(pattern in ns_lower for pattern in patterns):
                env_category = category
                break
        severity_adjustments = {
            'production': {s: s for s in Severity},
            'critical': {Severity.INFO: Severity.LOW, Severity.LOW: Severity.MEDIUM, Severity.MEDIUM: Severity.HIGH, Severity.HIGH: Severity.CRITICAL, Severity.CRITICAL: Severity.CRITICAL},
            'staging': {Severity.CRITICAL: Severity.HIGH, Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW, Severity.LOW: Severity.INFO, Severity.INFO: Severity.INFO},
            'development': {Severity.CRITICAL: Severity.MEDIUM, Severity.HIGH: Severity.LOW, Severity.MEDIUM: Severity.INFO, Severity.LOW: Severity.INFO, Severity.INFO: Severity.INFO},
            'ephemeral': {Severity.CRITICAL: Severity.LOW, Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.INFO, Severity.LOW: Severity.INFO, Severity.INFO: Severity.INFO},
            'unknown': {Severity.CRITICAL: Severity.HIGH, Severity.HIGH: Severity.HIGH, Severity.MEDIUM: Severity.MEDIUM, Severity.LOW: Severity.LOW, Severity.INFO: Severity.INFO},
        }
        adjusted = severity_adjustments.get(env_category, severity_adjustments['unknown']).get(base_severity, base_severity)
        if adjusted != base_severity:
            _get_logger().debug(f"[{self.name}] Adjusted severity from {base_severity.value} to {adjusted.value} for namespace '{namespace}'")
        return adjusted
