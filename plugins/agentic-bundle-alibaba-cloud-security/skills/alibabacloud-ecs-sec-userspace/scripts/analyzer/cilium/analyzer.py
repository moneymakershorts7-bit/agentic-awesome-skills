"""CiliumRuntimeSecurityAnalyzer core class - composes all detection capability mixins.

This module contains the main CiliumRuntimeSecurityAnalyzer class that inherits from:
- RuntimeMonitorMixin (eBPF programs/maps, Hubble, agent health, binary integrity)
- EvasionDetectorMixin (Tetragon evasion, VoidLink eBPF map tampering, conntrack discrepancy)
- PolicyAnalyzerMixin (CRD audit, CVE-2026-33726, network policy bypass)
- BaseAnalyzer (base class for all analyzers)
"""
from typing import List

from ...reporter.evidence import Evidence
from ...reporter.severity import Severity
from ..base import BaseAnalyzer
from .runtime_monitor import RuntimeMonitorMixin
from .evasion_detector import EvasionDetectorMixin
from .policy_analyzer import PolicyAnalyzerMixin


class CiliumRuntimeSecurityAnalyzer(
    RuntimeMonitorMixin,
    EvasionDetectorMixin,
    PolicyAnalyzerMixin,
    BaseAnalyzer,
):
    """Cilium/Tetragon eBPF Runtime Security Analyzer."""
    name = "cilium_runtime_security_analyzer"
    timeout = 60
    required_collectors = ["process", "network", "filesystem"]

    def should_skip(self) -> tuple:
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        evidences = []
        if not collected_data:
            return evidences
        if not self._is_cilium_environment(collected_data):
            return evidences

        self._ensure_whitelist_manager()

        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            process_data = {}
        try:
            network_data = self._get_data(collected_data, "network")
        except KeyError:
            network_data = {}
        try:
            filesystem_data = self._get_data(collected_data, "filesystem")
        except KeyError:
            filesystem_data = {}

        cluster_size = self._detect_cluster_size(network_data)
        evidences.extend(self._verify_cilium_agents(process_data))
        evidences.extend(self._check_ebpf_program_integrity(filesystem_data))
        evidences.extend(self._analyze_ebpf_maps(filesystem_data, cluster_size))
        evidences.extend(self._validate_hubble_telemetry(process_data, filesystem_data))
        evidences.extend(self._audit_cilium_crds(filesystem_data))
        evidences.extend(self._detect_tetragon_evasion(process_data, filesystem_data))
        evidences.extend(self._detect_voidlink_ebpf_tampering(process_data, filesystem_data))
        evidences.extend(self._detect_conntrack_flow_discrepancy())
        evidences.extend(self._check_cilium_agent_anomalies(process_data, filesystem_data))
        evidences.extend(self._validate_ebpf_program_attachments())
        evidences.extend(self._validate_crd_integrity(filesystem_data))
        evidences.extend(self._detect_cve_2026_33726_config(process_data, filesystem_data))
        evidences.extend(self._detect_network_policy_bypass(network_data, process_data))
        evidences.extend(self._verify_cilium_agent_integrity(process_data))

        if self._whitelist_manager:
            evidences = self._apply_whitelist_filtering(evidences)
        return evidences

    def _apply_whitelist_filtering(self, evidences: List[Evidence]) -> List[Evidence]:
        if not self._whitelist_manager:
            return evidences
        filtered = []
        for evidence in evidences:
            rule = self._whitelist_manager.is_whitelisted(module=evidence.module, evidence_value=evidence.title)
            if rule:
                if rule.severity_override:
                    override = getattr(Severity, rule.severity_override.upper(), None)
                    if override:
                        evidence.severity = override
                        evidence.raw_data['whitelisted'] = True
                        evidence.raw_data['whitelist_rule'] = rule.id
                else:
                    evidence.raw_data['whitelisted'] = True
                    evidence.raw_data['whitelist_rule'] = rule.id
                filtered.append(evidence)
            else:
                filtered.append(evidence)
        return filtered
