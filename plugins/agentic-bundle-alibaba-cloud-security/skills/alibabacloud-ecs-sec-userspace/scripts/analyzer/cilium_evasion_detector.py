"""Cilium Evasion Detection Module

Detects sophisticated evasion techniques where attackers leverage Cilium/eBPF capabilities
to bypass security controls or execute attacks.

Components:
- eBPF-based Container Escape Detection
- Cilium CRD Manipulation Detection
- Hubble Flow Manipulation Detection
- Tetragon Evasion Techniques
- Cilium Agent Supply Chain Attacks

ATT&CK Mapping:
- T1611 - Escape to Host (eBPF-based container escape)
- T1562.008 - Impair Defenses: Disable Security Tools (Tetragon/Hubble bypass)
- T1070.002 - Indicator Removal: Clear Linux Logs (Hubble flow manipulation)
- T1046 - Network Service Discovery (Cilium policy reconnaissance)
- T1556 - Modify Authentication Process (identity manipulation)
"""
import os
import re
import json
import hashlib
import subprocess
from typing import List, Optional
from datetime import datetime, timezone

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

class CiliumEvasionDetector(BaseAnalyzer):
    """Detect advanced Cilium/eBPF evasion techniques"""

    name = "cilium_evasion_detector"
    timeout = 60
    required_collectors = ["process", "network", "filesystem"]

    # eBPF helpers that can be used for container escape
    DANGEROUS_EBPF_HELPERS = {
        'bpf_override_return': ('T1611', 'Can bypass LSM security modules', Severity.CRITICAL),
        'bpf_probe_write_user': ('T1611', 'Can modify user-space memory', Severity.HIGH),
        'bpf_ktime_get_ns': ('T1070.002', 'Can be used for timing attacks', Severity.LOW),
        'bpf_tail_call': ('T1611', 'Can chain eBPF programs for evasion', Severity.MEDIUM),
        'bpf_ringbuf_output': ('T1048', 'Can exfiltrate data via ring buffer', Severity.MEDIUM),
    }

    # Sensitive eBPF hooks for container escape
    SENSITIVE_EBPF_HOOKS = [
        ('security_', 'LSM security hook', 'T1611', Severity.CRITICAL),
        ('lsm_', 'Linux Security Module hook', 'T1611', Severity.CRITICAL),
        ('cgroup/', 'Cgroup attachment point', 'T1611', Severity.HIGH),
        ('xdp', 'XDP hook', 'T1562.008', Severity.HIGH),
        ('tc_cls', 'Traffic control classifier', 'T1562.008', Severity.MEDIUM),
    ]

    # Suspicious Cilium CRD manipulation patterns
    CRD_MANIPULATION_PATTERNS = [
        (re.compile(r'ingress:\s*\[\s*\]', re.IGNORECASE),
         'Empty ingress rules (allow all)', 'T1046', Severity.HIGH),
        (re.compile(r'egress:\s*\[\s*\]', re.IGNORECASE),
         'Empty egress rules (allow all)', 'T1046', Severity.HIGH),
        (re.compile(r'toCIDR:\s*-?\s*["\']?0\.0\.0\.0/0', re.IGNORECASE),
         'Allow all outbound CIDR', 'T1046', Severity.MEDIUM),
        (re.compile(r'fromCIDR:\s*-?\s*["\']?0\.0\.0\.0/0', re.IGNORECASE),
         'Allow all inbound CIDR', 'T1046', Severity.MEDIUM),
        (re.compile(r'endpointSelector:\s*\{\s*\}', re.IGNORECASE),
         'Empty endpoint selector (applies to all)', 'T1556', Severity.HIGH),
        (re.compile(r'identity-allocation-mode:\s*kvstore', re.IGNORECASE),
         'Identity mode changed to kvstore', 'T1556', Severity.MEDIUM),
        (re.compile(r'enforcement:\s*false', re.IGNORECASE),
         'Policy enforcement disabled', 'T1562.008', Severity.HIGH),
    ]

    # Hubble flow manipulation indicators
    HUBBLE_MANIPULATION_PATTERNS = [
        (re.compile(r'disable-flow-log|flow-log:\s*false', re.IGNORECASE),
         'Hubble flow logging disabled', 'T1070.002', Severity.HIGH),
        (re.compile(r'metrics-server:\s*disabled', re.IGNORECASE),
         'Hubble metrics server disabled', 'T1070.002', Severity.MEDIUM),
        (re.compile(r'tls:\s*disabled|insecure-skip-tls-verify', re.IGNORECASE),
         'Hubble TLS verification disabled', 'T1562.008', Severity.HIGH),
        (re.compile(r'relay-disabled|disable-relay', re.IGNORECASE),
         'Hubble relay disabled', 'T1562.008', Severity.HIGH),
        (re.compile(r'observe:[\s\S]*{[^}]*enabled:\s*false', re.IGNORECASE),
         'Hubble observe feature disabled', 'T1070.002', Severity.HIGH),
    ]

    # Tetragon evasion command patterns
    TETRAGON_EVASION_COMMANDS = [
        (re.compile(r'kill\s+(-\w+\s+)?\d*.*tetragon|pkill.*tetragon', re.IGNORECASE),
         'Attempt to kill Tetragon process', 'T1562.008', Severity.CRITICAL),
        (re.compile(r'rm\s+(-rf?\s+)?/var/lib/tetragon', re.IGNORECASE),
         'Attempt to remove Tetragon data', 'T1562.008', Severity.CRITICAL),
        (re.compile(r'bpf\s+prog\s+(unload|detach)', re.IGNORECASE),
         'Unload/detach eBPF program', 'T1562.008', Severity.HIGH),
        (re.compile(r'bpftool\s+feature\s+probe', re.IGNORECASE),
         'Probe eBPF features (reconnaissance)', 'T1046', Severity.MEDIUM),
        (re.compile(r'chmod\s+[0-7]*\s+/sys/kernel/debug', re.IGNORECASE),
         'Modify debug filesystem permissions', 'T1562.008', Severity.HIGH),
    ]

    # Suspicious capability usage
    SUSPICIOUS_CAPABILITIES = [
        ('CAP_BPF', 'Can manipulate eBPF programs', 'T1611', Severity.HIGH),
        ('CAP_PERFMON', 'Can access performance monitoring', 'T1046', Severity.MEDIUM),
        ('CAP_SYS_ADMIN', 'Broad system administration', 'T1611', Severity.HIGH),
        ('CAP_NET_ADMIN', 'Network configuration control', 'T1562.008', Severity.MEDIUM),
    ]

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute Cilium evasion detection analysis"""
        evidences = []

        if not collected_data:
            return evidences

        if not self._is_cilium_environment(collected_data):
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

        # 1. Detect eBPF-based container escape attempts
        evidences.extend(self._detect_ebpf_container_escape(filesystem_data))

        # 2. Monitor Cilium CRD changes for policy manipulation
        evidences.extend(self._monitor_crd_changes(filesystem_data))

        # 3. Validate Hubble telemetry integrity
        evidences.extend(self._validate_hubble_integrity(process_data, filesystem_data))

        # 4. Verify Cilium agent integrity
        evidences.extend(self._verify_agent_integrity(process_data, filesystem_data))

        # 5. Detect Tetragon evasion techniques
        evidences.extend(self._detect_tetragon_evasion(process_data))

        # Apply whitelist filtering if available
        if self._whitelist_manager:
            evidences = self._apply_whitelist_filtering(evidences)

        return evidences

    def _is_cilium_environment(self, collected_data: dict) -> bool:
        """Detect if running in Cilium-managed environment"""
        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            return False
        if not isinstance(process_data, dict):
            process_data = {}
        processes = process_data.get("processes", [])
        for proc in processes:
            cmdline = proc.get("cmdline", "").lower()
            comm = proc.get("comm", "").lower()

            cilium_indicators = ['cilium-agent', 'cilium-operator', 'cilium-cni',
                                 'hubble-relay', 'tetragon']
            for indicator in cilium_indicators:
                if indicator in cmdline or indicator in comm:
                    _get_logger().info(f"[{self.name}] Cilium environment detected: found {indicator}")
                    return True

        # Check for Cilium directories
        cilium_dirs = ['/var/run/cilium', '/etc/cilium', '/var/lib/cilium']
        for cdir in cilium_dirs:
            if os.path.exists(cdir):
                _get_logger().info(f"[{self.name}] Cilium detected: directory {cdir} exists")
                return True

        # Check for Cilium eBPF filesystem
        if os.path.exists('/sys/fs/bpf/tc'):
            _get_logger().info(f"[{self.name}] Cilium detected: eBPF tc directory")
            return True

        return False

    def _detect_ebpf_container_escape(self, filesystem_data: dict) -> List[Evidence]:
        """Detect eBPF-based container escape attempts"""
        evidences = []

        # Check for dangerous eBPF programs using bpftool
        try:
            result = subprocess.run(
                ['bpftool', 'prog', 'list', '-j'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            if result.returncode == 0:
                try:
                    programs = json.loads(result.stdout)
                    evidences.extend(self._analyze_ebpf_programs(programs))
                except json.JSONDecodeError:
                    _get_logger().debug(f"[{self.name}] Failed to parse bpftool JSON output")
        except (subprocess.TimeoutExpired, OSError) as e:
            _get_logger().debug(f"[{self.name}] Cannot run bpftool: {e}")

        # Fallback: scan eBPF filesystem for suspicious programs
        evidences.extend(self._scan_ebpf_filesystem_for_escape())

        # Check for eBPF maps with unusually large values
        evidences.extend(self._check_ebpf_map_sizes())

        return evidences

    def _analyze_ebpf_programs(self, programs: list) -> List[Evidence]:
        """Analyze eBPF programs for container escape indicators"""
        evidences = []

        for prog in programs:
            prog_name = prog.get('name', '')
            prog_type = prog.get('type', '')

            # Check for dangerous eBPF helpers
            for helper, (attack_id, desc, severity) in self.DANGEROUS_EBPF_HELPERS.items():
                if helper in prog.get('tag', '') or helper in str(prog):
                    evidences.append(self._create_evidence(
                        title=f"Dangerous eBPF Helper Detected: {helper}",
                        description=f"eBPF program '{prog_name}' uses helper {helper}. {desc}. "
                                   f"This may indicate container escape attempt.",
                        severity=severity,
                        confidence=0.80,
                        attack_id=attack_id,
                        attack_tactic="Execution",
                        source_path=f"/proc/sys/kernel/bpf_progs_enabled",
                        raw_data={
                            "program_name": prog_name,
                            "program_type": prog_type,
                            "helper": helper,
                            "description": desc
                        },
                        remediation="Verify eBPF program is legitimate. Check program source and load time. "
                                   "Monitor for unauthorized eBPF program loads.",
                        evidence_details=EvidenceDetail(
                            pid=indicator.get('pid', 0),
                            cmdline=indicator.get('cmdline', '')[:300],
                            executable=indicator.get('exe', ''),
                            file_path=indicator.get('file_path', indicator.get('path', '')),
                            remote_address=indicator.get('remote_address', indicator.get('ip', '')),
                            connection_state=indicator.get('state', ''),
                            content=indicator.get('container_id', '')
                        ),
                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                    ))

            # Check for sensitive hook attachments
            for hook_prefix, hook_desc, attack_id, severity in self.SENSITIVE_EBPF_HOOKS:
                if prog_name.startswith(hook_prefix) or hook_prefix in prog_name:
                    evidences.append(self._create_evidence(
                        title=f"Sensitive eBPF Hook Usage: {prog_name}",
                        description=f"eBPF program attached to {hook_desc} ({hook_prefix}). "
                                   f"This can be used for container escape or security bypass.",
                        severity=severity,
                        confidence=0.75,
                        attack_id=attack_id,
                        attack_tactic="Privilege Escalation",
                        source_path="/sys/fs/bpf",
                        raw_data={
                            "program_name": prog_name,
                            "hook_type": hook_prefix,
                            "hook_description": hook_desc
                        },
                        remediation="Verify this eBPF program is part of legitimate Cilium operations. "
                                   "Check if program was loaded by authorized component.",
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

        return evidences

    def _scan_ebpf_filesystem_for_escape(self) -> List[Evidence]:
        """Scan eBPF filesystem for escape indicators"""
        evidences = []
        bpf_paths = ['/sys/fs/bpf/tc/globals', '/sys/fs/bpf']

        for bpf_path in bpf_paths:
            if not os.path.exists(bpf_path):
                continue

            try:
                for item in os.listdir(bpf_path):
                    # Check for suspicious program names
                    for helper_name in self.DANGEROUS_EBPF_HELPERS.keys():
                        if helper_name in item.lower():
                            full_path = os.path.join(bpf_path, item)
                            evidences.append(self._create_evidence(
                                title=f"Suspicious eBPF Program File: {item}",
                                description=f"Found eBPF program file with dangerous helper name: {item}. "
                                           f"This may indicate manual eBPF program deployment for escape.",
                                severity=Severity.HIGH,
                                confidence=0.70,
                                attack_id="T1611",
                                attack_tactic="Execution",
                                source_path=full_path,
                                raw_data={"file": item, "path": full_path},
                                remediation="Investigate eBPF program origin. Verify it.",
                                evidence_details=EvidenceDetail(
                                    pid=item.get('pid', 0),
                                    cmdline=item.get('cmdline', '')[:300],
                                    executable=item.get('exe', ''),
                                    file_path=item.get('file_path', item.get('path', '')),
                                    remote_address=item.get('remote_address', item.get('ip', '')),
                                    connection_state=item.get('state', '')
                                ),
                                remediation_commands=[
                        "Review Cilium network policies and enforce least privilege",
                        "Audit eBPF program attachments and verify legitimacy",
                        "Check for unauthorized network connections between pods",
                        "Monitor for continued policy violations and anomalous traffic"
                    ]
                            ))
            except OSError:
                continue

        return evidences

    def _check_ebpf_map_sizes(self) -> List[Evidence]:
        """Check for eBPF maps with unusually large values (potential data exfil)"""
        evidences = []

        try:
            result = subprocess.run(
                ['bpftool', 'map', 'list', '-j'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            if result.returncode == 0:
                try:
                    maps = json.loads(result.stdout)
                    for map_info in maps:
                        max_entries = map_info.get('max_entries', 0)
                        value_size = map_info.get('value_size', 0)
                        map_name = map_info.get('name', '')

                        # Flag maps with very large value sizes (>1MB)
                        if value_size > 1048576:
                            evidences.append(self._create_evidence(
                                title=f"Unusually Large eBPF Map Value Size: {map_name}",
                                description=f"eBPF map '{map_name}' has value size {value_size} bytes. "
                                           f"Large values can be used for data exfiltration channels.",
                                severity=Severity.MEDIUM,
                                confidence=0.65,
                                attack_id="T1048",
                                attack_tactic="Exfiltration",
                                source_path="/sys/fs/bpf",
                                raw_data={
                                    "map_name": map_name,
                                    "value_size": value_size,
                                    "max_entries": max_entries
                                },
                                remediation="Verify map size requirements. Large maps may indicate data exfiltration.",
                                evidence_details=EvidenceDetail(
                                    content=""
                                ),
                                remediation_commands=[
                        "Review Cilium network policies and enforce least privilege",
                        "Audit eBPF program attachments and verify legitimacy",
                        "Check for unauthorized network connections between pods",
                        "Monitor for continued policy violations and anomalous traffic"
                    ]
                            ))
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, OSError):
            pass

        return evidences

    def _monitor_crd_changes(self, filesystem_data: dict) -> List[Evidence]:
        """Monitor Cilium CRD changes for policy manipulation"""
        evidences = []

        # Search for Cilium CRD YAML files
        crd_search_paths = ['/etc/cilium', '/var/lib/cilium', '/tmp', '/home']
        for search_path in crd_search_paths:
            if not os.path.exists(search_path):
                continue

            try:
                for root, dirs, files in os.walk(search_path):
                    for filename in files:
                        if not filename.endswith(('.yaml', '.yml')):
                            continue

                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                                content = f.read()

                            # Check if it's a Cilium CRD
                            if 'CiliumNetworkPolicy' not in content and \
                               'CiliumClusterwideNetworkPolicy' not in content:
                                continue

                            # Extract namespace
                            namespace = self._extract_namespace(content)

                            # Check for manipulation patterns
                            for pattern, description, attack_id, severity in self.CRD_MANIPULATION_PATTERNS:
                                if pattern.search(content):
                                    evidences.append(self._create_evidence(
                                        title=f"Cilium CRD Manipulation: {description}",
                                        description=f"Cilium CRD in {filepath}: {description}. "
                                                   f"Namespace: {namespace}. "
                                                   f"This may allow unauthorized network access.",
                                        severity=severity,
                                        confidence=0.80,
                                        attack_id=attack_id,
                                        attack_tactic="Lateral Movement",
                                        source_path=filepath,
                                        raw_data={
                                            "file": filepath,
                                            "issue": description,
                                            "namespace": namespace
                                        },
                                        remediation="Review network policy changes. Ensure least-privilege access. "
                                                   "Avoid wildcard rules in production.",
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
                        except OSError:
                            continue
            except OSError:
                continue

        return evidences

    def _validate_hubble_integrity(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        """Validate Hubble telemetry hasn't been compromised"""
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []

        hubble_detected = False
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")

            if 'hubble' in cmdline.lower() or 'hubble' in comm.lower():
                hubble_detected = True
                pid = proc.get("pid", 0)

                # Check for suspicious Hubble flags
                for pattern, description, attack_id, severity in self.HUBBLE_MANIPULATION_PATTERNS:
                    if pattern.search(cmdline):
                        evidences.append(self._create_evidence(
                            title=f"Hubble Telemetry Tampering: {description}",
                            description=f"Hubble process (PID: {pid}): {description}. "
                                       f"This creates blind spots for attack detection.",
                            severity=severity,
                            confidence=0.85,
                            attack_id=attack_id,
                            attack_tactic="Defense Evasion",
                            source_path=f"/proc/{pid}/cmdline",
                            raw_data={
                                "pid": pid,
                                "issue": description,
                                "cmdline": cmdline[:300]
                            },
                            remediation="Enable all Hubble observability features. Review configuration best practices.",
                            evidence_details=EvidenceDetail(
                                pid=proc.get('pid', 0),
                                cmdline=proc.get('cmdline', '')[:300],
                                executable=proc.get('exe', ''),
                                file_path=proc.get('file_path', proc.get('path', '')),
                                remote_address=proc.get('remote_address', proc.get('ip', '')),
                                connection_state=proc.get('state', '')
                            ),
                            remediation_commands=[
                        "Review Cilium network policies and enforce least privilege",
                        "Audit eBPF program attachments and verify legitimacy",
                        "Check for unauthorized network connections between pods",
                        "Monitor for continued policy violations and anomalous traffic"
                    ]
                        ))
                break

        # Scan Hubble configuration files
        if hubble_detected or os.path.exists('/etc/hubble'):
            evidences.extend(self._scan_hubble_config_files())

        return evidences

    def _scan_hubble_config_files(self) -> List[Evidence]:
        """Scan Hubble configuration files for tampering"""
        evidences = []
        hubble_dirs = ['/etc/hubble', '/var/lib/hubble', '/opt/hubble']

        for base_dir in hubble_dirs:
            if not os.path.isdir(base_dir):
                continue

            try:
                for root, dirs, files in os.walk(base_dir):
                    for filename in files:
                        if not filename.endswith(('.yaml', '.yml', '.json')):
                            continue

                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                                content = f.read()

                            for pattern, description, attack_id, severity in self.HUBBLE_MANIPULATION_PATTERNS:
                                if pattern.search(content):
                                    evidences.append(self._create_evidence(
                                        title=f"Hubble Config Tampering: {description}",
                                        description=f"Hubble config {filepath}: {description}. "
                                                   f"Telemetry gaps may hide attack activity.",
                                        severity=severity,
                                        confidence=0.75,
                                        attack_id=attack_id,
                                        attack_tactic="Defense Evasion",
                                        source_path=filepath,
                                        raw_data={"file": filepath, "issue": description},
                                        remediation="Restore Hubble configuration from known-good backup.",
                                        evidence_details=EvidenceDetail(
                                            content=""
                                        ),
                                        remediation_commands=[
                        "Review Cilium network policies and enforce least privilege",
                        "Audit eBPF program attachments and verify legitimacy",
                        "Check for unauthorized network connections between pods",
                        "Monitor for continued policy violations and anomalous traffic"
                    ]
                                    ))
                                    break
                        except OSError:
                            continue
            except OSError:
                continue

        return evidences

    def _verify_agent_integrity(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        """Verify Cilium agent hasn't been tampered"""
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []

        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            pid = proc.get("pid", 0)

            if 'cilium-agent' in cmdline or 'cilium-agent' in comm:
                # Check binary integrity
                exe_path = f"/proc/{pid}/exe"
                if os.path.exists(exe_path):
                    try:
                        binary_hash = self._calculate_file_hash(exe_path)
                        if binary_hash:
                            _get_logger().debug(f"[{self.name}] Cilium agent binary hash: {binary_hash}")
                            # In production, compare against known-good hashes
                    except OSError:
                        pass

                # Check for suspicious environment variables
                env_file = f"/proc/{pid}/environ"
                if os.path.exists(env_file):
                    try:
                        with open(env_file, 'rb') as f:
                            env_content = f.read().decode('utf-8', errors='replace')

                        if 'CILIUM_DEBUG' in env_content or 'DEBUG' in env_content:
                            evidences.append(self._create_evidence(
                                title="Cilium Agent Debug Mode Enabled",
                                description=f"Cilium agent (PID: {pid}) has debug mode enabled. "
                                           f"This may expose sensitive information.",
                                severity=Severity.MEDIUM,
                                confidence=0.70,
                                attack_id="T1046",
                                attack_tactic="Discovery",
                                source_path=env_file,
                                raw_data={"pid": pid, "has_debug": True},
                                remediation="Disable debug mode in production. Review environment variables.",
                                evidence_details=EvidenceDetail(
                                    pid=proc.get('pid', 0),
                                    cmdline=proc.get('cmdline', '')[:300],
                                    executable=proc.get('exe', ''),
                                    file_path=proc.get('file_path', proc.get('path', '')),
                                    remote_address=proc.get('remote_address', proc.get('ip', '')),
                                    connection_state=proc.get('state', ''),
                                    content=proc.get('agent_id', proc.get('server_name', ''))
                                ),
                                remediation_commands=[
                        "Review agent configuration and tool permissions",
                        "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity",
                        "Restrict agent tool access to minimum required"
                    ]
                            ))
                    except OSError:
                        pass

                break

        # Check for unauthorized plugins/extensions
        cilium_plugin_dirs = ['/var/lib/cilium/plugins', '/opt/cilium/plugins']
        for plugin_dir in cilium_plugin_dirs:
            if os.path.exists(plugin_dir):
                try:
                    plugins = os.listdir(plugin_dir)
                    for plugin in plugins:
                        if not plugin.endswith('.so'):
                            continue

                        plugin_path = os.path.join(plugin_dir, plugin)
                        evidences.append(self._create_evidence(
                            title=f"Unauthorized Cilium Plugin: {plugin}",
                            description=f"Found plugin {plugin} in {plugin_dir}. "
                                       f"Unauthorized plugins may compromise agent integrity.",
                            severity=Severity.HIGH,
                            confidence=0.65,
                            attack_id="T1562.008",
                            attack_tactic="Defense Evasion",
                            source_path=plugin_path,
                            raw_data={"plugin": plugin, "directory": plugin_dir},
                            remediation="Verify plugin is from trusted source. Check plugin signatures.",
                            evidence_details=EvidenceDetail(
                                content=""
                            ),
                            remediation_commands=[
                        "Review agent configuration and tool permissions",
                        "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity",
                        "Restrict agent tool access to minimum required"
                    ]
                        ))
                except OSError:
                    continue

        return evidences

    def _detect_tetragon_evasion(self, process_data: dict) -> List[Evidence]:
        """Detect Tetragon runtime security evasion attempts"""
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []

        tetragon_detected = False
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            if 'tetragon' in cmdline.lower() or 'tetragon' in comm.lower():
                tetragon_detected = True
                break

        if not tetragon_detected and not os.path.exists('/sys/kernel/security/tetragon'):
            return evidences

        # Check processes for Tetragon evasion commands
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)

            for pattern, description, attack_id, severity in self.TETRAGON_EVASION_COMMANDS:
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title=f"Tetragon Evasion Attempt: {description}",
                        description=f"Process (PID: {pid}) shows Tetragon evasion indicator: {description}. "
                                   f"Cmdline: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.90,
                        attack_id=attack_id,
                        attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={
                            "pid": pid,
                            "cmdline": cmdline[:300],
                            "evasion_type": description
                        },
                        remediation="Investigate process immediately. Ensure Tetragon is running. "
                                   "Check for compromised containers attempting to disable runtime security.",
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

            # Check for suspicious capabilities
            for cap_name, cap_desc, attack_id, severity in self.SUSPICIOUS_CAPABILITIES:
                if cap_name in cmdline:
                    evidences.append(self._create_evidence(
                        title=f"Suspicious Capability Usage: {cap_name}",
                        description=f"Process (PID: {pid}) has {cap_name} capability. {cap_desc}. "
                                   f"This may be used for Tetragon evasion.",
                        severity=severity,
                        confidence=0.75,
                        attack_id=attack_id,
                        attack_tactic="Privilege Escalation",
                        source_path=f"/proc/{pid}/status",
                        raw_data={
                            "pid": pid,
                            "capability": cap_name,
                            "description": cap_desc
                        },
                        remediation="Review process capabilities. Apply principle of least privilege.",
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Review Cilium network policies and enforce least privilege",
                        "Audit eBPF program attachments and verify legitimacy",
                        "Check for unauthorized network connections between pods",
                        "Monitor for continued policy violations and anomalous traffic"
                    ]
                    ))

        # Check for Tetragon filesystem tampering
        tetragon_paths = ['/sys/kernel/security/tetragon', '/var/lib/tetragon']
        for tpath in tetragon_paths:
            if os.path.exists(tpath):
                try:
                    stat_info = os.stat(tpath)
                    mod_time = stat_info.st_mtime
                    mod_date = datetime.fromtimestamp(mod_time)
                    hours_since_mod = (datetime.now() - mod_date).total_seconds() / 3600

                    if hours_since_mod < 1:
                        evidences.append(self._create_evidence(
                            title="Recent Tetragon Filesystem Modification",
                            description=f"Tetragon path {tpath} was modified {hours_since_mod:.1f} hours ago. "
                                       f"May indicate tampering with runtime security.",
                            severity=Severity.HIGH,
                            confidence=0.70,
                            attack_id="T1562.008",
                            attack_tactic="Defense Evasion",
                            source_path=tpath,
                            raw_data={"path": tpath, "hours_ago": hours_since_mod},
                            remediation="Verify Tetragon modification was authorized. Check deployment logs.",
                            evidence_details=EvidenceDetail(
                                content=""
                            ),
                            remediation_commands=[
                        "Review Cilium network policies and enforce least privilege",
                        "Audit eBPF program attachments and verify legitimacy",
                        "Check for unauthorized network connections between pods",
                        "Monitor for continued policy violations and anomalous traffic"
                    ]
                        ))
                except OSError:
                    pass

        return evidences

    def _extract_namespace(self, content: str) -> str:
        """Extract Kubernetes namespace from CRD content"""
        ns_match = re.search(r'metadata:\s*\n\s+namespace:\s*(\S+)', content, re.MULTILINE)
        if not ns_match:
            # Try alternative pattern with flexible whitespace
            ns_match = re.search(r'namespace:\s*(\S+)', content)
        if ns_match:
            return ns_match.group(1).strip()
        return "unknown"

    def _calculate_file_hash(self, filepath: str) -> Optional[str]:
        """Calculate SHA256 hash of a file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except OSError:
            return None

    def _apply_whitelist_filtering(self, evidences: List[Evidence]) -> List[Evidence]:
        """Apply whitelist filtering to reduce false positives"""
        if not self._whitelist_manager:
            return evidences

        filtered = []
        for evidence in evidences:
            evidence_dict = {
                'title': evidence.title,
                'description': evidence.description,
                'severity': evidence.severity.value if hasattr(evidence.severity, 'value') else str(evidence.severity),
                'raw_data': evidence.raw_data or {},
            }

            rule = self._whitelist_manager.is_whitelisted(evidence_dict)
            if rule:
                _get_logger().debug(f"[{self.name}] Whitelisted evidence: {evidence.title} (rule: {rule.id})")
                if rule.severity_override:
                    try:
                        from ..reporter.severity import Severity as SevEnum
                        override_severity = getattr(SevEnum, rule.severity_override.upper(), None)
                        if override_severity:
                            evidence.severity = override_severity
                            evidence.raw_data['whitelisted'] = True
                            evidence.raw_data['whitelist_rule'] = rule.id
                    except (ValueError, TypeError, AttributeError) as e:
                        _get_logger().debug(f"[{self.name}] Failed to apply severity override: {e}")
            filtered.append(evidence)

        return filtered

    def _create_evidence(self, title: str, description: str, severity: Severity,
                        confidence: float, attack_id: str, attack_tactic: str,
                        source_path: str = "", raw_data: dict = None,
                        remediation: str = "", evidence_details=None,
                        remediation_commands=None) -> Evidence:
        """Create evidence with consistent formatting"""
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
            raw_data=raw_data or {},
            remediation=remediation,
            verified_status="unverified",
            timestamp=timestamp,
            evidence_details=evidence_details,
            remediation_commands=remediation_commands or []
        )
