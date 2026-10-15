"""Runtime monitoring mixin - eBPF, Hubble, agent health, binary integrity."""
import os
import re
import subprocess
import hashlib
import shutil
from typing import List, Optional
from datetime import datetime

from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity
from .constants import (
    CILIUM_AGENT_PATTERNS, SUSPICIOUS_CILIUM_FLAGS, EXPECTED_EBPF_PROGRAMS,
    CRITICAL_EBPF_MAPS, HUBBLE_INDICATORS, SUSPICIOUS_HUBBLE_PATTERNS,
    ATTACK_ID, ATTACK_TACTIC, CAPACITY_THRESHOLDS, BPF_PATHS, HUBBLE_DIRS,
    CRITICAL_EBPF_HOOKS, EXPECTED_BINARY_SIZES, OFFICIAL_CILIUM_HASHES,
    CILIUM_DIRS, CILIUM_BPF_MARKERS, CLUSTER_SIZE_THRESHOLDS,
    CILIUM_PROCESS_INDICATORS,
)
from .helpers import _get_logger


class RuntimeMonitorMixin:
    """Mixin providing eBPF, Hubble, agent health, and binary integrity monitoring."""

    def _is_cilium_environment(self, collected_data: dict) -> bool:
        score = 0
        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            process_data = {}
        if isinstance(process_data, dict):
            processes = process_data.get("processes", [])
            for proc in processes:
                cmdline = proc.get("cmdline", "").lower()
                comm = proc.get("comm", "").lower()
                for indicator in CILIUM_PROCESS_INDICATORS:
                    if indicator in cmdline or indicator in comm:
                        _get_logger().info(f"[{self.name}] Cilium process detected: {indicator}")
                        score += 1
                        break
                if score > 0:
                    break
        dir_score = sum(1 for cdir in CILIUM_DIRS if os.path.exists(cdir))
        if dir_score >= 1:
            score += 1
        bpf_score = sum(1 for bp in CILIUM_BPF_MARKERS if os.path.exists(bp))
        if bpf_score >= 1:
            score += 1
        if shutil.which('cilium') is not None:
            score += 1
        if os.path.exists('/etc/systemd/system/cilium.service'):
            score += 1
        is_cilium = score >= 2
        _get_logger().info(f"[{self.name}] Cilium environment {'confirmed' if is_cilium else 'not detected'} (score={score})")
        return is_cilium

    def _detect_cluster_size(self, network_data: dict) -> str:
        endpoints = network_data.get("endpoints", []) if isinstance(network_data, dict) else []
        count = len(endpoints)
        if count < CLUSTER_SIZE_THRESHOLDS['small']: return 'small'
        elif count < CLUSTER_SIZE_THRESHOLDS['medium']: return 'medium'
        elif count < CLUSTER_SIZE_THRESHOLDS['large']: return 'large'
        else: return 'xlarge'

    def _verify_cilium_agents(self, process_data: dict) -> List[Evidence]:
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        cilium_agents_found = []
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            for pattern, description in CILIUM_AGENT_PATTERNS:
                if pattern.search(cmdline) or pattern.search(proc.get("comm", "")):
                    cilium_agents_found.append({'pid': pid, 'cmdline': cmdline, 'comm': proc.get("comm", ""), 'description': description})
                    for flag_pattern, flag_desc in SUSPICIOUS_CILIUM_FLAGS:
                        if flag_pattern.search(cmdline):
                            evidences.append(self._create_evidence(
                                title=f"Suspicious Cilium Flag: {flag_desc}",
                                description=f"Cilium process (PID: {pid}) has suspicious flag: {flag_desc}.",
                                severity=Severity.HIGH, confidence=0.85, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                                source_path=f"/proc/{pid}/cmdline", raw_data={"pid": pid, "cmdline": cmdline[:300]},
                                remediation="Review Cilium agent flags.",
                                evidence_details=EvidenceDetail(pid=proc.get('pid', 0), cmdline=proc.get('cmdline', '')[:300],
                                    executable=proc.get('exe', ''), file_path=proc.get('file_path', proc.get('path', '')),
                                    remote_address=proc.get('remote_address', proc.get('ip', '')),
                                    connection_state=proc.get('state', ''), content=proc.get('agent_id', proc.get('server_name', ''))),
                                remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                                    "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
                            ))
                    exe_path = f"/proc/{pid}/exe"
                    if os.path.exists(exe_path):
                        try:
                            h = self._calculate_file_hash(exe_path)
                            if h: _get_logger().debug(f"[{self.name}] Cilium binary hash (PID {pid}): {h}")
                        except OSError:
                            pass
                    break
        agent_by_namespace = {}
        for agent in cilium_agents_found:
            pid = agent['pid']
            ns_id = None
            try:
                if os.path.exists(f"/proc/{pid}/ns/net"):
                    ns_id = os.stat(f"/proc/{pid}/ns/net").st_ino
            except OSError:
                pass
            key = (agent['description'], ns_id)
            agent_by_namespace.setdefault(key, []).append(agent)
        for (desc, ns_id), agents in agent_by_namespace.items():
            if len(agents) > 1:
                alert = agents[0]
                evidences.append(self._create_evidence(
                    title=f"Multiple Cilium Agent Instances on Same Node: {desc}",
                    description=f"Found {len(agents)} instances of {desc}.",
                    severity=Severity.CRITICAL, confidence=0.85, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                    raw_data={"description": desc, "count": len(agents), "namespace_id": ns_id, "pids": [a['pid'] for a in agents]},
                    remediation="Verify only one legitimate Cilium agent per node.",
                    evidence_details=EvidenceDetail(pid=alert.get('pid', 0), cmdline=alert.get('cmdline', '')[:300],
                        executable=alert.get('exe', ''), remote_address=alert.get('remote_address', alert.get('ip', '')),
                        connection_state=alert.get('state', ''), content=alert.get('container_id', '')),
                    remediation_commands=["Inspect container runtime configuration", "Review pod security policies and context",
                        "Check container image provenance and signatures", "Audit Kubernetes RBAC and network policies"],
                ))
        for agent in cilium_agents_found:
            pid = agent['pid']
            status_file = f"/proc/{pid}/status"
            if os.path.exists(status_file):
                try:
                    with open(status_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.startswith('Uid:'):
                                uid = int(line.split()[1])
                                if uid != 0:
                                    evidences.append(self._create_evidence(
                                        title="Cilium Agent Not Running as Root",
                                        description=f"Cilium agent (PID: {pid}) running as UID {uid}.",
                                        severity=Severity.HIGH, confidence=0.75, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                                        source_path=status_file, raw_data={"pid": pid, "uid": uid},
                                        remediation="Ensure cilium-agent runs with proper privileges.",
                                        evidence_details=EvidenceDetail(pid=agent.get('pid', 0), cmdline=agent.get('cmdline', '')[:300],
                                            executable=agent.get('exe', ''), file_path=agent.get('file_path', agent.get('path', '')),
                                            remote_address=agent.get('remote_address', agent.get('ip', '')),
                                            connection_state=agent.get('state', ''), user=agent.get('user', ''),
                                            content=agent.get('container_id', '')),
                                        remediation_commands=["Investigate user activity and lock account if compromised",
                                            "Review user authentication logs", "Check for unauthorized access from this user"],
                                    ))
                                break
                except OSError:
                    pass
        return evidences

    def _check_ebpf_program_integrity(self, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        try:
            result = subprocess.run(['bpftool', 'prog', 'list'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
            if result.returncode == 0:
                evidences.extend(self._parse_ebpf_programs(result.stdout))
            else:
                _get_logger().debug(f"[{self.name}] bpftool prog list failed")
        except (subprocess.TimeoutExpired, OSError) as e:
            _get_logger().debug(f"[{self.name}] Cannot run bpftool: {e}")
            evidences.extend(self._scan_bpf_filesystem())
        return evidences

    def _parse_ebpf_programs(self, prog_list: str) -> List[Evidence]:
        evidences = []
        found = []
        for line in prog_list.strip().split('\n'):
            if not line.strip(): continue
            prog_name = None
            m = re.search(r'name\s+"([^"]+)"', line)
            if m: prog_name = m.group(1)
            else:
                for part in line.split():
                    if part.startswith('cil_'): prog_name = part; break
            if prog_name:
                found.append(prog_name)
                if prog_name.startswith('cil_') and prog_name not in EXPECTED_EBPF_PROGRAMS:
                    evidences.append(self._create_evidence(
                        title=f"Unknown Cilium eBPF Program: {prog_name}",
                        description=f"Found unexpected eBPF program '{prog_name}'.",
                        severity=Severity.HIGH, confidence=0.75, attack_id="T1611", attack_tactic="Lateral Movement",
                        raw_data={"program_name": prog_name}, remediation="Verify eBPF program legitimacy.",
                        evidence_details=EvidenceDetail(remote_address="", connection_state=""),
                        remediation_commands=["Review Cilium network policies and enforce least privilege",
                            "Audit eBPF program attachments and verify legitimacy",
                            "Check for unauthorized network connections between pods",
                            "Monitor for continued policy violations and anomalous traffic"],
                    ))
        for p in EXPECTED_EBPF_PROGRAMS:
            if p not in found: _get_logger().debug(f"[{self.name}] Expected program not found: {p}")
        return evidences

    def _scan_bpf_filesystem(self) -> List[Evidence]:
        evidences = []
        for bpf_path in BPF_PATHS:
            if not os.path.exists(bpf_path): continue
            try:
                for item in os.listdir(bpf_path):
                    if not item.startswith('cil_'): continue
                    full_path = os.path.join(bpf_path, item)
                    mod_date = datetime.fromtimestamp(os.stat(full_path).st_mtime)
                    mins = (datetime.now() - mod_date).total_seconds() / 60
                    if mins < 5: continue
                    if mins < 1440:
                        evidences.append(self._create_evidence(
                            title=f"Recently Modified eBPF Program: {item}",
                            description=f"eBPF program {full_path} modified {mins:.0f} minutes ago.",
                            severity=Severity.MEDIUM, confidence=0.7, attack_id="T1611", attack_tactic="Lateral Movement",
                            source_path=full_path, raw_data={"path": full_path, "minutes_ago": mins},
                            remediation="Verify eBPF program modification was authorized.",
                            evidence_details=EvidenceDetail(file_path=item, remote_address="", connection_state="", content=""),
                            remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                                "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
                        ))
            except OSError:
                pass
        return evidences

    def _analyze_ebpf_maps(self, filesystem_data: dict, cluster_size: str = 'small') -> List[Evidence]:
        evidences = []
        threshold = CAPACITY_THRESHOLDS.get(cluster_size, 1000)
        try:
            result = subprocess.run(['bpftool', 'map', 'list'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
            if result.returncode == 0:
                evidences.extend(self._parse_ebpf_maps(result.stdout, threshold))
        except (subprocess.TimeoutExpired, OSError):
            pass
        evidences.extend(self._scan_ebpf_map_files(threshold))
        return evidences

    def _parse_ebpf_maps(self, map_list: str, capacity_threshold: int = 1000) -> List[Evidence]:
        evidences = []
        for line in map_list.strip().split('\n'):
            if not line.strip(): continue
            for map_name, map_desc in CRITICAL_EBPF_MAPS:
                if map_name in line:
                    if re.search(r'flags\s+0x[89a-fA-F]', line):
                        evidences.append(self._create_evidence(
                            title=f"Suspicious eBPF Map Flags: {map_name}", description=f"eBPF map {map_name} has unusual flags.",
                            severity=Severity.HIGH, confidence=0.75, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                            raw_data={"map_name": map_name}, remediation="Verify map flags.",
                            evidence_details=EvidenceDetail(remote_address="", connection_state=""),
                            remediation_commands=["Review Cilium network policies and enforce least privilege",
                                "Audit eBPF program attachments and verify legitimacy",
                                "Check for unauthorized network connections between pods",
                                "Monitor for continued policy violations and anomalous traffic"],
                        ))
                    cap_match = re.search(r'max_entries\s+(\d+)', line)
                    if cap_match:
                        max_e = int(cap_match.group(1))
                        if max_e > capacity_threshold * 10:
                            evidences.append(self._create_evidence(
                                title=f"Unusually Large eBPF Map Capacity: {map_name}",
                                description=f"eBPF map {map_name} has capacity {max_e}, threshold {capacity_threshold}.",
                                severity=Severity.MEDIUM, confidence=0.65, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                                raw_data={"map_name": map_name, "max_entries": max_e},
                                remediation="Verify map capacity settings.", evidence_details=EvidenceDetail(remote_address="", connection_state=""),
                                remediation_commands=["Review Cilium network policies and enforce least privilege",
                                    "Audit eBPF program attachments and verify legitimacy",
                                    "Check for unauthorized network connections between pods",
                                    "Monitor for continued policy violations and anomalous traffic"],
                            ))
                    break
        return evidences

    def _scan_ebpf_map_files(self, capacity_threshold: int = 1000) -> List[Evidence]:
        evidences = []
        for bpf_path in BPF_PATHS:
            if not os.path.exists(bpf_path): continue
            try:
                items = os.listdir(bpf_path)
                for map_name, map_desc in CRITICAL_EBPF_MAPS:
                    for item in items:
                        if map_name in item:
                            full_path = os.path.join(bpf_path, item)
                            mod_date = datetime.fromtimestamp(os.stat(full_path).st_mtime)
                            hours = (datetime.now() - mod_date).total_seconds() / 3600
                            if hours < 24:
                                evidences.append(self._create_evidence(
                                    title=f"Recently Modified eBPF Map: {item}",
                                    description=f"eBPF map {item} ({map_desc}) modified {hours:.1f} hours ago.",
                                    severity=Severity.LOW, confidence=0.6, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                                    source_path=full_path, raw_data={"map": item, "hours_ago": hours},
                                    remediation="Verify map modification was part of normal Cilium operations.",
                                    evidence_details=EvidenceDetail(file_path=item, remote_address="", connection_state=""),
                                    remediation_commands=["Review Cilium network policies and enforce least privilege",
                                        "Audit eBPF program attachments and verify legitimacy",
                                        "Check for unauthorized network connections between pods",
                                        "Monitor for continued policy violations and anomalous traffic"],
                                ))
            except OSError:
                pass
        return evidences

    def _validate_hubble_telemetry(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        hubble_detected = False
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            for pattern, description in HUBBLE_INDICATORS:
                if pattern.search(cmdline) or pattern.search(comm):
                    hubble_detected = True
                    pid = proc.get("pid", 0)
                    for hp, hd in SUSPICIOUS_HUBBLE_PATTERNS:
                        if hp.search(cmdline):
                            evidences.append(self._create_evidence(
                                title=f"Hubble Configuration Issue: {hd}",
                                description=f"Hubble process (PID: {pid}): {hd}.",
                                severity=Severity.MEDIUM, confidence=0.75, attack_id="T1070.002", attack_tactic="Indicator Removal",
                                source_path=f"/proc/{pid}/cmdline", raw_data={"pid": pid, "issue": hd},
                                remediation="Enable Hubble flow logging and TLS.",
                                evidence_details=EvidenceDetail(pid=proc.get('pid', 0), cmdline=proc.get('cmdline', '')[:300],
                                    executable=proc.get('exe', ''), file_path=proc.get('file_path', proc.get('path', '')),
                                    remote_address=proc.get('remote_address', proc.get('ip', '')), connection_state=proc.get('state', '')),
                                remediation_commands=["Review Cilium network policies and enforce least privilege",
                                    "Audit eBPF program attachments and verify legitimacy",
                                    "Check for unauthorized network connections between pods",
                                    "Monitor for continued policy violations and anomalous traffic"],
                            ))
                    break
        if not hubble_detected:
            for d in ['/etc/hubble', '/var/lib/hubble']:
                if os.path.exists(d): hubble_detected = True; break
        if hubble_detected:
            evidences.extend(self._scan_hubble_configs())
        return evidences

    def _scan_hubble_configs(self) -> List[Evidence]:
        evidences = []
        for base_dir in HUBBLE_DIRS:
            if not os.path.isdir(base_dir): continue
            try:
                for root, dirs, files in os.walk(base_dir):
                    for fn in files:
                        if not fn.endswith(('.yaml', '.yml', '.json')): continue
                        fp = os.path.join(root, fn)
                        try:
                            with open(fp, 'r', errors='replace', encoding='utf-8') as f: content = f.read()
                            for pattern, description in SUSPICIOUS_HUBBLE_PATTERNS:
                                if pattern.search(content):
                                    evidences.append(self._create_evidence(
                                        title=f"Hubble Config Issue: {description}", description=f"Hubble config {fp}: {description}.",
                                        severity=Severity.MEDIUM, confidence=0.7, attack_id="T1070.002", attack_tactic="Indicator Removal",
                                        source_path=fp, raw_data={"file": fp, "issue": description},
                                        remediation="Enable all Hubble observability features.",
                                        evidence_details=EvidenceDetail(content=""),
                                        remediation_commands=["Review Cilium network policies and enforce least privilege",
                                            "Audit eBPF program attachments and verify legitimacy",
                                            "Check for unauthorized network connections between pods",
                                            "Monitor for continued policy violations and anomalous traffic"],
                                    )); break
                        except OSError: continue
            except OSError: continue
        return evidences

    def _validate_ebpf_program_attachments(self) -> List[Evidence]:
        evidences = []
        try:
            result = subprocess.run(['bpftool', 'net', 'list'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
            if result.returncode == 0:
                output = result.stdout.lower()
                for hook in CRITICAL_EBPF_HOOKS:
                    if hook not in output:
                        evidences.append(self._create_evidence(
                            title=f"Critical eBPF Hook Not Attached: {hook}",
                            description=f"Cilium eBPF program for {hook} hook is not attached.",
                            severity=Severity.CRITICAL, confidence=0.80, attack_id="T1562.008", attack_tactic="Defense Evasion",
                            raw_data={"missing_hook": hook, "expected_programs": [p for p in EXPECTED_EBPF_PROGRAMS if hook in p.lower()]},
                            remediation="Restart Cilium agent to reattach eBPF programs.",
                            evidence_details=EvidenceDetail(content=f"Missing eBPF hook: {hook}"),
                            remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                                "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
                        ))
            else:
                _get_logger().debug(f"[{self.name}] bpftool net list failed")
        except (subprocess.TimeoutExpired, OSError):
            _get_logger().debug(f"[{self.name}] Cannot validate eBPF attachments")
        return evidences

    def _verify_cilium_agent_integrity(self, process_data: dict) -> List[Evidence]:
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            if 'cilium-agent' not in cmdline and 'cilium-operator' not in cmdline: continue
            binary_type = "cilium-agent" if 'cilium-agent' in cmdline else "cilium-operator"
            exe_path = f"/proc/{pid}/exe"
            if not os.path.exists(exe_path): continue
            evidences.extend(self._verify_cilium_binary(binary_type, pid, exe_path, proc))
        return evidences

    def _verify_cilium_binary(self, binary_type: str, pid: int, exe_path: str, proc: dict) -> List[Evidence]:
        evidences = []
        h = self._calculate_file_hash(exe_path)
        if not h: return evidences
        _get_logger().debug(f"[{self.name}] Cilium binary hash ({binary_type}, PID {pid}): {h}")
        evidences.extend(self._check_binary_modification(binary_type, pid, exe_path, h, proc))
        evidences.extend(self._check_binary_size(binary_type, pid, exe_path, proc))
        evidences.extend(self._check_debug_symbols(binary_type, exe_path, proc))
        return evidences

    def _check_binary_modification(self, binary_type: str, pid: int, exe_path: str, binary_hash: str, proc: dict) -> List[Evidence]:
        evidences = []
        try:
            mod_date = datetime.fromtimestamp(os.stat(exe_path).st_mtime)
            days = (datetime.now() - mod_date).total_seconds() / 86400
            if days >= 7: return evidences
            if self._matches_official_hash(binary_type, binary_hash):
                _get_logger().info(f"[{self.name}] Cilium binary matches official release hash")
                return evidences
            evidences.append(self._create_evidence(
                title=f"Cilium Agent Binary Recently Modified: {binary_type}",
                description=f"Cilium {binary_type} binary (PID: {pid}) modified {days:.1f} days ago. Hash: {binary_hash}.",
                severity=Severity.CRITICAL, confidence=0.85, attack_id="T1562.008", attack_tactic="Defense Evasion",
                source_path=exe_path, raw_data={"binary_type": binary_type, "pid": pid, "binary_hash": binary_hash,
                    "modified_days_ago": round(days, 1), "modification_date": mod_date.isoformat(), "matches_official": False},
                remediation="Verify Cilium binary integrity against official releases.",
                evidence_details=EvidenceDetail(pid=proc.get('pid', 0), cmdline=proc.get('cmdline', '')[:300],
                    executable=proc.get('exe', ''), file_path=proc.get('file_path', proc.get('path', '')),
                    remote_address=proc.get('remote_address', proc.get('ip', '')), connection_state=proc.get('state', ''),
                    content=proc.get('agent_id', proc.get('server_name', ''))),
                remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                    "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
            ))
        except OSError:
            pass
        return evidences

    def _matches_official_hash(self, binary_type: str, binary_hash: str) -> bool:
        for version, binaries in OFFICIAL_CILIUM_HASHES.items():
            if binary_type in binaries and binaries[binary_type].endswith(binary_hash):
                return True
        return False

    def _check_binary_size(self, binary_type: str, pid: int, exe_path: str, proc: dict) -> List[Evidence]:
        evidences = []
        if binary_type not in EXPECTED_BINARY_SIZES: return evidences
        try:
            size = os.stat(exe_path).st_size
            min_s, max_s = EXPECTED_BINARY_SIZES[binary_type]
            if min_s <= size <= max_s: return evidences
            evidences.append(self._create_evidence(
                title=f"Cilium Agent Binary Size Anomaly: {binary_type}",
                description=f"Cilium {binary_type} binary size ({size/1e6:.1f}MB) outside expected range ({min_s/1e6:.0f}-{max_s/1e6:.0f}MB).",
                severity=Severity.HIGH, confidence=0.75, attack_id="T1562.008", attack_tactic="Defense Evasion",
                source_path=exe_path, raw_data={"binary_type": binary_type, "pid": pid, "actual_size_mb": round(size/1e6, 1)},
                remediation="Use official Cilium binaries for production.",
                evidence_details=EvidenceDetail(pid=proc.get('pid', 0), cmdline=proc.get('cmdline', '')[:300],
                    executable=proc.get('exe', ''), file_path=proc.get('file_path', proc.get('path', '')),
                    remote_address=proc.get('remote_address', proc.get('ip', '')), connection_state=proc.get('state', ''),
                    content=proc.get('agent_id', proc.get('server_name', ''))),
                remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                    "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
            ))
        except OSError:
            pass
        return evidences

    def _check_debug_symbols(self, binary_type: str, exe_path: str, proc: dict) -> List[Evidence]:
        evidences = []
        try:
            result = subprocess.run(['file', exe_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            if result.returncode == 0 and 'not stripped' in result.stdout.lower():
                evidences.append(self._create_evidence(
                    title="Cilium Agent Binary Has Debug Symbols",
                    description=f"Cilium {binary_type} binary contains debug symbols.",
                    severity=Severity.LOW, confidence=0.65, attack_id="T1562.008", attack_tactic="Defense Evasion",
                    source_path=exe_path, raw_data={"binary_type": binary_type, "file_info": result.stdout[:200]},
                    remediation="Use official Cilium binaries for production.",
                    evidence_details=EvidenceDetail(pid=proc.get('pid', 0), cmdline=proc.get('cmdline', '')[:300],
                        executable=proc.get('exe', ''), file_path=proc.get('file_path', proc.get('path', '')),
                        remote_address=proc.get('remote_address', proc.get('ip', '')), connection_state=proc.get('state', ''),
                        content=proc.get('agent_id', proc.get('server_name', ''))),
                    remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
                ))
        except (subprocess.TimeoutExpired, OSError):
            pass
        return evidences

    def _calculate_file_hash(self, filepath: str) -> Optional[str]:
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except OSError:
            return None
