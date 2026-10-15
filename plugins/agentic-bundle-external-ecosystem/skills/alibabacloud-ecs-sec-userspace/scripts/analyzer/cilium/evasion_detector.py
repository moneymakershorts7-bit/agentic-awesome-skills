"""Evasion detection mixin - Tetragon evasion, VoidLink eBPF map tampering."""
import os
import re
import json
import subprocess
from typing import List
from datetime import datetime

from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity
from .constants import (
    TETRAGON_INDICATORS, TETRAGON_EVASION_PATTERNS, VOIDLINK_PATTERNS,
    ATTACK_ID, ATTACK_TACTIC, CRITICAL_MAP_PATHS, TETRAGON_PATHS,
)
from .helpers import _get_logger


class EvasionDetectorMixin:
    """Mixin providing evasion detection capabilities."""

    def _detect_tetragon_evasion(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        tetragon_detected = False
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            for pattern, description in TETRAGON_INDICATORS:
                if pattern.search(cmdline) or pattern.search(comm):
                    tetragon_detected = True
                    break
        if os.path.exists('/sys/kernel/security/tetragon'):
            tetragon_detected = True
        if not tetragon_detected:
            return evidences
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            for pattern, description, severity in TETRAGON_EVASION_PATTERNS:
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title=f"Tetragon Evasion: {description}",
                        description=f"Process (PID: {pid}) shows Tetragon evasion indicator: {description}.",
                        severity=severity, confidence=0.85, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                        source_path=f"/proc/{pid}/cmdline", raw_data={"pid": pid, "cmdline": cmdline[:300]},
                        remediation="Investigate process immediately.",
                        evidence_details=EvidenceDetail(pid=proc.get('pid', 0), cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''), file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''), content=proc.get('container_id', '')),
                        remediation_commands=["Inspect container runtime configuration", "Review pod security policies and context",
                            "Check container image provenance and signatures", "Audit Kubernetes RBAC and network policies"],
                    ))
                    break
        for tpath in TETRAGON_PATHS:
            if os.path.exists(tpath):
                try:
                    stat_info = os.stat(tpath)
                    mod_date = datetime.fromtimestamp(stat_info.st_mtime)
                    hours_since_mod = (datetime.now() - mod_date).total_seconds() / 3600
                    if hours_since_mod < 1:
                        proc = processes[0] if processes else {}
                        evidences.append(self._create_evidence(
                            title="Recent Tetragon Filesystem Modification",
                            description=f"Tetragon path {tpath} was modified {hours_since_mod:.1f} hours ago.",
                            severity=Severity.HIGH, confidence=0.7, attack_id=ATTACK_ID, attack_tactic=ATTACK_TACTIC,
                            source_path=tpath, raw_data={"path": tpath, "hours_ago": hours_since_mod},
                            remediation="Verify Tetragon modification was authorized.",
                            evidence_details=EvidenceDetail(file_path=proc.get('file_path', proc.get('path', '')),
                                remote_address=proc.get('remote_address', proc.get('ip', '')),
                                connection_state=proc.get('state', '')),
                            remediation_commands=["Review Cilium network policies and enforce least privilege",
                                "Audit eBPF program attachments and verify legitimacy",
                                "Check for unauthorized network connections between pods",
                                "Monitor for continued policy violations and anomalous traffic"],
                        ))
                except OSError:
                    pass
        return evidences

    def _detect_voidlink_ebpf_tampering(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            for pattern, description, severity in VOIDLINK_PATTERNS:
                if pattern.search(cmdline):
                    evidences.append(self._create_evidence(
                        title=f"VoidLink eBPF Tampering: {description}",
                        description=f"Process (PID: {pid}) shows VoidLink attack indicator: {description}.",
                        severity=severity, confidence=0.90, attack_id="T1562.008", attack_tactic="Defense Evasion",
                        source_path=f"/proc/{pid}/cmdline", raw_data={"pid": pid, "cmdline": cmdline[:300]},
                        remediation="Investigate process immediately.",
                        evidence_details=EvidenceDetail(pid=proc.get('pid', 0), cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''), file_path=proc.get('file_path', proc.get('path', '')),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')),
                        remediation_commands=["Review Cilium network policies and enforce least privilege",
                            "Audit eBPF program attachments and verify legitimacy",
                            "Check for unauthorized network connections between pods",
                            "Monitor for continued policy violations and anomalous traffic"],
                    ))
                    break
        for map_path in CRITICAL_MAP_PATHS:
            if os.path.exists(map_path):
                try:
                    stat_info = os.stat(map_path)
                    mod_date = datetime.fromtimestamp(stat_info.st_mtime)
                    minutes_since_mod = (datetime.now() - mod_date).total_seconds() / 60
                    if 5 <= minutes_since_mod <= 1440:
                        evidences.append(self._create_evidence(
                            title=f"Cilium eBPF Map Modified During Runtime: {os.path.basename(map_path)}",
                            description=f"Critical Cilium eBPF map {map_path} was modified {minutes_since_mod:.0f} minutes ago.",
                            severity=Severity.HIGH, confidence=0.75, attack_id="T1562.008", attack_tactic="Defense Evasion",
                            source_path=map_path, raw_data={"map_path": map_path, "modified_ago_minutes": round(minutes_since_mod, 1)},
                            remediation="Verify map modification was authorized.",
                            evidence_details=EvidenceDetail(content=""),
                            remediation_commands=["Review agent configuration and tool permissions",
                                "Audit prompt inputs for injection attempts", "Verify skill/plugin sources and integrity",
                                "Restrict agent tool access to minimum required"],
                        ))
                except OSError:
                    pass
        return evidences

    def _detect_conntrack_flow_discrepancy(self) -> List[Evidence]:
        evidences = []
        try:
            conntrack_result = subprocess.run(['conntrack', '-L', '-o', 'extended'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
            if conntrack_result.returncode != 0:
                _get_logger().debug(f"[{self.name}] Cannot read kernel conntrack table")
                return evidences
            kernel_connections = set()
            for line in conntrack_result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                src_ip = dst_ip = src_port = dst_port = ""
                for i, part in enumerate(parts):
                    if part == 'src' and i+1 < len(parts): src_ip = parts[i+1]
                    elif part == 'dst' and i+1 < len(parts): dst_ip = parts[i+1]
                    elif part == 'sport' and i+1 < len(parts): src_port = parts[i+1]
                    elif part == 'dport' and i+1 < len(parts): dst_port = parts[i+1]
                if src_ip and dst_ip:
                    kernel_connections.add(f"{parts[0]}:{src_ip}:{src_port}->{dst_ip}:{dst_port}")
            cilium_flows = set()
            try:
                hubble_result = subprocess.run(['hubble', 'observe', '--last', '1000', '-o', 'json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
                if hubble_result.returncode == 0:
                    for line in hubble_result.stdout.strip().split('\n'):
                        if not line.strip():
                            continue
                        try:
                            flow = json.loads(line)
                            l4 = flow.get('l4', {})
                            proto = 'tcp' if 'tcp' in l4 else 'udp' if 'udp' in l4 else None
                            if not proto:
                                continue
                            src_ip = flow.get('ip', {}).get('source', '')
                            dst_ip = flow.get('ip', {}).get('destination', '')
                            src_port = str(l4[proto].get('source_port', ''))
                            dst_port = str(l4[proto].get('destination_port', ''))
                            if src_ip and dst_ip:
                                cilium_flows.add(f"{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}")
                        except json.JSONDecodeError:
                            continue
            except (subprocess.TimeoutExpired, OSError):
                return evidences
            hidden = kernel_connections - cilium_flows
            ratio = len(hidden) / max(len(kernel_connections), 1)
            if len(hidden) > 5 or ratio > 0.10:
                evidences.append(self._create_evidence(
                    title="Conntrack vs Hubble Flow Discrepancy Detected",
                    description=f"Found {len(hidden)} connections in kernel conntrack but not in Hubble flows (discrepancy: {ratio:.1%}).",
                    severity=Severity.CRITICAL if len(hidden) > 10 else Severity.HIGH, confidence=0.85,
                    attack_id="T1070.002", attack_tactic="Indicator Removal", source_path="/proc/net/nf_conntrack",
                    raw_data={"kernel_connections_count": len(kernel_connections), "cilium_flows_count": len(cilium_flows),
                        "hidden_connections_count": len(hidden), "discrepancy_ratio": round(ratio, 3)},
                    remediation="Investigate potential conntrack manipulation.",
                    evidence_details=EvidenceDetail(content=""),
                    remediation_commands=["Review Cilium network policies and enforce least privilege",
                        "Audit eBPF program attachments and verify legitimacy",
                        "Check for unauthorized network connections between pods",
                        "Monitor for continued policy violations and anomalous traffic"],
                ))
        except (subprocess.TimeoutExpired, OSError) as e:
            _get_logger().debug(f"[{self.name}] Cannot perform conntrack analysis: {e}")
        return evidences

    def _check_cilium_agent_anomalies(self, process_data: dict, filesystem_data: dict) -> List[Evidence]:
        evidences = []
        cilium_agents = []
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if 'cilium-agent' in cmdline:
                pid = proc.get("pid", 0)
                uptime_seconds = 0
                try:
                    stat_file = f"/proc/{pid}/stat"
                    if os.path.exists(stat_file):
                        with open(stat_file, 'r', encoding='utf-8') as f:
                            fields = f.read().split()
                        if len(fields) >= 22:
                            clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
                            starttime_ticks = int(fields[21])
                            boot_time = datetime.now().timestamp() - (os.path.getmtime('/proc/uptime'))
                            uptime_seconds = datetime.now().timestamp() - (boot_time + starttime_ticks / clk_tck)
                except ImportError:
                    pass
                version_match = re.search(r'--version\s*=?\s*(\S+)', cmdline)
                cilium_agents.append({'pid': pid, 'uptime_seconds': uptime_seconds,
                    'version': version_match.group(1) if version_match else "unknown", 'cmdline': cmdline[:200]})
        if len(cilium_agents) > 1:
            versions = set(a['version'] for a in cilium_agents if a['version'] != "unknown")
            if len(versions) > 1:
                agent = cilium_agents[0]
                evidences.append(self._create_evidence(
                    title="Multiple Cilium Agent Versions Detected",
                    description=f"Found {len(cilium_agents)} agents with {len(versions)} versions: {', '.join(versions)}.",
                    severity=Severity.HIGH, confidence=0.80, attack_id="T1578.002", attack_tactic="Defense Evasion",
                    raw_data={"agent_count": len(cilium_agents), "versions": list(versions)},
                    remediation="Ensure all Cilium agents are same version.",
                    evidence_details=EvidenceDetail(remote_address=agent.get('remote_address', agent.get('ip', '')),
                        connection_state=agent.get('state', ''), content=agent.get('agent_id', agent.get('server_name', ''))),
                    remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
                ))
        for agent in cilium_agents:
            if 0 < agent['uptime_seconds'] < 600:
                evidences.append(self._create_evidence(
                    title=f"Cilium Agent Recently Restarted (PID: {agent['pid']})",
                    description=f"Agent running for only {agent['uptime_seconds']:.0f} seconds.",
                    severity=Severity.MEDIUM, confidence=0.70, attack_id="T1562.008", attack_tactic="Defense Evasion",
                    raw_data={"pid": agent['pid'], "uptime_seconds": agent['uptime_seconds']},
                    remediation="Check Cilium agent logs for crash reasons.",
                    evidence_details=EvidenceDetail(pid=agent.get('pid', 0), cmdline=agent.get('cmdline', '')[:300],
                        executable=agent.get('exe', ''), remote_address=agent.get('remote_address', agent.get('ip', '')),
                        connection_state=agent.get('state', ''), content=agent.get('agent_id', agent.get('server_name', ''))),
                    remediation_commands=["Review agent configuration and tool permissions", "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity", "Restrict agent tool access to minimum required"],
                ))
        return evidences
