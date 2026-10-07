"""Port scanning and hidden connection detection mixins for NetworkAnalyzer.

Contains methods for:
- Suspicious listening port detection
- Hidden connection detection
- Port scanning detection
- Process reputation checks
- Environment awareness (dev environment detection)
- Cloud system process identification
- Connection suppression logic

Reverse shell detection is in reverse_shell.py.
"""
from typing import List

from .helpers import (
    _get_os_module, _get_subprocess_module, _get_logger,
    _get_attack_tactic_name, _get_fp_tracker,
)
from .constants import (
    PORT_WHITELIST, PROCESS_WHITELIST, CLOUD_PROCESS_PATTERNS,
)
from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .reverse_shell import ReverseShellMixin


class PortAndShellMixin(ReverseShellMixin):
    """Mixin providing port and shell detection capabilities."""

    # =========================================================================
    # Suspicious Port Detection
    # =========================================================================

    def _detect_suspicious_ports(self, network_data: dict) -> List[Evidence]:
        """Detect suspicious listening ports with environment awareness"""
        evidences = []

        try:
            listening_ports = network_data.get("listening_ports", [])

            for port_info in listening_ports:
                port = port_info.get("port", 0)
                process_name = port_info.get("process", "")
                pid = port_info.get("pid", 0)
                listen_ip = port_info.get("ip", "")

                if listen_ip in ("0.0.0.0", "::", "::0", "*"):
                    continue

                if port > 1024 and port not in PORT_WHITELIST:
                    if self._is_cloud_system_process(process_name):
                        continue

                    if process_name not in PROCESS_WHITELIST:
                        context = f"{process_name}:{port}"
                        _, is_false_positive_fn, record_fp_fn = _get_fp_tracker()
                        if is_false_positive_fn('network_analyzer', 'suspicious_listening_port',
                                           context=context):
                            record_fp_fn('network_analyzer', 'suspicious_listening_port',
                                     context=f'Suppressed: {context}')
                            continue

                        confidence = 0.5
                        verified_status = "pending"

                        if pid and self._check_process_reputation(pid, process_name):
                            confidence = 0.3
                            verified_status = "likely_fp"

                        if self._is_dev_environment():
                            confidence = max(confidence - 0.1, 0.2)

                        local_addr = f"{listen_ip}:{port}"
                        remote_addr = f"0.0.0.0:{port}"
                        evidence_detail = EvidenceDetail(
                            local_address=local_addr if local_addr != ":" else None,
                            remote_address=None,
                            connection_state="LISTEN",
                            pid=pid if pid else None,
                        )
                        remediation_cmds = [
                            f"netstat -tlnp | grep {port}",
                            f"kill -9 {pid}" if pid else "kill -9 <pid>",
                            f"lsof -i :{port}",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"Suspicious listening port: {port} (process: {process_name})",
                            severity=Severity.MEDIUM,
                            attack_id="T1571",
                            attack_tactic=_get_attack_tactic_name("T1571"),
                            confidence=confidence,
                            description=f"Non-standard port {port} listened by process {process_name}",
                            raw_data=port_info,
                            verified_status=verified_status,
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Suspicious port detection failed: {e}")

        return evidences

    def _check_process_reputation(self, pid: int, process_name: str) -> bool:
        """Check if process is reputable (installed via package manager)."""
        try:
            os_module = _get_os_module()
            subprocess_module = _get_subprocess_module()
            exe_path = os_module.readlink(f"/proc/{pid}/exe")

            result = subprocess_module.run(
                ["dpkg", "-S", exe_path],
                stdout=subprocess_module.PIPE, stderr=subprocess_module.PIPE, universal_newlines=True, timeout=3
            )
            if result.returncode == 0:
                return True

            result = subprocess_module.run(
                ["rpm", "-qf", exe_path],
                stdout=subprocess_module.PIPE, stderr=subprocess_module.PIPE, universal_newlines=True, timeout=3
            )
            if result.returncode == 0:
                return True

        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass

        return False

    def _is_cloud_system_process(self, process_name: str) -> bool:
        """Check if process is a cloud provider system process."""
        if process_name in PROCESS_WHITELIST:
            return True

        for pattern in CLOUD_PROCESS_PATTERNS:
            if pattern.search(process_name):
                return True

        return False

    def _is_dev_environment(self) -> bool:
        """Detect if running on a development/workstation environment."""
        os_module = _get_os_module()
        dev_indicators = [
            os_module.path.expanduser("~/.vscode"),
            os_module.path.expanduser("~/.cursor"),
            os_module.path.expanduser("~/.qoder"),
            os_module.path.expanduser("~/.config/JetBrains"),
            os_module.path.expanduser("~/.npm"),
            os_module.path.expanduser("~/.cargo"),
            os_module.path.expanduser("~/.local/share/virtualenvs"),
        ]

        found = sum(1 for p in dev_indicators if os_module.path.exists(p))
        return found >= 2

    # =========================================================================
    # Hidden Connection Detection
    # =========================================================================

    def _should_suppress_connection(self, conn: dict) -> tuple:
        """Enhanced suppression with cloud/container context."""
        from .helpers import _is_cloud_metadata_ip, _is_container_network_ip, _is_service_mesh_port

        remote_ip = conn.get("remote_ip", "")
        remote_port = conn.get("remote_port", 0)

        if _is_cloud_metadata_ip(remote_ip):
            return True, "Cloud provider metadata service"

        if _is_container_network_ip(remote_ip):
            return True, "Container network traffic"

        is_mesh, mesh_desc = _is_service_mesh_port(remote_port)
        if is_mesh:
            return True, f"Service mesh port ({mesh_desc})"

        return False, ""

    def _detect_hidden_connections(self, network_data: dict, process_data: dict) -> List[Evidence]:
        """Detect hidden connections using optimized process index."""
        evidences = []

        try:
            processes = process_data.get("processes", [])
            process_index = self._build_process_index(processes)
            process_inodes = process_index["process_inodes"]

            orphaned = []
            for conn in network_data.get("tcp_connections", []):
                inode = conn.get("inode", 0)
                state = conn.get("state", "")
                remote_ip = conn.get("remote_ip", "")
                local_ip = conn.get("local_ip", "")
                remote_port = conn.get("remote_port", "")

                if remote_ip in ["127.0.0.1", "::1"] or local_ip in ["127.0.0.1", "::1"]:
                    continue

                should_suppress, _ = self._should_suppress_connection(conn)
                if should_suppress:
                    continue

                if remote_port in PORT_WHITELIST:
                    continue

                if state == "ESTABLISHED" and inode > 0 and inode not in process_inodes:
                    orphaned.append(conn)

            if len(orphaned) >= 5:
                for conn in orphaned:
                    inode = conn.get("inode", 0)
                    local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                    remote_addr = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"
                    evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
                        remote_address=remote_addr if remote_addr != ":" else None,
                        connection_state=conn.get("state") or None,
                        pid=conn.get("pid") or None,
                    )
                    remediation_cmds = [
                        f"netstat -tlnp | grep {inode}",
                        "ls -la /proc/*/fd | grep socket",
                        "ss -tlnp",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"Hidden connection detected: inode {inode} in network connections but no corresponding process",
                        severity=Severity.HIGH,
                        attack_id="T1205.001",
                        attack_tactic=_get_attack_tactic_name("T1205.001"),
                        confidence=0.7,
                        description=f"Connection {conn.get('local_ip', '')}:{conn.get('local_port', 0)} -> {conn.get('remote_ip', '')}:{conn.get('remote_port', 0)} inode not found in processes",
                        raw_data=conn,
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Hidden connection detection failed: {e}")

        return evidences

    # =========================================================================
    # Port Scanning Detection
    # =========================================================================

    def _detect_port_scanning(self, network_data: dict) -> List[Evidence]:
        """Detect port scanning behavior (T1046 - Remote Service Scan Discovery)"""
        evidences = []

        try:
            target_ip_connections = {}

            for conn in network_data.get("tcp_connections", []):
                remote_ip = conn.get("remote_ip", "")
                state = conn.get("state", "")

                if remote_ip in ["127.0.0.1", "::1"]:
                    continue

                should_suppress, _ = self._should_suppress_connection(conn)
                if should_suppress:
                    continue

                if state not in ["ESTABLISHED", "SYN_SENT"]:
                    continue

                if remote_ip not in target_ip_connections:
                    target_ip_connections[remote_ip] = []
                target_ip_connections[remote_ip].append(conn)

            for ip, connections in target_ip_connections.items():
                unique_ports = set(conn.get("remote_port", 0) for conn in connections)

                if len(unique_ports) >= 5:
                    sample_conn = connections[0]
                    local_addr = f"{sample_conn.get('local_ip', '')}:{sample_conn.get('local_port', '')}"
                    remote_addr = f"{ip}:{list(unique_ports)[0]}"
                    evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
                        remote_address=remote_addr if remote_addr != ":" else None,
                        connection_state=sample_conn.get("state") or None,
                        pid=sample_conn.get("pid") or None,
                    )
                    remediation_cmds = [
                        f"netstat -tlnp | grep {ip}",
                        f"ss -tnp dst {ip}",
                        f"iptables -A OUTPUT -d {ip} -j DROP",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1046",
                        attack_tactic=_get_attack_tactic_name(attack_id="T1046"),
                        title=f"Suspected port scanning: target {ip}",
                        description=f"Detected {len(connections)} connections to {ip}, involving {len(unique_ports)} different ports",
                        confidence=0.6,
                        raw_data={
                            "target_ip": ip,
                            "connection_count": len(connections),
                            "unique_ports": list(unique_ports)[:20],
                            "ports_count": len(unique_ports)
                        },
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Port scanning detection failed: {e}")

        return evidences
