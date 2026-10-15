"""Reverse shell detection mixin for NetworkAnalyzer.

Contains methods for:
- Reverse shell detection (full and quick mode)
- Process index building for O(n+m) connection matching
"""
from typing import Dict, List

from .helpers import (
    _get_logger,
    _get_attack_tactic_name,
)
from .constants import SHELL_PATTERNS
from ...reporter.evidence import Evidence, EvidenceDetail, Severity


class ReverseShellMixin:
    """Mixin providing reverse shell detection capabilities."""

    def _build_process_index(self, processes: List[Dict]) -> Dict:
        """Build optimized process index for O(n+m) connection matching."""
        process_index = {}
        shell_pids = set()
        process_inodes = set()
        pid_to_inodes = {}

        for proc in processes:
            pid = proc.get("pid")
            if pid is not None:
                process_index[pid] = proc
                comm = proc.get("comm", "")
                if SHELL_PATTERNS.match(comm):
                    shell_pids.add(pid)

                fd_list = proc.get("fd_list", [])
                proc_inodes = set()
                for fd_info in fd_list:
                    if fd_info.get("type") == "socket":
                        target = fd_info.get("target", "")
                        if "socket:[" in target:
                            try:
                                inode = int(target.split("[")[1].rstrip("]"))
                                proc_inodes.add(inode)
                                process_inodes.add(inode)
                            except (ValueError, IndexError):
                                pass
                pid_to_inodes[pid] = proc_inodes

        return {
            "process_index": process_index,
            "shell_pids": shell_pids,
            "process_inodes": process_inodes,
            "pid_to_inodes": pid_to_inodes,
        }

    def _detect_reverse_shell(self, network_data: dict, process_data: dict) -> List[Evidence]:
        """Detect reverse shell using O(n+m) algorithm."""
        evidences = []

        try:
            processes = process_data.get("processes", [])
            if not processes:
                return evidences

            connection_map = {}
            for conn in network_data.get("tcp_connections", []):
                inode = conn.get("inode", 0)
                if inode > 0:
                    connection_map[inode] = conn

            for proc in processes:
                pid = proc.get("pid")
                comm = proc.get("comm", "")

                if not SHELL_PATTERNS.match(comm):
                    continue

                fd_list = proc.get("fd_list", [])
                for fd_info in fd_list:
                    if fd_info.get("type") != "socket":
                        continue

                    target = fd_info.get("target", "")
                    if "socket:[" not in target:
                        continue

                    try:
                        inode = int(target.split("[")[1].rstrip("]"))
                    except (ValueError, IndexError):
                        continue

                    conn = connection_map.get(inode)
                    if not conn:
                        continue

                    remote_ip = conn.get("remote_ip", "")
                    state = conn.get("state", "")

                    if remote_ip not in ["127.0.0.1", "::1", "0.0.0.0"] and \
                       state in ["ESTABLISHED", "SYN_SENT"]:
                        local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                        remote_addr = f"{remote_ip}:{conn.get('remote_port', '')}"
                        evidence_detail = EvidenceDetail(
                            local_address=local_addr if local_addr != ":" else None,
                            remote_address=remote_addr if remote_addr != ":" else None,
                            connection_state=state or None,
                            pid=pid if pid else None,
                        )
                        remediation_cmds = [
                            f"kill -9 {pid}" if pid else "kill -9 <pid>",
                            f"netstat -tlnp | grep {pid}" if pid else "netstat -tlnp | grep <pid>",
                            f"iptables -A OUTPUT -d {remote_ip} -j DROP",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"Reverse shell detected: PID {pid} ({comm}) connected to external address {remote_ip}",
                            severity=Severity.CRITICAL,
                            attack_id="T1059.004",
                            attack_tactic=_get_attack_tactic_name("T1059.004"),
                            confidence=0.95,
                            description=f"Shell process holds external network connection: {remote_ip}:{conn.get('remote_port', '')}",
                            raw_data={"pid": pid, "connection": conn},
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Reverse shell detection failed: {e}")

        return evidences
