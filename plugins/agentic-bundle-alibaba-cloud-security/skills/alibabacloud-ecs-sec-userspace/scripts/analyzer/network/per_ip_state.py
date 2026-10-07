"""Per-IP TCP connection state anomaly detection mixin.

Contains methods for:
- Per-IP connection state collection
- Per-IP CLOSE_WAIT/TIME_WAIT/FIN_WAIT anomaly detection
"""
from typing import Dict, List, Tuple

from .helpers import _get_logger, _get_attack_tactic_name, _get_defaultdict
from .constants import (
    PER_IP_CLOSE_WAIT_THRESHOLD, PER_IP_TIME_WAIT_THRESHOLD, PER_IP_FIN_WAIT_THRESHOLD,
)
from ...reporter.evidence import Evidence, EvidenceDetail, Severity


class PerIPStateAnomalyMixin:
    """Mixin providing per-IP TCP connection state anomaly detection."""

    def _collect_per_ip_states(self, connections: List[Dict]) -> Tuple[Dict, Dict]:
        """Group connection states by remote IP."""
        defaultdict_cls = _get_defaultdict()
        ip_state_counts = defaultdict_cls(lambda: defaultdict_cls(int))
        ip_state_details = defaultdict_cls(lambda: defaultdict_cls(list))

        for conn in connections:
            state = conn.get("state", "")
            remote_ip = conn.get("remote_ip", "")

            if not state or not remote_ip:
                continue

            if remote_ip in ["127.0.0.1", "::1"]:
                continue

            should_suppress, _ = self._should_suppress_connection(conn)
            if should_suppress:
                continue

            ip_state_counts[remote_ip][state] += 1

            if len(ip_state_details[remote_ip][state]) < 5:
                ip_state_details[remote_ip][state].append({
                    "local_port": conn.get("local_port", 0),
                    "remote_port": conn.get("remote_port", 0),
                    "pid": conn.get("pid", 0),
                    "process_name": conn.get("process_name", ""),
                })

        return ip_state_counts, ip_state_details

    def _check_per_ip_close_wait(self, ip: str, state_counts: Dict, ip_state_details: Dict) -> List[Evidence]:
        """Check per-IP CLOSE_WAIT anomalies."""
        close_wait_count = state_counts.get("CLOSE_WAIT", 0)
        if close_wait_count <= PER_IP_CLOSE_WAIT_THRESHOLD:
            return []

        processes_involved = set()
        for detail in ip_state_details[ip]["CLOSE_WAIT"]:
            if detail.get("process_name"):
                processes_involved.add(detail["process_name"])

        sample_detail = ip_state_details[ip]["CLOSE_WAIT"][0] if ip_state_details[ip]["CLOSE_WAIT"] else {}
        local_addr = f":{sample_detail.get('local_port', '')}"
        remote_addr = f"{ip}:{sample_detail.get('remote_port', '')}"
        evidence_detail = EvidenceDetail(
            local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state="CLOSE_WAIT",
            pid=sample_detail.get("pid") or None,
        )
        remediation_cmds = [
            f"ss -tnp dst {ip} state close-wait",
            f"netstat -tnp | grep {ip} | grep CLOSE_WAIT",
            f"iptables -A OUTPUT -d {ip} -j DROP",
        ]
        return [self._create_evidence(
            title=f"Per-IP CLOSE_WAIT anomaly: {ip} has {close_wait_count} connections",
            description=(
                f"Remote IP {ip} has {close_wait_count} connections in CLOSE_WAIT state "
                f"(threshold: {PER_IP_CLOSE_WAIT_THRESHOLD}).\n"
                f"This indicates connection leak to specific endpoint - remote side closed "
                f"connections but local application hasn't closed its end.\n"
                f"Top processes: {', '.join(list(processes_involved)[:5]) if processes_involved else 'unknown'}"
            ),
            severity=Severity.MEDIUM,
            confidence=0.80,
            attack_id="T1499",
            attack_tactic=_get_attack_tactic_name("T1499"),
            raw_data={
                "remote_ip": ip,
                "state": "CLOSE_WAIT",
                "count": close_wait_count,
                "threshold": PER_IP_CLOSE_WAIT_THRESHOLD,
                "sample_connections": ip_state_details[ip]["CLOSE_WAIT"][:5],
                "processes": list(processes_involved)[:10],
            },
            remediation=(
                f"Investigate connections to {ip}. "
                f"Check application connection handling to remote endpoint. "
                f"Verify if remote service is misbehaving or under attack."
            ),
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]

    def _check_per_ip_time_wait(self, ip: str, state_counts: Dict, ip_state_details: Dict) -> List[Evidence]:
        """Check per-IP TIME_WAIT anomalies."""
        time_wait_count = state_counts.get("TIME_WAIT", 0)
        if time_wait_count <= PER_IP_TIME_WAIT_THRESHOLD:
            return []

        sample_detail = ip_state_details[ip]["TIME_WAIT"][0] if ip_state_details[ip]["TIME_WAIT"] else {}
        local_addr = f":{sample_detail.get('local_port', '')}"
        remote_addr = f"{ip}:{sample_detail.get('remote_port', '')}"
        evidence_detail = EvidenceDetail(
            local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state="TIME_WAIT",
            pid=sample_detail.get("pid") or None,
        )
        remediation_cmds = [
            f"ss -tnp dst {ip} state time-wait",
            f"netstat -tnp | grep {ip} | grep TIME_WAIT",
            f"iptables -A INPUT -s {ip} -j RATE_LIMIT",
        ]
        return [self._create_evidence(
            title=f"Per-IP TIME_WAIT anomaly: {ip} has {time_wait_count} connections",
            description=(
                f"Remote IP {ip} has {time_wait_count} connections in TIME_WAIT state "
                f"(threshold: {PER_IP_TIME_WAIT_THRESHOLD}).\n"
                f"This may indicate connection storm or rapid connection churn to specific endpoint.\n"
                f"Can exhaust local ports and cause connection failures to this IP."
            ),
            severity=Severity.MEDIUM,
            confidence=0.75,
            attack_id="T1498",
            attack_tactic=_get_attack_tactic_name("T1498"),
            raw_data={
                "remote_ip": ip,
                "state": "TIME_WAIT",
                "count": time_wait_count,
                "threshold": PER_IP_TIME_WAIT_THRESHOLD,
                "sample_connections": ip_state_details[ip]["TIME_WAIT"][:5],
            },
            remediation=(
                f"Review connection pattern to {ip}. "
                f"Check for connection flood or DoS attack targeting this endpoint. "
                f"Consider enabling connection pooling or rate limiting."
            ),
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]

    def _check_per_ip_fin_wait(self, ip: str, state_counts: Dict, ip_state_details: Dict) -> List[Evidence]:
        """Check per-IP FIN_WAIT anomalies."""
        fin_wait1_count = state_counts.get("FIN_WAIT1", 0)
        fin_wait2_count = state_counts.get("FIN_WAIT2", 0)
        total_fin_wait = fin_wait1_count + fin_wait2_count

        if total_fin_wait <= PER_IP_FIN_WAIT_THRESHOLD:
            return []

        evidence_detail = EvidenceDetail(
            local_address=None,
            remote_address=ip,
            connection_state="FIN_WAIT",
            pid=None,
        )
        remediation_cmds = [
            f"ss -tnp dst {ip} state fin-wait-1 state fin-wait-2",
            f"netstat -tnp | grep {ip} | grep FIN_WAIT",
            f"iptables -A INPUT -s {ip} -j DROP",
        ]
        return [self._create_evidence(
            title=f"Per-IP FIN_WAIT anomaly: {ip} has {total_fin_wait} connections",
            description=(
                f"Remote IP {ip} has {total_fin_wait} connections in FIN_WAIT states "
                f"(FIN_WAIT1: {fin_wait1_count}, FIN_WAIT2: {fin_wait2_count}, "
                f"threshold: {PER_IP_FIN_WAIT_THRESHOLD}).\n"
                f"High FIN_WAIT count to specific IP may indicate slow connection "
                f"teardown or network issues with this endpoint."
            ),
            severity=Severity.MEDIUM,
            confidence=0.70,
            attack_id="T1499",
            attack_tactic=_get_attack_tactic_name("T1499"),
            raw_data={
                "remote_ip": ip,
                "state": "FIN_WAIT",
                "fin_wait1_count": fin_wait1_count,
                "fin_wait2_count": fin_wait2_count,
                "total": total_fin_wait,
                "threshold": PER_IP_FIN_WAIT_THRESHOLD,
            },
            remediation=(
                f"Check network connectivity to {ip}. "
                f"Review application connection termination logic for this endpoint. "
                f"Consider tuning TCP timeout parameters."
            ),
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]

    def _detect_per_ip_connection_state_anomalies(self, network_data: Dict) -> List[Evidence]:
        """Detect per-IP TCP connection state anomalies."""
        evidences = []

        if not network_data:
            return evidences

        try:
            all_connections = (
                network_data.get("tcp_connections", []) +
                network_data.get("tcp6_connections", [])
            )

            if not all_connections:
                return evidences

            ip_state_counts, ip_state_details = self._collect_per_ip_states(all_connections)

            for ip, state_counts in ip_state_counts.items():
                evidences.extend(self._check_per_ip_close_wait(ip, state_counts, ip_state_details))
                evidences.extend(self._check_per_ip_time_wait(ip, state_counts, ip_state_details))
                evidences.extend(self._check_per_ip_fin_wait(ip, state_counts, ip_state_details))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Per-IP connection state anomaly detection failed: {e}")

        return evidences
