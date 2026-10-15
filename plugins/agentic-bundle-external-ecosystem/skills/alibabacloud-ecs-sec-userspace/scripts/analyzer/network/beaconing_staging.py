"""Connection beaconing and data staging detection mixins for NetworkAnalyzer.

Contains methods for:
- Connection beaconing pattern detection (C2 beaconing)
- Data staging detection before exfiltration
"""
from typing import Dict, List

from .helpers import _get_defaultdict
from .constants import STAGING_PORTS, STAGING_TOOLS
from ...reporter.evidence import Evidence, EvidenceDetail, Severity


class BeaconingStagingMixin:
    """Mixin providing connection beaconing and data staging detection."""

    def _detect_connection_beaconing(self, connections: List[Dict]) -> List[Evidence]:
        """Detect beaconing patterns indicating C2 communication

        Analyzes connection timing patterns to identify:
        - Periodic outbound connections (regular intervals)
        - Consistent connection durations
        - Repeated connections to same destination
        """
        evidences = []

        # Group connections by destination
        defaultdict_cls = _get_defaultdict()
        dest_connections = defaultdict_cls(list)
        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            remote_port = conn.get("remote_port", 0)
            dest_key = f"{remote_ip}:{remote_port}"

            timestamp = conn.get("timestamp", 0)
            if timestamp and remote_ip:
                dest_connections[dest_key].append({
                    "timestamp": timestamp,
                    "local_process": conn.get("process_name", ""),
                    "state": conn.get("state", "")
                })

        # Analyze each destination for beaconing patterns
        for dest_key, conn_list in dest_connections.items():
            if len(conn_list) < 3:
                continue

            # Sort by timestamp
            conn_list.sort(key=lambda x: x["timestamp"])

            # Calculate inter-connection intervals
            intervals = []
            for i in range(1, len(conn_list)):
                interval = conn_list[i]["timestamp"] - conn_list[i-1]["timestamp"]
                if interval > 0:
                    intervals.append(interval)

            if not intervals:
                continue

            # Check for regular intervals (low standard deviation)
            if len(intervals) >= 2:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5

                # Coefficient of variation < 0.3 indicates regular timing
                if avg_interval > 0:
                    cv = std_dev / avg_interval

                    if cv < 0.3 and avg_interval < 3600:  # Regular intervals within 1 hour
                        dest_parts = dest_key.split(":")
                        remote_addr = dest_key
                        evidence_detail = EvidenceDetail(
                            local_address=None,
                            remote_address=remote_addr if remote_addr != ":" else None,
                            connection_state=conn_list[0].get("state") or None,
                            pid=None,
                        )
                        remediation_cmds = [
                            f"netstat -tlnp | grep {dest_parts[0]}" if dest_parts else "netstat -tlnp",
                            f"ss -tnp dst {dest_parts[0]}",
                            f"iptables -A OUTPUT -d {dest_parts[0]} -j DROP",
                        ]
                        evidence = self._create_evidence(
                            title=f"Potential C2 Beaconing Detected",
                            description=(
                                f"Regular connection pattern detected to {dest_key}:\n"
                                f"Average interval: {avg_interval:.1f}s\n"
                                f"Standard deviation: {std_dev:.1f}s\n"
                                f"Connection count: {len(conn_list)}\n"
                                f"This pattern indicates automated C2 communication."
                            ),
                            severity=Severity.HIGH,
                            confidence=0.75,
                            attack_id="T1071.001",
                            attack_tactic="Command and Control",
                            source_path=f"/proc/net/tcp",
                            raw_data={
                                "destination": dest_key,
                                "avg_interval": avg_interval,
                                "std_dev": std_dev,
                                "coefficient_of_variation": cv,
                                "connection_count": len(conn_list),
                                "pattern": "beaconing"
                            },
                            remediation=(
                                f"Investigate connections to {dest_key}. "
                                f"Check if this is legitimate monitoring or update traffic. "
                                f"Block destination if malicious."
                            ),
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        )
                        evidences.append(evidence)

        return evidences

    def _detect_data_staging(self, connections: List[Dict], processes: List[Dict]) -> List[Evidence]:
        """Detect data staging patterns before exfiltration

        Identifies:
        - Large data transfers to external hosts
        - Compression/archival tool usage with network activity
        - Unusual upload/download ratios
        """
        evidences = []

        for conn in connections:
            remote_port = conn.get("remote_port", 0)
            local_process = conn.get("process_name", "").lower()

            # Check for archival/compression tools with network activity
            if any(tool in local_process for tool in STAGING_TOOLS) and remote_port in STAGING_PORTS:
                local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                remote_addr = f"{conn.get('remote_ip', '')}:{remote_port}"
                evidence_detail = EvidenceDetail(
                    local_address=local_addr if local_addr != ":" else None,
                    remote_address=remote_addr if remote_addr != ":" else None,
                    connection_state=conn.get("state") or None,
                    pid=conn.get("pid") or None,
                )
                remediation_cmds = [
                    f"netstat -tlnp | grep {remote_port}",
                    f"ps aux | grep {local_process}",
                    f"lsof -i :{remote_port}",
                ]
                evidence = self._create_evidence(
                    title=f"Potential Data Staging Activity",
                    description=(
                        f"Data staging tool '{local_process}' has active network connection:\n"
                        f"Remote: {conn.get('remote_ip', '')}:{remote_port}\n"
                        f"State: {conn.get('state', '')}"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.70,
                    attack_id="T1560",
                    attack_tactic="Collection",
                    source_path="/proc/net/tcp",
                    raw_data={
                        "process": local_process,
                        "remote_ip": conn.get("remote_ip", ""),
                        "remote_port": remote_port,
                        "pattern": "data_staging"
                    },
                    remediation=(
                        f"Verify if '{local_process}' network activity is authorized. "
                        f"Check for sensitive data compression or transfer."
                    ),
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                )
                evidences.append(evidence)

        return evidences
