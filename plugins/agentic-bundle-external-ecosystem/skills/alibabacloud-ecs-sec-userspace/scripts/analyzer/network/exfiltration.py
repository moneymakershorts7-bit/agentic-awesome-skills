"""Data exfiltration detection mixin for NetworkAnalyzer.

Contains methods for detecting:
- DNS tunneling for data exfiltration
- HTTPS exfiltration via unconventional ports
- ICMP tunneling for covert data channels
"""
from typing import List

from .helpers import _get_logger, _get_attack_tactic_name
from .constants import STANDARD_PORTS
from ...reporter.evidence import Evidence, EvidenceDetail, Severity


class ExfiltrationMixin:
    """Mixin providing data exfiltration detection capabilities."""

    def _detect_data_exfiltration(self, network_data: dict, process_data: dict) -> List[Evidence]:
        """Data exfiltration detection (multi-protocol analysis)

        Design intent:
            Detect signs of attackers stealing data through the network

        Detected attack patterns:
            1. DNS tunneling (T1048.001)
            2. HTTP/HTTPS exfiltration (T1041, T1048.003)
            3. ICMP tunneling (T1048.002)

        Args:
            network_data: Network collector output
            process_data: Process collector output

        Returns:
            findings: Data exfiltration evidence list, with protocol type and risk level

        ATT&CK mapping:
            - T1048 - Exfiltration Over Alternative Protocol
            - T1041 - Exfiltration Over C2 Channel
            - T1567 - Exfiltration Over Web Service
        """
        evidences = []

        try:
            # 1. DNS tunneling detection
            evidences.extend(self._detect_dns_exfiltration(network_data))

            # 2. Unconventional port HTTPS exfiltration detection
            evidences.extend(self._detect_https_exfiltration(network_data))

            # 3. ICMP tunneling detection
            evidences.extend(self._detect_icmp_tunneling(network_data))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"T1048 data exfiltration detection failed: {e}")

        return evidences

    def _detect_dns_exfiltration(self, network_data: dict) -> List[Evidence]:
        """Detect DNS tunneling for data exfiltration.

        Checks for ultra-long DNS queries, excessive subdomains, and
        high-frequency DNS request patterns that may indicate data encoding.
        """
        evidences = []
        dns_queries = network_data.get("dns_queries", [])

        if not dns_queries:
            return evidences

        src_query_count = {}
        long_domain_queries = []

        for query in dns_queries:
            src_ip = query.get("src_ip", "")
            domain = query.get("domain", "")

            src_query_count[src_ip] = src_query_count.get(src_ip, 0) + 1

            if len(domain) > 50:
                long_domain_queries.append(query)

            if domain.count('.') > 4:
                long_domain_queries.append(query)

        # High-frequency DNS query detection
        for src_ip, count in src_query_count.items():
            if count > 100:
                evidence_detail = EvidenceDetail(
                    local_address=src_ip if src_ip else None,
                    remote_address=None,
                    connection_state=None,
                    pid=None,
                )
                remediation_cmds = [
                    f"tcpdump -i any port 53 and host {src_ip}",
                    "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
                    f"iptables -A OUTPUT -s {src_ip} -p udp --dport 53 -j LOG",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1048.001",
                    attack_tactic=_get_attack_tactic_name(attack_id="T1048.001"),
                    title=f"Suspected DNS tunneling: {src_ip} high-frequency DNS queries",
                    description=f"Detected {src_ip} initiated {count} DNS queries, possible DNS tunnel data exfiltration",
                    confidence=0.65,
                    raw_data={"src_ip": src_ip, "query_count": count},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))

        # Long domain name detection
        if len(long_domain_queries) >= 5:
            evidence_detail = EvidenceDetail(
                local_address=None,
                remote_address=None,
                connection_state=None,
                pid=None,
            )
            remediation_cmds = [
                "tcpdump -i any port 53 -l -n",
                "cat /var/log/syslog | grep -i dns",
                "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
            ]
            evidences.append(self._create_evidence(
                severity=Severity.HIGH,
                attack_id="T1048.001",
                attack_tactic=_get_attack_tactic_name(attack_id="T1048.001"),
                title="Suspected DNS tunneling: abnormal long domain name queries",
                description=f"Detected {len(long_domain_queries)} abnormal long domain name or multi-level subdomain queries",
                confidence=0.7,
                raw_data={
                    "query_count": len(long_domain_queries),
                    "sample_domains": [q.get("domain") for q in long_domain_queries[:5]]
                },
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))

        return evidences

    def _detect_https_exfiltration(self, network_data: dict) -> List[Evidence]:
        """Detect data exfiltration via unconventional HTTPS ports.

        Looks for ESTABLISHED connections to high ports (>8000) that may
        be used for data exfiltration over non-standard ports.
        """
        evidences = []
        tcp_connections = network_data.get("tcp_connections", [])
        unusual_https = []

        for conn in tcp_connections:
            remote_port = conn.get("remote_port", 0)
            state = conn.get("state", "")

            should_suppress, _ = self._should_suppress_connection(conn)
            if should_suppress:
                continue

            if state == "ESTABLISHED" and remote_port not in STANDARD_PORTS:
                if remote_port > 8000:
                    remote_ip = conn.get("remote_ip", "")
                    if remote_ip not in ["127.0.0.1", "::1"]:
                        unusual_https.append(conn)

        if len(unusual_https) < 3:
            return evidences

        sample_conn = unusual_https[0]
        local_addr = f"{sample_conn.get('local_ip', '')}:{sample_conn.get('local_port', '')}"
        remote_addr = f"{sample_conn.get('remote_ip', '')}:{sample_conn.get('remote_port', '')}"
        evidence_detail = EvidenceDetail(
            local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state=sample_conn.get("state") or None,
            pid=sample_conn.get("pid") or None,
        )
        remediation_cmds = [
            "ss -tnp | grep -E ':(8[0-9]{3}|9[0-9]{3}|[1-9][0-9]{4})'",
            "tcpdump -i any 'tcp portrange 8000-65535'",
            "netstat -tlnp",
        ]
        evidences.append(self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.002",
            attack_tactic=_get_attack_tactic_name(attack_id="T1048.002"),
            title="Suspected data exfiltration: unconventional port connections",
            description=f"Detected {len(unusual_https)} active connections to unconventional high ports, possibly used for data exfiltration",
            confidence=0.5,
            raw_data={
                "connection_count": len(unusual_https),
                "sample_ports": list(set(c.get("remote_port") for c in unusual_https))
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        ))

        return evidences

    def _detect_icmp_tunneling(self, network_data: dict) -> List[Evidence]:
        """Detect ICMP tunneling for data exfiltration.

        Looks for oversized ICMP packets (>100 bytes) in high volumes
        that may indicate covert data channels.
        """
        evidences = []
        icmp_packets = network_data.get("icmp_packets", [])

        if not icmp_packets:
            return evidences

        large_icmp = [p for p in icmp_packets if p.get("size", 0) > 100]

        if len(large_icmp) < 10:
            return evidences

        avg_size = sum(p.get("size", 0) for p in large_icmp) / len(large_icmp)
        evidence_detail = EvidenceDetail(
            local_address=None,
            remote_address=None,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any icmp",
            "sysctl net.ipv4.icmp_echo_ignore_all",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j LOG",
        ]
        evidences.append(self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.003",
            attack_tactic=_get_attack_tactic_name(attack_id="T1048.003"),
            title="Suspected ICMP tunneling: large packet ICMP traffic",
            description=f"Detected {len(large_icmp)} large-sized ICMP packets (>100 bytes), possibly used for ICMP tunneling",
            confidence=0.55,
            raw_data={"packet_count": len(large_icmp), "avg_size": avg_size},
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        ))

        return evidences
