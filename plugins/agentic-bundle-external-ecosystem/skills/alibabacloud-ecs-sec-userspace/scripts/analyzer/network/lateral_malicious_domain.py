"""Lateral movement and malicious domain detection mixins.

Contains methods for:
- Malicious domain detection (full and quick mode)
- Lateral movement detection
"""
from typing import Dict, List

from .helpers import (
    _get_logger, _get_attack_tactic_name, _get_cloud_whitelist,
    _get_security_db,
)
from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .constants import LATERAL_MOVEMENT_PATTERNS


class LateralMaliciousDomainMixin:
    """Mixin providing lateral movement and malicious domain detection."""

    def _detect_malicious_domains(self, network_data: dict) -> List[Evidence]:
        """Detect connections to malicious domains using security database."""
        evidences = []

        try:
            get_security_db_manager, _ = _get_security_db()
            is_cloud_service_endpoint = _get_cloud_whitelist()
            db_manager = get_security_db_manager()

            dns_queries = network_data.get("dns_queries", [])
            checked_domains = set()

            for query in dns_queries:
                domain = query.get("domain", "")
                if not domain or domain in checked_domains:
                    continue
                checked_domains.add(domain)

                is_cloud, provider, reason = is_cloud_service_endpoint(domain=domain)
                if is_cloud:
                    _get_logger().debug(f"Cloud service domain whitelisted: {domain} ({provider})")
                    continue

                threat_info = db_manager.is_malicious_domain(domain)
                if threat_info:
                    evidence_detail = EvidenceDetail(
                        local_address=None, remote_address=domain,
                        connection_state=None, pid=None,
                    )
                    remediation_cmds = [
                        f"dig {domain}", f"nslookup {domain}",
                        f"iptables -A OUTPUT -d {domain} -j DROP",
                        f"echo '0.0.0.0 {domain}' >> /etc/hosts",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1071.001",
                        attack_tactic=_get_attack_tactic_name(attack_id="T1071.001"),
                        title=f"Malicious domain detected: DNS query {domain}",
                        description=f"Detected DNS query to known malicious domain {domain} "
                                   f"(threat type: {threat_info.threat_type}, "
                                   f"confidence: {threat_info.confidence:.2f}, "
                                   f"source: {threat_info.source})",
                        confidence=threat_info.confidence,
                        raw_data={
                            "domain": domain, "threat_type": threat_info.threat_type,
                            "source": threat_info.source, "query": query
                        },
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().warning(f"Malicious domain detection failed: {e}")

        return evidences
    def _detect_lateral_movement(self, network_data: Dict) -> List[Evidence]:
        """Detect lateral movement patterns. ATT&CK: T1021"""
        evidences = []

        if not network_data:
            return evidences

        connections = network_data.get('connections', [])

        for conn in connections:
            cmdline = conn.get('cmdline', '')

            for pattern, desc in LATERAL_MOVEMENT_PATTERNS:
                if pattern.search(cmdline):
                    local_pid = conn.get('pid', 0)
                    local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                    remote_addr = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"
                    evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
                        remote_address=remote_addr if remote_addr != ":" else None,
                        connection_state=conn.get('state') or None,
                        pid=local_pid if local_pid else None,
                    )
                    remediation_cmds = [
                        f"netstat -tlnp | grep {local_pid}" if local_pid else "netstat -tlnp",
                        f"kill -9 {local_pid}" if local_pid else "kill -9 <pid>",
                        "ss -tnp",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH, attack_id='T1021',
                        attack_tactic='Lateral Movement', title=desc,
                        description=f'Connection: {cmdline[:200]}',
                        confidence=0.65, source_path='network_connections',
                        raw_data={'pattern': desc},
                        remediation='Verify remote connections are authorized.',
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break

        return evidences
