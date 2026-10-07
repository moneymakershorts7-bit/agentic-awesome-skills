"""C2 communication and web protocol abuse detection mixins.

Contains methods for:
- C2 (Command and Control) communication detection
- Web protocol abuse detection

Lateral movement and malicious domain detection are in lateral_malicious_domain.py.
"""
import re
from typing import Dict, List, Optional

from .helpers import _get_logger, _get_attack_tactic_name, _get_cloud_whitelist
from .constants import C2_PATTERNS, SUSPICIOUS_USER_AGENTS, WEB_PROTOCOL_PORTS
from ...reporter.evidence import Evidence, EvidenceDetail, Severity
from .lateral_malicious_domain import LateralMaliciousDomainMixin


class C2AndWebMixin(LateralMaliciousDomainMixin):
    """Mixin providing C2 and web protocol abuse detection."""

    # =========================================================================
    # Web Protocol Abuse Detection
    # =========================================================================

    def _detect_web_protocol_abuse(self, network_data: Dict) -> List[Evidence]:
        """Detect web protocol abuse for C2 communication (T1071.001)."""
        evidences = []

        if not network_data:
            return evidences

        connections = network_data.get('tcp_connections', []) + network_data.get('tcp6_connections', [])

        for conn in connections:
            evidence = self._check_web_protocol_abuse_connection(conn)
            if evidence:
                evidences.append(evidence)

        return evidences

    def _extract_domain_from_cmdline(self, cmdline: str) -> Optional[str]:
        """Extract domain from command line URL."""
        if not cmdline:
            return None
        url_pattern = re.search(r'https?://([a-zA-Z0-9.\-]+)', cmdline)
        return url_pattern.group(1) if url_pattern else None

    def _is_connection_whitelisted(self, conn: Dict) -> bool:
        """Check if connection is whitelisted by cloud service endpoint."""
        cmdline = conn.get('cmdline', '')
        remote_ip = conn.get('remote_ip', '')
        is_cloud_service_endpoint = _get_cloud_whitelist()

        domain = self._extract_domain_from_cmdline(cmdline)
        if domain:
            is_cloud, _, _ = is_cloud_service_endpoint(domain=domain)
            if is_cloud:
                return True

        if remote_ip:
            is_cloud, _, _ = is_cloud_service_endpoint(ip=remote_ip)
            if is_cloud:
                return True

        return False

    def _has_suspicious_user_agent(self, cmdline: str) -> bool:
        """Check if command line has suspicious user agent."""
        return any(ua_pattern.search(cmdline) for ua_pattern in SUSPICIOUS_USER_AGENTS)

    def _has_post_with_encoding(self, cmdline: str) -> bool:
        """Check if command line has POST request with data encoding."""
        return bool(re.search(r'POST.*(-d|--data|Content-Type.*application)', cmdline, re.IGNORECASE))

    def _create_web_protocol_abuse_evidence(self, conn: Dict, indicators: Dict) -> Evidence:
        """Create evidence for web protocol abuse."""
        remote_ip = conn.get('remote_ip', '')
        remote_port = conn.get('remote_port', 0)
        state = conn.get('state', '')
        cmdline = conn.get('cmdline', '')

        local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
        remote_addr = f"{remote_ip}:{remote_port}"

        evidence_detail = EvidenceDetail(
            local_address=local_addr if local_addr != ":" else None,
            remote_address=remote_addr if remote_addr != ":" else None,
            connection_state=state or None,
            pid=conn.get('pid') or None,
        )

        remediation_cmds = [
            f"netstat -tlnp | grep {remote_port}",
            f"curl -v https://{remote_ip}:{remote_port}",
            f"iptables -A OUTPUT -d {remote_ip} -p tcp --dport {remote_port} -j LOG",
        ]

        return self._create_evidence(
            severity=Severity.MEDIUM, attack_id='T1071.001',
            attack_tactic=_get_attack_tactic_name('T1071.001'),
            title='Potential Web Protocol C2 Communication',
            description=(
                f'Suspicious HTTP/HTTPS connection detected:\n'
                f'Remote: {remote_ip}:{remote_port}\n'
                f'Command: {cmdline[:150]}'
            ),
            confidence=0.55, source_path='network_connections',
            raw_data={
                'remote_ip': remote_ip, 'remote_port': remote_port,
                'cmdline': cmdline[:200], 'indicators': indicators,
            },
            remediation='Investigate destination endpoint. Verify if traffic is legitimate.',
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )

    def _check_web_protocol_abuse_connection(self, conn: Dict) -> Optional[Evidence]:
        """Check single connection for web protocol abuse indicators."""
        cmdline = conn.get('cmdline', '')
        remote_port = conn.get('remote_port', 0)
        state = conn.get('state', '')

        if not cmdline or state != 'ESTABLISHED':
            return None

        should_suppress, _ = self._should_suppress_connection(conn)
        if should_suppress:
            return None

        if self._is_connection_whitelisted(conn):
            return None

        if remote_port not in WEB_PROTOCOL_PORTS:
            return None

        has_suspicious_ua = self._has_suspicious_user_agent(cmdline)
        has_post_encoding = self._has_post_with_encoding(cmdline)

        if not has_suspicious_ua and not has_post_encoding:
            return None

        return self._create_web_protocol_abuse_evidence(
            conn,
            indicators={
                'suspicious_ua': has_suspicious_ua,
                'post_with_encoding': has_post_encoding,
            }
        )

    # =========================================================================
    # C2 Communication Detection
    # =========================================================================

    def _detect_c2_communication(self, network_data: Dict) -> List[Evidence]:
        """Detect command and control communication. ATT&CK: T1071, T1573"""
        evidences = []

        if not network_data:
            return evidences

        connections = network_data.get('tcp_connections', []) + network_data.get('tcp6_connections', [])
        is_cloud_service_endpoint = _get_cloud_whitelist()

        for conn in connections:
            cmdline = conn.get('cmdline', '')
            remote_ip = conn.get('remote_ip', '')
            remote_port = conn.get('remote_port', 0)

            domain_in_cmdline = ""
            if cmdline:
                url_pattern = re.search(r'https?://([a-zA-Z0-9.\-]+)', cmdline)
                if url_pattern:
                    domain_in_cmdline = url_pattern.group(1)

            if domain_in_cmdline:
                is_cloud, provider, reason = is_cloud_service_endpoint(domain=domain_in_cmdline)
                if is_cloud:
                    _get_logger().debug(f"C2 detection skipped: cloud service endpoint {domain_in_cmdline} ({provider})")
                    continue

            if remote_ip:
                is_cloud, provider, reason = is_cloud_service_endpoint(ip=remote_ip)
                if is_cloud:
                    _get_logger().debug(f"C2 detection skipped: cloud service IP {remote_ip} ({provider})")
                    continue

            for pattern, desc in C2_PATTERNS:
                if pattern.search(cmdline):
                    local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                    remote_addr = f"{remote_ip}:{remote_port}"
                    evidence_detail = EvidenceDetail(
                        local_address=local_addr if local_addr != ":" else None,
                        remote_address=remote_addr if remote_addr != ":" else None,
                        connection_state=conn.get('state') or None,
                        pid=conn.get('pid') or None,
                    )
                    remediation_cmds = [
                        f"netstat -tlnp | grep {remote_port}",
                        f"kill -9 {conn.get('pid', 0)}" if conn.get('pid') else "kill -9 <pid>",
                        f"iptables -A OUTPUT -d {remote_ip} -j DROP",
                        "ss -tnp",
                    ]
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL, attack_id='T1071',
                        attack_tactic=_get_attack_tactic_name('T1071'),
                        title=f'C2 communication indicator: {desc}',
                        description=f'Connection: {cmdline[:200]}',
                        confidence=0.70, source_path='network_connections',
                        raw_data={'pattern': desc},
                        remediation='Block C2 communication. Isolate system. Investigate.',
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break

        return evidences
