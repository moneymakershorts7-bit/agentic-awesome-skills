"""DNS tunneling detection mixin for NetworkAnalyzer.

Contains methods for detecting:
- Unusually long DNS queries
- High-entropy subdomain patterns
- High-frequency DNS requests
- TXT record abuse
- Known DNS tunneling tools
"""
import math
from typing import Dict, List

from .constants import (
    DNS_TUNNEL_DOMAIN_LENGTH_THRESHOLD,
    DNS_HIGH_ENTROPY_THRESHOLD,
    DNS_QUERY_RATE_THRESHOLD,
    DNS_TUNNEL_TOOLS,
)
from ...reporter.evidence import Evidence, EvidenceDetail, Severity


class DnsTunnelMixin:
    """Mixin providing DNS tunneling detection capabilities."""

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            text: Input string

        Returns:
            Entropy value (higher = more random)
        """
        if not text:
            return 0.0

        # Count character frequencies
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def _detect_dns_tunneling(self, collected_data: dict) -> List[Evidence]:
        """Detect DNS tunneling for data exfiltration and C2 communication

        Detects:
        - Unusually long DNS queries (>50 chars)
        - High-entropy subdomain patterns (random-looking)
        - High-frequency DNS requests
        - TXT record abuse
        - Known DNS tunneling tools

        ATT&CK: T1048.001, T1071.004
        """
        evidences = []

        if not collected_data:
            return evidences

        try:
            dns_data = self._get_data(collected_data, "dns")
        except KeyError:
            return evidences

        dns_queries = dns_data.get('queries', [])
        domain_query_count = {}

        for query in dns_queries:
            domain = query.get('domain', '')
            query_type = query.get('type', '')

            if not domain:
                continue

            base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            domain_query_count[base_domain] = domain_query_count.get(base_domain, 0) + 1

            evidences.extend(self._check_dns_long_domain(domain, query_type))
            evidences.extend(self._check_dns_high_entropy(domain, query_type))
            evidences.extend(self._check_dns_txt_abuse(domain, query_type))

        evidences.extend(self._check_dns_high_frequency(domain_query_count))
        evidences.extend(self._check_dns_tunnel_tools(collected_data))

        return evidences

    def _check_dns_long_domain(self, domain: str, query_type: str) -> List[Evidence]:
        """Check for unusually long domain names indicating DNS tunneling."""
        if len(domain) <= DNS_TUNNEL_DOMAIN_LENGTH_THRESHOLD:
            return []

        evidence_detail = EvidenceDetail(
            local_address=None,
            remote_address=domain,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any port 53 -l -n",
            f"dig {domain}",
            "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
        ]
        return [self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.001",
            title=f"DNS Tunneling Indicator: Long Domain",
            description=f"Unusually long DNS query detected ({len(domain)} chars): {domain[:100]}...",
            confidence=0.6,
            raw_data={
                "domain": domain,
                "length": len(domain),
                "query_type": query_type,
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]

    def _check_dns_high_entropy(self, domain: str, query_type: str) -> List[Evidence]:
        """Check for high-entropy subdomains indicating random-looking names."""
        if '.' not in domain:
            return []

        subdomain = domain.split('.')[0]
        if len(subdomain) <= 10:
            return []

        entropy = self._calculate_entropy(subdomain)
        if entropy <= DNS_HIGH_ENTROPY_THRESHOLD:
            return []

        evidence_detail = EvidenceDetail(
            local_address=None,
            remote_address=domain,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any port 53 -l -n",
            f"dig {domain}",
            "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
        ]
        return [self._create_evidence(
            severity=Severity.MEDIUM,
            attack_id="T1048.001",
            title=f"DNS Tunneling Indicator: High Entropy",
            description=f"High-entropy subdomain detected (entropy={entropy:.2f}): {subdomain}",
            confidence=0.65,
            raw_data={
                "domain": domain,
                "subdomain": subdomain,
                "entropy": entropy,
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]

    def _check_dns_txt_abuse(self, domain: str, query_type: str) -> List[Evidence]:
        """Check for TXT record abuse commonly used for DNS tunneling."""
        if query_type != 'TXT' or len(domain) <= 30:
            return []

        evidence_detail = EvidenceDetail(
            local_address=None,
            remote_address=domain,
            connection_state=None,
            pid=None,
        )
        remediation_cmds = [
            "tcpdump -i any port 53 -l -n",
            f"dig TXT {domain}",
            "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
        ]
        return [self._create_evidence(
            severity=Severity.LOW,
            attack_id="T1048.001",
            title=f"DNS Tunneling Indicator: TXT Record",
            description=f"Long TXT query detected (potential C2/exfil): {domain[:100]}...",
            confidence=0.5,
            raw_data={
                "domain": domain,
                "query_type": query_type,
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )]

    def _check_dns_high_frequency(self, domain_query_count: Dict[str, int]) -> List[Evidence]:
        """Check for high-frequency DNS requests to same domain (potential beaconing)."""
        evidences = []

        for base_domain, count in domain_query_count.items():
            if count < DNS_QUERY_RATE_THRESHOLD:
                continue

            evidence_detail = EvidenceDetail(
                local_address=None,
                remote_address=base_domain,
                connection_state=None,
                pid=None,
            )
            remediation_cmds = [
                "tcpdump -i any port 53 -l -n",
                f"dig {base_domain}",
                "systemctl status named 2>/dev/null || systemctl status dnsmasq 2>/dev/null",
            ]
            evidences.append(self._create_evidence(
                severity=Severity.MEDIUM,
                attack_id="T1071.004",
                title=f"DNS Tunneling Indicator: High Frequency",
                description=f"High-frequency DNS queries to {base_domain} ({count} queries)",
                confidence=0.7,
                raw_data={
                    "domain": base_domain,
                    "query_count": count,
                },
                evidence_details=evidence_detail,
                remediation_commands=remediation_cmds,
            ))

        return evidences

    def _check_dns_tunnel_tools(self, collected_data: dict) -> List[Evidence]:
        """Check for known DNS tunneling tools running as processes."""
        evidences = []

        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            return evidences

        for proc in process_data.get("processes", []):
            cmdline = proc.get("cmdline", "").lower()
            comm = proc.get("comm", "").lower()
            pid = proc.get("pid", 0)

            for tool in DNS_TUNNEL_TOOLS:
                if tool not in cmdline and tool not in comm:
                    continue

                evidence_detail = EvidenceDetail(
                    local_address=None,
                    remote_address=None,
                    connection_state=None,
                    pid=pid if pid else None,
                )
                remediation_cmds = [
                    f"kill -9 {pid}" if pid else "kill -9 <pid>",
                    f"ps aux | grep {tool}",
                    f"netstat -tlnp | grep {pid}" if pid else "netstat -tlnp",
                ]
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1048.001",
                    title=f"DNS Tunneling Tool Detected: {tool}",
                    description=f"Detected DNS tunneling tool {tool} running (PID {pid})",
                    confidence=0.85,
                    raw_data={
                        "pid": pid,
                        "tool": tool,
                        "cmdline": cmdline[:200],
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
                break

        return evidences
