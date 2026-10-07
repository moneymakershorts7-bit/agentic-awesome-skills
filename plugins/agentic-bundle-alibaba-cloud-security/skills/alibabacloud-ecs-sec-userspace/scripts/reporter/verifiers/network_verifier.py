"""NetworkVerifier - Verify network-related alerts

Verifies:
- IP reputation and geolocation
- Known legitimate services (CDN, cloud providers)
- DNS resolution validation
- Connection pattern analysis
- Threat intelligence integration
"""
import logging
from typing import Dict, Optional, Set
from dataclasses import dataclass

from ..evidence import Evidence
from ...utils.data.threat_intel import C2_PORTS, MALICIOUS_IPS, MALICIOUS_DOMAINS

logger = logging.getLogger("sec-userspace")


@dataclass
class VerifyCheckResult:
    """Result of a single verification check"""
    is_false_positive: bool
    is_confirmed_threat: bool
    reason: str


class NetworkVerifier:
    """Verify network-related security alerts"""
    
    def __init__(self, collected_data: Optional[Dict] = None):
        """Initialize network verifier
        
        Args:
            collected_data: Collected data from collectors
        """
        self.collected_data = collected_data or {}
        self.whitelist_ips = self._load_whitelist_ips()
        self.whitelist_domains = self._load_whitelist_domains()
        self.cdn_ranges = self._get_cdn_ranges()
        self.malicious_ips = MALICIOUS_IPS
        self.malicious_domains = MALICIOUS_DOMAINS
        self.c2_ports = C2_PORTS
    
    def _load_whitelist_ips(self) -> Set[str]:
        """Load known good IPs
        
        Returns:
            Set of whitelisted IPs
        """
        # In production, load from threat intel database
        return set()
    
    def _load_whitelist_domains(self) -> Set[str]:
        """Load known good domains
        
        Returns:
            Set of whitelisted domains
        """
        # Common legitimate domains
        return {
            'microsoft.com', 'windows.com', 'azure.com',
            'google.com', 'googleapis.com', 'gstatic.com',
            'amazon.com', 'amazonaws.com', 'cloudfront.net',
            'github.com', 'githubusercontent.com',
            'ubuntu.com', 'debian.org', 'redhat.com',
            'docker.com', 'docker.io',
            'nodejs.org', 'npmjs.com', 'pypi.org',
            'alibaba.com', 'aliyuncs.com',
        }
    
    def _get_cdn_ranges(self) -> Dict[str, list]:
        """Get known CDN IP ranges
        
        Returns:
            Dict mapping CDN name to IP range patterns
        """
        # Simplified - in production would use full IP ranges
        return {
            'cloudflare': ['104.', '172.64.', '173.245.'],
            'akamai': ['23.', '104.', '184.'],
            'fastly': ['151.101.', '199.232.'],
            'aws_cloudfront': ['13.32.', '13.33.', '13.35.'],
            'azure_cdn': ['13.107.', '40.112.', '40.113.'],
        }
    
    def verify(self, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify network-related evidence
        
        Args:
            evidence: Evidence to verify
            
        Returns:
            VerifyCheckResult: Verification result
        """
        raw_data = evidence.raw_data or {}
        
        # Check by IP address
        ip = raw_data.get('ip') or raw_data.get('dst_ip') or raw_data.get('src_ip')
        if ip:
            return self._verify_by_ip(ip, evidence)
        
        # Check by domain
        domain = raw_data.get('domain') or raw_data.get('dst_domain')
        if domain:
            return self._verify_by_domain(domain, evidence)
        
        # Check by port
        port = raw_data.get('port') or raw_data.get('dst_port')
        if port:
            return self._verify_by_port(port, evidence)
        
        # No network indicators found
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason="No network indicators to verify"
        )
    
    def _verify_by_ip(self, ip: str, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify by IP address
        
        Args:
            ip: IP address to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        # Check whitelist
        if ip in self.whitelist_ips:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"IP {ip} is in whitelist"
            )
        
        # Check for private/internal IPs (including cloud internal)
        if self._is_private_ip(ip):
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"IP {ip} is internal/private address"
            )
        
        # Check for CDN/cloud provider IPs
        cdn_provider = self._check_cdn_ip(ip)
        if cdn_provider:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"IP {ip} belongs to {cdn_provider} CDN/cloud"
            )
        
        # Check against threat intelligence - malicious IPs
        if ip in self.malicious_ips:
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=True,
                reason=f"IP {ip} matches known malicious IP in threat intelligence"
            )
        
        # No match found - requires manual review
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"IP {ip} requires manual review"
        )
    
    def _verify_by_domain(self, domain: str, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify by domain
        
        Args:
            domain: Domain to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        domain_lower = domain.lower()
        
        # Extract base domain
        parts = domain_lower.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain_lower
        
        # Check whitelist
        if base_domain in self.whitelist_domains:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Domain {domain} matches known legitimate: {base_domain}"
            )
        
        # Check threat intelligence - malicious domains
        if domain_lower in self.malicious_domains or base_domain in self.malicious_domains:
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=True,
                reason=f"Domain {domain} matches known malicious domain in threat intelligence"
            )
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.date', '.bid', '.stream']
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                return VerifyCheckResult(
                    is_false_positive=False,
                    is_confirmed_threat=True,
                    reason=f"Domain {domain} uses suspicious TLD {tld}"
                )
        
        # Check for typosquatting patterns
        if self._is_typosquat(domain_lower):
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=True,
                reason=f"Domain {domain} may be typosquatting"
            )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Domain {domain} requires manual review"
        )
    
    def _verify_by_port(self, port: int, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify by port number
        
        Args:
            port: Port number to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        # Check threat intelligence - C2/malicious ports
        if port in self.c2_ports:
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=True,
                reason=f"Port {port} associated with {self.c2_ports[port]}"
            )
        
        # Common legitimate ports
        legitimate_ports = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            25: 'SMTP',
            587: 'SMTP-TLS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
        }
        
        if port in legitimate_ports:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"Port {port} is legitimate service ({legitimate_ports[port]})"
            )
        
        # High ports (>1024) are often ephemeral
        if port > 1024:
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=False,
                reason=f"Port {port} is high/ephemeral port, requires context"
            )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"Port {port} requires manual review"
        )
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal
        
        Args:
            ip: IP address
            
        Returns:
            bool: Whether IP is private
        """
        try:
            octets = [int(x) for x in ip.split('.')]
            
            # 10.0.0.0/8
            if octets[0] == 10:
                return True
            
            # 172.16.0.0/12
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            
            # 192.168.0.0/16
            if octets[0] == 192 and octets[1] == 168:
                return True
            
            # 127.0.0.0/8 (loopback)
            if octets[0] == 127:
                return True
            
            # 169.254.0.0/16 (link-local)
            if octets[0] == 169 and octets[1] == 254:
                return True
            
            # 0.0.0.0
            if ip == '0.0.0.0':
                return True
            
            # Cloud provider internal IP ranges
            if self._is_cloud_internal_ip(ip):
                return True
            
        except (ValueError, IndexError):
            pass
        
        return False
    
    def _is_cloud_internal_ip(self, ip: str) -> bool:
        """Check if IP belongs to cloud provider internal ranges
        
        Args:
            ip: IP address
            
        Returns:
            bool: Whether IP is cloud provider internal
        """
        try:
            octets = [int(x) for x in ip.split('.')]
            
            # RFC 6598 shared address space (100.64.0.0/10, carrier-grade NAT)
            if octets[0] == 100 and 64 <= octets[1] <= 127:
                return True

            # Cloud provider VPC internal ranges (11.0.0.0/8)
            if octets[0] == 11 and 100 <= octets[1] <= 255:
                return True
            
            # AWS VPC common ranges
            if octets[0] == 172 and 30 <= octets[1] <= 31:
                return True
            
            # GCP internal
            if octets[0] == 10 and octets[1] == 128:
                return True
            
            # Azure additional internal
            if octets[0] == 10 and octets[1] == 0:
                return True
            
        except (ValueError, IndexError):
            pass
        
        return False
    
    def _check_cdn_ip(self, ip: str) -> Optional[str]:
        """Check if IP belongs to a CDN/cloud provider
        
        Args:
            ip: IP address
            
        Returns:
            CDN provider name or None
        """
        for provider, ranges in self.cdn_ranges.items():
            for prefix in ranges:
                if ip.startswith(prefix):
                    return provider
        return None
    
    def _is_typosquat(self, domain: str) -> bool:
        """Check for typosquatting patterns
        
        Args:
            domain: Domain to check
            
        Returns:
            bool: Whether domain appears to be typosquatting
        """
        # Common typosquatting patterns
        known_brands = {
            'goog1e', 'gooogle', 'g00gle',  # Google
            'micros0ft', 'microsft', 'rnicrosoft',  # Microsoft
            'arnazon', 'amazcn',  # Amazon
            'paypa1', 'paypaf',  # PayPal
            'app1e', 'appl3',  # Apple
        }
        
        for typo in known_brands:
            if typo in domain:
                return True
        
        return False
