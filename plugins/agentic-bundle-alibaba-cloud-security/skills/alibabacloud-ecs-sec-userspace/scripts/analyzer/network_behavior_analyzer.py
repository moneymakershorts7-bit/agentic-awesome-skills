"""Network Behavior Profiling Analyzer - Runtime Connection Analysis"""
import math
from typing import List, Dict
from collections import defaultdict
from ..reporter.evidence import Evidence, Severity
from ..utils.remediation_generator import generate_generic_remediation
from .base import BaseAnalyzer
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

class NetworkBehaviorAnalyzer(BaseAnalyzer):
    """Profile network connections and detect anomalous communication patterns
    
    ATT&CK Coverage: T1071 (Application Layer Protocol), T1571 (Non-Standard Port),
                     T1048 (Exfiltration Over Alternative Protocol), T1568 (Dynamic Resolution)
    """
    name = 'network_behavior_analyzer'
    timeout = 30
    required_collectors = ['network']
    estimated_time = 5.0
    analyzer_type = BaseAnalyzer.IMPORTANT
    BEACONING_THRESHOLD = 0.85
    MIN_CONNECTIONS_FOR_BEACON = 5
    DNS_QUERY_THRESHOLD = 50
    ENTROPY_THRESHOLD = 3.5
    COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 8080, 8443}
    SUSPICIOUS_PORT_SERVICES = {4444: 'Metasploit default', 5555: 'Android ADB / Backdoor', 6666: 'IRC backdoor', 7777: 'Back Orifice', 8888: 'Common C2 port', 9999: 'DarkComet RAT', 12345: 'NetBus trojan', 31337: 'Back Orifice / Elite', 1234: 'Common reverse shell', 54321: 'Common backdoor'}

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze network behavior for anomalies"""
        evidences = []
        network_data = self._get_data(collected_data, 'network')
        if not network_data:
            _get_logger().warning(f'[{self.name}] No network data available')
            return evidences
        try:
            connections = network_data.get('connections', [])
            listening_ports = network_data.get('listening_ports', [])
            dns_queries = network_data.get('dns_queries', [])
            evidences.extend(self._detect_beaconing(connections))
            evidences.extend(self._detect_suspicious_ports(listening_ports))
            evidences.extend(self._analyze_dns_anomalies(dns_queries))
            evidences.extend(self._detect_data_staging(connections))
            evidences.extend(self._detect_encrypted_channels(connections))
            if evidences:
                _get_logger().info(f'[{self.name}] Found {len(evidences)} network behavior anomalies')
            else:
                _get_logger().info(f'[{self.name}] No network behavior anomalies detected')
        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().error(f'[{self.name}] Error during analysis: {e}', exc_info=True)
        return evidences
    def _detect_beaconing(self, connections: List[Dict]) -> List[Evidence]:
        """Detect periodic C2 beaconing patterns"""
        evidences = []
        dest_connections = defaultdict(list)
        for conn in connections:
            dst_ip = conn.get('dst_ip', '')
            dst_port = conn.get('dst_port', 0)
            timestamp = conn.get('timestamp', 0)
            if dst_ip and timestamp:
                key = f'{dst_ip}:{dst_port}'
                dest_connections[key].append(timestamp)
        for dest, timestamps in dest_connections.items():
            if len(timestamps) < self.MIN_CONNECTIONS_FOR_BEACON:
                continue
            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            if not intervals:
                continue
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                continue
            variance = sum(((x - mean_interval) ** 2 for x in intervals)) / len(intervals)
            std_dev = math.sqrt(variance)
            cv = std_dev / mean_interval if mean_interval > 0 else 1e9
            regularity_score = max(0, 1 - cv)
            if regularity_score >= self.BEACONING_THRESHOLD:
                dst_ip, dst_port = dest.rsplit(':', 1)
                evidence = self._create_evidence(title='Potential C2 Beaconing Detected', description=f'Regular periodic connections detected (possible C2 beacon):\n  Destination: {dst_ip}:{dst_port}\n  Connection count: {len(timestamps)}\n  Mean interval: {mean_interval:.2f}s\n  Regularity score: {regularity_score:.2%}\n  Pattern suggests automated callback', severity=Severity.CRITICAL, confidence=min(0.95, regularity_score), attack_id='T1071', attack_tactic='Command and Control', source_path='network_monitoring', raw_data={'destination': dest, 'connection_count': len(timestamps), 'mean_interval': mean_interval, 'regularity_score': regularity_score}, remediation='Block the destination IP at firewall. Investigate the process making these connections. Capture network traffic for further analysis.', evidence_details=self._create_evidence_details(service_type='network_behavior'), remediation_commands=generate_generic_remediation(attack_id='1071', context={'analyzer': 'network_behavior_analyzer'}))
                evidences.append(evidence)
        return evidences

    def _detect_suspicious_ports(self, listening_ports: List[Dict]) -> List[Evidence]:
        """Detect suspicious listening ports"""
        evidences = []
        for port_info in listening_ports:
            port = port_info.get('port', 0)
            protocol = port_info.get('protocol', 'tcp')
            if port in self.SUSPICIOUS_PORT_SERVICES:
                service = self.SUSPICIOUS_PORT_SERVICES[port]
                evidence = self._create_evidence(title=f'Suspicious Listening Port: {port}/tcp ({service})', description=f"Detected listener on known malicious/suspicious port:\n  Port: {port}/{protocol}\n  Associated with: {service}\n  PID: {port_info.get('pid', 'N/A')}\n  Process: {port_info.get('process', 'N/A')}", severity=Severity.HIGH, confidence=0.8, attack_id='T1571', attack_tactic='Command and Control', source_path=f'/proc/net/{protocol}', raw_data=port_info, remediation=f'Investigate the process listening on port {port}. If unauthorized, terminate immediately and scan for malware.', evidence_details=self._create_evidence_details(service_type='network_behavior'), remediation_commands=generate_generic_remediation(attack_id='1571', context={'analyzer': 'network_behavior_analyzer'}))
                evidences.append(evidence)
            elif port not in self.COMMON_PORTS and port > 10000:
                process_name = port_info.get('process', '').lower()
                suspicious_indicators = ['reverse', 'shell', 'backdoor', 'bind']
                if any((ind in process_name for ind in suspicious_indicators)):
                    evidence = self._create_evidence(title=f'Unusual High Port Listener: {port}/tcp', description=f"Suspicious process listening on non-standard high port:\n  Port: {port}/{protocol}\n  Process: {port_info.get('process', 'N/A')}\n  PID: {port_info.get('pid', 'N/A')}", severity=Severity.MEDIUM, confidence=0.65, attack_id='T1571', attack_tactic='Command and Control', source_path=f'/proc/net/{protocol}', raw_data=port_info, remediation='Verify this is a legitimate service.', evidence_details=self._create_evidence_details(service_type='network_behavior'), remediation_commands=generate_generic_remediation(attack_id='1571', context={'analyzer': 'network_behavior_analyzer'}))
                    evidences.append(evidence)
        return evidences

    def _analyze_dns_anomalies(self, dns_queries: List[Dict]) -> List[Evidence]:
        """Analyze DNS queries for DGA and tunneling indicators"""
        evidences = []
        if len(dns_queries) > self.DNS_QUERY_THRESHOLD:
            domain_lengths = [len(q.get('domain', '')) for q in dns_queries]
            avg_length = sum(domain_lengths) / len(domain_lengths) if domain_lengths else 0
            if avg_length > 30:
                evidence = self._create_evidence(title='Potential DNS Tunneling or DGA Activity', description=f'Abnormal DNS query patterns detected:\n  Total queries: {len(dns_queries)}\n  Average domain length: {avg_length:.1f} chars\n  Indicates: Possible DNS tunneling or DGA malware', severity=Severity.HIGH, confidence=0.7, attack_id='T1568.002', attack_tactic='Command and Control', source_path='dns_monitoring', raw_data={'query_count': len(dns_queries), 'avg_domain_length': avg_length, 'sample_domains': [q.get('domain', '') for q in dns_queries[:5]]}, remediation='Analyze DNS query content for encoded data. Check for known DGA patterns. Consider blocking suspicious domains.', evidence_details=self._create_evidence_details(service_type='network_behavior'), remediation_commands=generate_generic_remediation(attack_id='1568.002', context={'analyzer': 'network_behavior_analyzer'}))
                evidences.append(evidence)
        high_entropy_domains = []
        for query in dns_queries:
            domain = query.get('domain', '')
            if domain:
                entropy = self._calculate_entropy(domain.split('.')[0])
                if entropy > self.ENTROPY_THRESHOLD:
                    high_entropy_domains.append({'domain': domain, 'entropy': entropy})
        if len(high_entropy_domains) > 10:
            evidence = self._create_evidence(title='High Entropy Domain Queries (DGA Indicator)', description=f'Detected {len(high_entropy_domains)} queries to high-entropy domains:\n\n' + '\n'.join([f"  - {d['domain']} (entropy: {d['entropy']:.2f})" for d in high_entropy_domains[:10]]), severity=Severity.MEDIUM, confidence=0.65, attack_id='T1568.002', attack_tactic='Command and Control', source_path='dns_monitoring', raw_data={'high_entropy_count': len(high_entropy_domains), 'domains': high_entropy_domains[:10]}, remediation='Investigate for DGA malware. Block suspicious domains.', evidence_details=self._create_evidence_details(service_type='network_behavior'), remediation_commands=generate_generic_remediation(attack_id='1568.002', context={'analyzer': 'network_behavior_analyzer'}))
            evidences.append(evidence)
        return evidences

    def _detect_data_staging(self, connections: List[Dict]) -> List[Evidence]:
        """Detect potential data staging before exfiltration"""
        evidences = []
        large_transfers = []
        for conn in connections:
            bytes_sent = conn.get('bytes_sent', 0)
            if bytes_sent > 100 * 1024 * 1024:
                large_transfers.append(conn)
        if large_transfers:
            evidence = self._create_evidence(title='Large Outbound Data Transfers Detected', description=f'Detected {len(large_transfers)} large outbound transfers (>100MB):\n\n' + '\n'.join([f"  - {c.get('dst_ip')}:{c.get('dst_port')} - {c.get('bytes_sent', 0) // (1024 * 1024)} MB" for c in large_transfers[:5]]), severity=Severity.HIGH, confidence=0.7, attack_id='T1074', attack_tactic='Collection', source_path='network_monitoring', raw_data={'large_transfer_count': len(large_transfers), 'transfers': [{'dst': f"{c.get('dst_ip')}:{c.get('dst_port')}", 'bytes': c.get('bytes_sent')} for c in large_transfers[:5]]}, remediation='Investigate the source of large data transfers. Check if this matches backup activity. If unauthorized, block immediately and assess data loss.', evidence_details=self._create_evidence_details(service_type='network_behavior'), remediation_commands=generate_generic_remediation(attack_id='1074', context={'analyzer': 'network_behavior_analyzer'}))
            evidences.append(evidence)
        return evidences

    def _detect_encrypted_channels(self, connections: List[Dict]) -> List[Evidence]:
        """Detect unusual encrypted channel establishment"""
        evidences = []
        non_standard_tls = []
        for conn in connections:
            dst_port = conn.get('dst_port', 0)
            protocol = conn.get('protocol', '').upper()
            if 'TLS' in protocol or 'SSL' in protocol or 'HTTPS' in protocol:
                if dst_port not in [443, 8443, 993, 995, 465, 587]:
                    non_standard_tls.append(conn)
        if len(non_standard_tls) > 5:
            evidence = self._create_evidence(
                title='Encrypted Channels on Non-Standard Ports',
                description=f'Detected {len(non_standard_tls)} TLS/SSL connections on non-standard ports:\n\n' + '\n'.join([f"  - {c.get('dst_ip')}:{c.get('dst_port')}" for c in non_standard_tls[:10]]),
                severity=Severity.MEDIUM,
                confidence=0.6,
                attack_id='T1573',
                attack_tactic='Command and Control',
                source_path='network_monitoring',
                raw_data={'count': len(non_standard_tls), 'connections': [f"{c.get('dst_ip')}:{c.get('dst_port')}" for c in non_standard_tls[:10]]},
                remediation='Investigate why TLS is being used on non-standard ports. This could indicate covert C2 channels.',
                evidence_details=self._create_evidence_details(service_type='network_behavior'),
                remediation_commands=generate_generic_remediation(attack_id='T1573', context={'analyzer': 'network_behavior_analyzer'})
            )
            evidences.append(evidence)
        return evidences

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        freq = defaultdict(int)
        for char in text:
            freq[char] += 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy