"""NetworkAnalyzer core class - composes all detection capability mixins.

This module contains the main NetworkAnalyzer class that inherits from:
- PortAndShellMixin (reverse shell, port scanning, hidden connections)
- ExfiltrationMixin (DNS/HTTPS/ICMP data exfiltration)
- C2AndWebMixin (C2 communication, web protocol abuse, lateral movement, malicious domains)
- DnsTunnelMixin (DNS tunneling detection)
- BeaconingStagingMixin (connection beaconing, data staging)
- StateAnomalyMixin (TCP connection state anomalies)

All class-level constants, thresholds, and whitelists are defined in constants.py.
All lazy import helpers and caches are defined in helpers.py.
"""
from typing import List

from ...reporter.evidence import Evidence
from ..base import BaseAnalyzer
from .helpers import _get_logger, _get_fp_tracker
from .port_and_shell import PortAndShellMixin
from .exfiltration import ExfiltrationMixin
from .c2_and_web import C2AndWebMixin
from .dns_tunnel import DnsTunnelMixin
from .beaconing_staging import BeaconingStagingMixin
from .state_anomaly import StateAnomalyMixin


class NetworkAnalyzer(
    PortAndShellMixin,
    ExfiltrationMixin,
    C2AndWebMixin,
    DnsTunnelMixin,
    BeaconingStagingMixin,
    StateAnomalyMixin,
    BaseAnalyzer,
):
    """Network anomaly detection analyzer.

    Composes detection capabilities from multiple mixins:
    - Port/shell detection
    - Data exfiltration detection
    - C2 communication detection
    - DNS tunneling detection
    - Connection beaconing/staging detection
    - TCP state anomaly detection
    """
    name = "network_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    required_collectors = ["network", "process"]

    # Smart scheduling attributes
    estimated_time = 2.0  # Fast network connection data read
    analyzer_type = BaseAnalyzer.CRITICAL  # Critical security check

    def should_skip(self) -> tuple:
        """Check if should skip in quick mode."""
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Analyze network data using chunked processing for connection-heavy detections.

        Connection-heavy detections (reverse shell, hidden connections, port
        scanning, data exfiltration, beaconing, data staging, C2, web abuse)
        are processed via analyze_in_chunks() for memory efficiency.

        Port-based and domain-based detections run separately as they use
        different data keys (listening_ports, dns_queries).

        In quick mode, only lightweight checks are performed:
        - Connections to known C2 ports
        - Connections to known mining pools
        """
        evidences = []

        get_tracker_func, _, _ = _get_fp_tracker()
        tracker = get_tracker_func()
        tracker.record_detection('network_analyzer', 1)

        try:
            network_data = self._get_data(collected_data, "network")
            process_data = self._get_data(collected_data, "process")

            if not network_data or not process_data:
                return evidences

            # Quick mode: lightweight checks only
            # Full mode: comprehensive analysis
            # 1. Reverse shell detection (uses processes + connections)
            evidences.extend(self._detect_reverse_shell(network_data, process_data))

            # 2. Suspicious listening port detection (uses listening_ports only)
            evidences.extend(self._detect_suspicious_ports(network_data))

            # 3. Hidden connection detection (uses processes fd + connections)
            evidences.extend(self._detect_hidden_connections(network_data, process_data))

            # 4-11. Connection-heavy detections via chunked processing
            evidences.extend(self._analyze_connections_chunked(collected_data, network_data))

            # DNS tunneling detection (uses dns collector data)
            evidences.extend(self._detect_dns_tunneling(collected_data))

            # TCP connection state anomaly detection
            evidences.extend(self._detect_connection_state_anomalies(network_data))

            # Per-IP connection state anomaly detection
            evidences.extend(self._detect_per_ip_connection_state_anomalies(network_data))

        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().error(f"Network anomaly analysis failed: {e}")

        return evidences
    def _analyze_connections_chunked(self, collected_data: dict, network_data: dict) -> List[Evidence]:
        """Process connection-heavy detections in chunks using analyze_in_chunks().

        Handles: port scanning, data exfiltration, beaconing, data staging,
        malicious domains, C2 communication, and web protocol abuse.
        """
        evidences = []

        # Combine TCP connections for chunked processing
        all_connections = (
            network_data.get("tcp_connections", []) +
            network_data.get("tcp6_connections", [])
        )

        if not all_connections:
            # Still run detections that don't need connections
            evidences.extend(self._detect_malicious_domains(network_data))
            return evidences

        # Build process index once for detections that need process info
        process_data = self._get_data(collected_data, "process")
        processes = process_data.get("processes", []) if process_data else []
        self._build_process_index(processes)

        # Port scanning detection - uses connections only
        evidences.extend(self._detect_port_scanning(network_data))

        # Data exfiltration detection via chunked processing
        def process_exfiltration_chunk(chunk, analyzer):
            """Process chunk for data exfiltration indicators."""
            chunk_network = {
                "tcp_connections": chunk,
                "dns_queries": network_data.get("dns_queries", []),
                "icmp_packets": network_data.get("icmp_packets", []),
            }
            return analyzer._detect_data_exfiltration(chunk_network, process_data)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_exfiltration_chunk
        ))

        # Connection beaconing detection via chunked processing
        def process_beaconing_chunk(chunk, analyzer):
            return analyzer._detect_connection_beaconing(chunk)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_beaconing_chunk
        ))

        # Data staging detection via chunked processing
        def process_staging_chunk(chunk, analyzer):
            return analyzer._detect_data_staging(chunk, processes)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_staging_chunk
        ))

        # Malicious domain detection (uses DNS queries, not connections)
        evidences.extend(self._detect_malicious_domains(network_data))

        # C2 communication detection via chunked processing
        def process_c2_chunk(chunk, analyzer):
            chunk_network = {"tcp_connections": chunk, "tcp6_connections": []}
            return analyzer._detect_c2_communication(chunk_network)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_c2_chunk
        ))

        # Web protocol abuse detection via chunked processing
        def process_web_abuse_chunk(chunk, analyzer):
            chunk_network = {"tcp_connections": chunk, "tcp6_connections": []}
            return analyzer._detect_web_protocol_abuse(chunk_network)

        evidences.extend(self.analyze_in_chunks(
            collected_data,
            "network",
            "tcp_connections",
            process_chunk_func=process_web_abuse_chunk
        ))

        return evidences
