"""Lateral Movement Analyzer - Main Class.

Composes all detection capabilities via mixin-based composition:
- SSHDetectorMixin: SSH abuse, key theft, config tampering, hijacking
- TunnelDetectorMixin: Tunnel tools, reverse proxy detection
- NetworkScanDetectorMixin: Network scanning, host discovery, remote execution
- CredentialRelayMixin: Container escape, cloud lateral, tool transfer, config mgmt
- LateralCorrelationMixin: Temporal correlation engine

Extracted from lateral_movement_analyzer.py - zero functional change.
"""
from typing import List, Dict
from ...reporter.evidence import Evidence
from .ssh_detector import SSHDetectorMixin
from .tunnel_detector import TunnelDetectorMixin
from .remote_exploit import NetworkScanDetectorMixin
from .container_escape import ContainerEscapeMixin
from .cloud_lateral import CloudLateralMixin
from .credential_relay import CredentialRelayMixin
from .correlation import LateralCorrelationMixin
from ..base import BaseAnalyzer
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


class LateralMovementAnalyzer(
    SSHDetectorMixin,
    TunnelDetectorMixin,
    NetworkScanDetectorMixin,
    ContainerEscapeMixin,
    CloudLateralMixin,
    CredentialRelayMixin,
    LateralCorrelationMixin,
    BaseAnalyzer,
):
    """Lateral Movement Detection Analyzer"""

    name = "lateral_movement_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    required_collectors = ["process", "network"]  # filesystem only for full mode
    quick_collectors = ["process"]  # quick mode only needs process data
    estimated_time = 1.0  # Optimized from higher value

    def should_skip(self) -> tuple:
        """Lateral movement detection runs in quick mode with lightweight process checks"""
        return False, ""

    def _get_data(self, collected_data: Dict, key: str) -> Dict:
        """Safely extract data from collected data dict

        Properly handles collector result objects to avoid TypeError.
        """
        if not collected_data:
            return {}
        if key not in collected_data:
            return {}

        data = collected_data[key]

        # Handle collector result object
        if hasattr(data, 'data') and hasattr(data, 'status'):
            if data.status != 'success':
                return {}
            return data.data or {}

        # Handle dict or list format
        if isinstance(data, (dict, list)):
            return data

        return data or {}
    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze collected data for lateral movement indicators"""
        evidences = []

        from ...utils.fp_tracker import get_tracker
        tracker = get_tracker()
        tracker.record_detection('lateral_movement_analyzer', 1)

        try:
            # Full mode: comprehensive analysis
            process_data = self._get_data(collected_data, "process")
            network_data = self._get_data(collected_data, "network")
            filesystem_data = self._get_data(collected_data, "filesystem")

            if not process_data or not network_data:
                return evidences

            # SSH abuse detection (existing + enhanced)
            evidences.extend(self._detect_ssh_abuse(process_data, filesystem_data))

            # SSH hijacking detection (NEW - T1563.001)
            evidences.extend(self._detect_ssh_hijacking(process_data, filesystem_data))

            # Cloud service lateral movement detection (NEW - T1021.007)
            evidences.extend(self._detect_cloud_lateral_movement(process_data))

            # Remote service tunnel detection
            evidences.extend(self._detect_tunnel_tools(process_data, network_data))

            # Lateral tool transfer detection (NEW - T1570)
            evidences.extend(self._detect_tool_transfer(process_data))

            # Configuration management abuse detection (NEW - T1072)
            evidences.extend(self._detect_config_mgmt_abuse(process_data))

            # Container escape detection
            evidences.extend(self._detect_container_escape(process_data, filesystem_data))

            # Network scanning detection
            evidences.extend(self._detect_network_scanning(process_data))

            # Remote execution detection
            evidences.extend(self._detect_remote_execution(process_data))

            # Temporal correlation for multi-stage campaigns (NEW)
            evidences.extend(self._run_temporal_correlation(collected_data))

        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().warning(f"Lateral movement analysis error: {e}")

        return evidences
