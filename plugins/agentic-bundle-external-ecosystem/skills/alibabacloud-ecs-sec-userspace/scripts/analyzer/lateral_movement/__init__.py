"""Lateral Movement Analyzer Package.

Split from lateral_movement_analyzer.py (2084 lines) into focused sub-modules
using mixin-based composition. All files under 500 lines. Zero functional change.
"""

from .analyzer import LateralMovementAnalyzer
from .ssh_detector import SSHDetectorMixin
from .tunnel_detector import TunnelDetectorMixin
from .remote_exploit import NetworkScanDetectorMixin
from .container_escape import ContainerEscapeMixin
from .cloud_lateral import CloudLateralMixin
from .credential_relay import CredentialRelayMixin
from .correlation import LateralCorrelationMixin

__all__ = [
    'LateralMovementAnalyzer',
    'SSHDetectorMixin',
    'TunnelDetectorMixin',
    'NetworkScanDetectorMixin',
    'ContainerEscapeMixin',
    'CloudLateralMixin',
    'CredentialRelayMixin',
    'LateralCorrelationMixin',
]
