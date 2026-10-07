"""Network anomaly detection analyzer package.

This package provides the NetworkAnalyzer class, split into multiple sub-modules
for maintainability. Each sub-module focuses on a specific detection capability:

- analyzer.py: Core NetworkAnalyzer class composing all mixins
- constants.py: All whitelists, thresholds, patterns
- helpers.py: Lazy import helpers and module-level caches
- port_and_shell.py: Reverse shell, port scanning, hidden connections
- exfiltration.py: DNS/HTTPS/ICMP data exfiltration detection
- c2_and_web.py: C2 communication, web protocol abuse, lateral movement
- dns_tunnel.py: DNS tunneling detection
- beaconing_staging.py: Connection beaconing and data staging
- state_anomaly.py: TCP connection state anomaly detection
"""
from .analyzer import NetworkAnalyzer

__all__ = ["NetworkAnalyzer"]
