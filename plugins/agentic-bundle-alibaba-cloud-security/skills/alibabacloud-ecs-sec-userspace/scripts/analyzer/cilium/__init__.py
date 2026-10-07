"""Cilium/Tetragon eBPF Runtime Security Analyzer package.

This package provides the CiliumRuntimeSecurityAnalyzer class, split into
multiple sub-modules for maintainability:

- analyzer.py: Core CiliumRuntimeSecurityAnalyzer class composing all mixins
- constants.py: All patterns, thresholds, whitelists, and class-level constants
- helpers.py: Lazy import helpers and module-level utilities
- policy_analyzer.py: CRD audit, CVE-2026-33726, network policy bypass
- evasion_detector.py: Tetragon evasion, VoidLink eBPF map tampering
- runtime_monitor.py: eBPF program integrity, Hubble telemetry, agent health, binary integrity
"""
from .analyzer import CiliumRuntimeSecurityAnalyzer

__all__ = ["CiliumRuntimeSecurityAnalyzer"]
