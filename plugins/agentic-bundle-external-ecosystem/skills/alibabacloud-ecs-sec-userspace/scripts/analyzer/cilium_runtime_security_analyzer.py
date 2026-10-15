"""Cilium/Tetragon eBPF Runtime Security Analyzer (compatibility shim).

This file is a backward-compatibility re-export. The implementation has been
split into the cilium/ sub-package:
  - cilium/analyzer.py: Main class + orchestration
  - cilium/policy_analyzer.py: CRD audit, policy bypass, CVE-2026-33726
  - cilium/evasion_detector.py: Tetragon evasion, VoidLink detection
  - cilium/runtime_monitor.py: eBPF, Hubble, agent health, binary integrity
"""
from .cilium.analyzer import CiliumRuntimeSecurityAnalyzer as _Base

# Alias for registry discovery (registry checks obj.__module__ == shim module)
CiliumRuntimeSecurityAnalyzer = _Base
CiliumRuntimeSecurityAnalyzer.__module__ = __name__

__all__ = ['CiliumRuntimeSecurityAnalyzer']
