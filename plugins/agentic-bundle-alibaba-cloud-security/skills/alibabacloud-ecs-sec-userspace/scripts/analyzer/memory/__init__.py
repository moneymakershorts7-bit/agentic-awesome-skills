"""Memory Forensics Analyzer package.

This package provides the MemoryForensicsAnalyzer class, split into
multiple sub-modules for maintainability:

- forensics_analyzer.py: Core MemoryForensicsAnalyzer class composing all mixins
- constants.py: All patterns, heuristics, and configuration
- helpers.py: Lazy import helpers and module-level utilities
- injection_detector.py: Memory injection detection capabilities
- rwx_scanner.py: RWX memory scanning and credential extraction
- process_hollowing.py: Process hollowing and DLL injection detection
"""
from .forensics_analyzer import MemoryForensicsAnalyzer

__all__ = ["MemoryForensicsAnalyzer"]
