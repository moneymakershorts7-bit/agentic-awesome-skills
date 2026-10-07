"""Process Information Collector - Package.

This package contains the split version of the original process.py module.
The original 2955-line file has been organized into:
- collector.py: ProcessCollector class (main implementation)

Backward compatibility: The original scripts/collector/process.py imports from here.
"""
from .collector import ProcessCollector

__all__ = ['ProcessCollector']
