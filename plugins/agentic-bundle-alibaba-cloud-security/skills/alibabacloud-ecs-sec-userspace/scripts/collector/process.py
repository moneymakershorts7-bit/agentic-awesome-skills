"""Process Information Collector - Thin wrapper for backward compatibility.

This module has been split into the process/ package.
All functionality is now in scripts/collector/process/collector.py.

This file re-exports ProcessCollector to maintain backward compatibility.
"""
from .process.collector import ProcessCollector

__all__ = ['ProcessCollector']
