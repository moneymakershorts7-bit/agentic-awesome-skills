"""File System Anomaly Collector - Thin wrapper for backward compatibility

This file is a thin wrapper that re-exports FilesystemCollector from the
filesystem package. The original monolithic module has been split into:

    scripts/collector/filesystem/
    ├── __init__.py              # Package exports
    ├── collector.py             # FilesystemCollector body (main class)
    ├── file_scanner.py          # File scanning (tmp, hidden, webroot, etc.)
    ├── hash_calculator.py       # Binary hash computation and caching
    ├── permission_checker.py    # SUID/SGID file scanning
    └── suid_finder.py           # SUID/SGID cache management

All existing imports like `from scripts.collector.filesystem import FilesystemCollector`
continue to work without modification.
"""

from .filesystem.collector import FilesystemCollector

__all__ = ["FilesystemCollector"]
