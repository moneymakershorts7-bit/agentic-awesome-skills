"""File System Anomaly Collector package

Split from monolithic filesystem.py into modular sub-modules:
- collector.py: Main FilesystemCollector class with mixin composition
- file_scanner.py: Basic file scanning (tmp, hidden, recent, history, shell, skill)
- hash_calculator.py: Binary hash computation and caching
- permission_checker.py: SUID/SGID file scanning
- suid_finder.py: SUID/SGID cache management
- webroot_scanner.py: Web root recursive scanning
- k8s_scanner.py: Kubernetes sensitive file scanning
"""

from .collector import FilesystemCollector

__all__ = ["FilesystemCollector"]
