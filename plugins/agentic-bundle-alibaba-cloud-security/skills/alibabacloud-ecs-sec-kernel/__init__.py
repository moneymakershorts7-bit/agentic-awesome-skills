"""
sec-kernel - Linux Kernel CVE Detection Tool
"""
import os
from pathlib import Path

__version__ = "1.4.1"
__author__ = "sec-kernel contributors"

# Read VERSION file if exists
_version_file = Path(__file__).parent / "VERSION"
if _version_file.exists():
    __version__ = _version_file.read_text().strip()

# Package metadata
__package_name__ = "sec-kernel"
__description__ = "Linux Kernel CVE Detection Tool with PoC Verification"
