"""
EnvironmentDetector - RunEnvironmentDetector

Detect current runtime environment type:
- Host: Physical machine/virtual machine direct run
- WSL2: Windows Subsystem for Linux
"""
import os
import logging
import sys
if sys.version_info < (3, 7):
    from ..thirdparties.dataclasses_backport import dataclass, field
else:
    from dataclasses import dataclass, field
from typing import Dict

logger = logging.getLogger(__name__)


@dataclass
class EnvInfo:
    """Run environment info"""

    env_type: str = "host"  # "host" | "wsl2"

    is_wsl2: bool = False

    evidence: Dict[str, str] = field(default_factory=dict)


class EnvironmentDetector:
    """Run environment detector"""

    def detect(self) -> EnvInfo:
        """
        Detect current runtime environment

        Returns:
            EnvInfo: Environment info data structure
        """
        info = EnvInfo()

        self._detect_wsl2(info)

        if info.is_wsl2:
            info.env_type = "wsl2"
        else:
            info.env_type = "host"

        logger.debug("Environment detected: %s", info.env_type)
        return info

    def _detect_wsl2(self, info: EnvInfo) -> None:
        """Detect WSL2 environment"""
        try:
            with open("/proc/version", "r", encoding="utf-8") as f:
                version = f.read()
            if "microsoft" in version.lower() or "WSL2" in version:
                info.is_wsl2 = True
                info.evidence["wsl2"] = "Detected via /proc/version"
        except (OSError, IOError):
            pass