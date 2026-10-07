"""
CVE-2004-1235 PoC orchestrator

Custom pre-check and post-processing.
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)

class CVE20041235PoCVerifier(BasePoCVerifier):
    """CVE-2004-1235 PoC orchestrator"""

    cve_id = "CVE-2004-1235"
    poc_bin = "poc-bin/cve_2004_1235.bin"
    timeout = 10

    _CONFIG_KEY = "CONFIG_BINFMT_ELF"
    _RANGES = [
        {"min": "2.4.0", "fixed": "2.4.29"},
        {"min": "2.6.0", "fixed": "2.6.10"},
    ]

    def get_prepare_handler(self):
        """Return CVE-2004-1235 specific Prepare handler"""
        from ..detector.cve_2004_1235_prepare import CVE20041235PrepareHandler
        return CVE20041235PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2004-1235 specific Post handler"""
        from ..detector.cve_2004_1235_post import CVE20041235PostHandler
        return CVE20041235PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version in affected range
        2. CONFIG_BINFMT_ELF available
        """
        # Version check
        version_vulnerable = False
        for ver_range in self._RANGES:
            if version_in_range(kernel_info.version, ver_range["min"],
                                fixed_version=ver_range["fixed"]):
                version_vulnerable = True
                break

        if not version_vulnerable:
            ranges_str = ", ".join(
                f"[{r['min']}, {r['fixed']})" for r in self._RANGES
            )
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.9,
                error_message=(
                    f"Kernel {kernel_info.version} not in affected ranges "
                    f"{ranges_str}"
                )
            )

        # Config check
        config_enabled = check_config_enabled(
            self._CONFIG_KEY, kernel_info.config
        )

        if not config_enabled and kernel_info.config:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.8,
                error_message=(
                    f"{self._CONFIG_KEY} not enabled - "
                    f"vulnerability path not reachable"
                )
            )

        logger.info(
            "Pre-check passed: version=%s, config=%s",
            kernel_info.version, config_enabled
        )
        return None  # Pass

    def get_extra_env(self, kernel_info: KernelInfo) -> Dict[str, str]:
        """Pass kernel version info to C PoC"""
        return {
            "KERNEL_VERSION": kernel_info.version,
            "KERNEL_ARCH": kernel_info.arch,
        }

    def post_process(self, result: PoCResult,
                     kernel_info: KernelInfo) -> PoCResult:
        """Post-processing: enhance result description"""
        if result.status == "EXPLOITABLE":
            logger.info(
                "CVE-2004-1235 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
