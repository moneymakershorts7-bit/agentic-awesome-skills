"""
CVE-2004-0077 PoC Orchestrator

Custom pre-check and post-processing for mremap integer overflow LPE verification.
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)

class CVE20040077PoCVerifier(BasePoCVerifier):
    """CVE-2004-0077 PoC orchestrator"""

    cve_id = "CVE-2004-0077"
    poc_bin = "poc-bin/cve_2004_0077.bin"
    timeout = 10

    _CONFIG_KEY = "CONFIG_MMU"
    _MIN_VERSION = "2.2.0"
    _FIXED_VERSION = "2.4.25"

    def get_prepare_handler(self):
        """Return CVE-2004-0077 specific Prepare handler"""
        from ..detector.cve_2004_0077_prepare import CVE20040077PrepareHandler
        return CVE20040077PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2004-0077 specific Post handler"""
        from ..detector.cve_2004_0077_post import CVE20040077PostHandler
        return CVE20040077PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version in affected range
        2. CONFIG_MMU available
        """
        # Version check
        if not version_in_range(kernel_info.version, self._MIN_VERSION,
                                fixed_version=self._FIXED_VERSION):
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.9,
                error_message=(
                    f"Kernel {kernel_info.version} not in affected range "
                    f"[{self._MIN_VERSION}, {self._FIXED_VERSION})"
                )
            )

        # Config check (MMU support)
        config_enabled = check_config_enabled(
            self._CONFIG_KEY, kernel_info.config
        )

        # If config not available but version is in range,
        # old kernels typically have MMU built-in, so continue
        if kernel_info.config and not config_enabled:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.8,
                error_message=(
                    f"CONFIG_MMU not enabled - MMU support not available"
                )
            )

        logger.info(
            "Pre-check passed: version=%s, mmu_config=%s",
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
                "CVE-2004-0077 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
