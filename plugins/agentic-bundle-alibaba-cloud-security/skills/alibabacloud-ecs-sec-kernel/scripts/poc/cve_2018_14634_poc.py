"""
CVE-2018-14634 PoC orchestration

Custom pre-checks and post-processing.
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)

class CVE201814634PoCVerifier(BasePoCVerifier):
    """CVE-2018-14634 PoC Orchestrator"""

    cve_id = "CVE-2018-14634"
    poc_bin = "poc-bin/cve_2018_14634.bin"
    timeout = 10

    _MODULE_NAME = "binfmt_elf"
    _CONFIG_KEY = "CONFIG_BINFMT_ELF"
    _MIN_VERSION = "2.6.0"
    _FIXED_VERSION = "4.15.2"

    def get_prepare_handler(self):
        """Return CVE-2018-14634 dedicated Prepare handler"""
        from ..detector.cve_2018_14634_prepare import CVE201814634PrepareHandler
        return CVE201814634PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2018-14634 dedicated Post handler"""
        from ..detector.cve_2018_14634_post import CVE201814634PostHandler
        return CVE201814634PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version in affected range
        2. CONFIG_BINFMT_ELF Configuration enabled
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

        # Configuration check
        config_enabled = check_config_enabled(
            self._CONFIG_KEY, kernel_info.config
        )

        if not config_enabled and kernel_info.config is not None:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.8,
                error_message=(
                    f"{self._CONFIG_KEY} not enabled - "
                    f"binfmt_elf subsystem not available"
                )
            )

        logger.info(
            "Pre-check passed: version=%s, config_enabled=%s",
            kernel_info.version, config_enabled
        )
        return None  # passed

    def get_extra_env(self, kernel_info: KernelInfo) -> Dict[str, str]:
        """Pass Kernel Version info to C PoC"""
        return {
            "KERNEL_VERSION": kernel_info.version,
            "KERNEL_ARCH": kernel_info.arch,
        }

    def post_process(self, result: PoCResult,
                     kernel_info: KernelInfo) -> PoCResult:
        """Post-processing: enhance result description"""
        if result.status == "EXPLOITABLE":
            logger.info(
                "CVE-2018-14634 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
