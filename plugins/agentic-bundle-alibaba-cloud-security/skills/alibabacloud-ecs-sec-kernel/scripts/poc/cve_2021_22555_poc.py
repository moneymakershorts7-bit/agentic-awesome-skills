"""
CVE-2021-22555 PoC orchestration

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

class CVE202122555PoCVerifier(BasePoCVerifier):
    """CVE-2021-22555 PoC Orchestrator"""

    cve_id = "CVE-2021-22555"
    poc_bin = "poc-bin/cve_2021_22555.bin"
    timeout = 10

    _MODULE_NAME = "x_tables"
    _CONFIG_KEY = "CONFIG_NETFILTER_XTABLES"
    _MIN_VERSION = "2.6.19"
    _FIXED_VERSION = "5.12.0"

    def get_prepare_handler(self):
        """Return CVE-2021-22555 dedicated Prepare handler"""
        from ..detector.cve_2021_22555_prepare import CVE202122555PrepareHandler
        return CVE202122555PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2021-22555 dedicated Post handler"""
        from ..detector.cve_2021_22555_post import CVE202122555PostHandler
        return CVE202122555PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version in affected range
        2. CONFIG_NETFILTER_XTABLES Configuration enabled
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
                    f"x_tables subsystem not available"
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
                "CVE-2021-22555 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
