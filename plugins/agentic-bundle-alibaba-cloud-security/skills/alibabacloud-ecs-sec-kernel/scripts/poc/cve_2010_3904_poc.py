"""
CVE-2010-3904 PoC orchestrator

Custom pre-check and post-processing for RDS rds_page_copy_user() vulnerability.
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)

class CVE20103904PoCVerifier(BasePoCVerifier):
    """CVE-2010-3904 PoC orchestrator"""

    cve_id = "CVE-2010-3904"
    poc_bin = "poc-bin/cve_2010_3904.bin"
    timeout = 10

    _CONFIG_KEY = "CONFIG_RDS"
    _RANGES = [
        {"min": "2.6.30", "fixed": "2.6.36"},
    ]

    def get_prepare_handler(self):
        """Return CVE-2010-3904 specific Prepare handler"""
        from ..detector.cve_2010_3904_prepare import CVE20103904PrepareHandler
        return CVE20103904PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2010-3904 specific Post handler"""
        from ..detector.cve_2010_3904_post import CVE20103904PostHandler
        return CVE20103904PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version in affected range
        2. CONFIG_RDS available
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
                "CVE-2010-3904 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
