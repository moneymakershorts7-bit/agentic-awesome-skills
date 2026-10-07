"""
CVE-2016-0728 PoC orchestration
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)

class CVE20160728PoCVerifier(BasePoCVerifier):
    """CVE-2016-0728 PoC Orchestrator"""

    cve_id = "CVE-2016-0728"
    poc_bin = "poc-bin/cve_2016_0728.bin"
    timeout = 10

    _CONFIG_KEY = "CONFIG_KEYS"
    _MIN_VERSION = "3.8.0"
    _FIXED_VERSION = "4.4.1"

    def get_prepare_handler(self):
        from ..detector.cve_2016_0728_prepare import CVE20160728PrepareHandler
        return CVE20160728PrepareHandler()

    def get_post_handler(self):
        from ..detector.cve_2016_0728_post import CVE20160728PostHandler
        return CVE20160728PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        if not version_in_range(kernel_info.version, self._MIN_VERSION,
                                fixed_version=self._FIXED_VERSION):
            return PoCResult(
                status="NOT_EXPLOITABLE", confidence=0.9,
                error_message=(
                    f"Kernel {kernel_info.version} not in affected range "
                    f"[{self._MIN_VERSION}, {self._FIXED_VERSION})"
                )
            )

        config_enabled = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
        if not config_enabled and kernel_info.config is not None:
            return PoCResult(
                status="NOT_EXPLOITABLE", confidence=0.8,
                error_message=f"{self._CONFIG_KEY} not enabled"
            )

        logger.info("Pre-check passed: version=%s", kernel_info.version)
        return None

    def get_extra_env(self, kernel_info: KernelInfo) -> Dict[str, str]:
        return {
            "KERNEL_VERSION": kernel_info.version,
            "KERNEL_ARCH": kernel_info.arch,
        }

    def post_process(self, result: PoCResult, kernel_info: KernelInfo) -> PoCResult:
        if result.status == "EXPLOITABLE":
            logger.info("CVE-2016-0728 EXPLOITABLE on kernel %s", kernel_info.version)
        return result
