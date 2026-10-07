"""
CVE-2025-21756 PoC Orchestration

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

class CVE202521756PoCVerifier(BasePoCVerifier):
    """CVE-2025-21756 PoC Orchestrator"""

    cve_id = "CVE-2025-21756"
    poc_bin = "poc-bin/cve_2025_21756.bin"
    timeout = 10

    _MODULE_NAME = "vsock"
    _CONFIG_KEY = "CONFIG_VSOCKETS"
    _MIN_VERSION = "6.0.0"
    _FIXED_VERSION = "6.6.75"

    def get_prepare_handler(self):
        """Return CVE-2025-21756 dedicated Prepare handler"""
        from ..detector.cve_2025_21756_prepare import CVE202521756PrepareHandler
        return CVE202521756PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2025-21756 dedicated Post handler"""
        from ..detector.cve_2025_21756_post import CVE202521756PostHandler
        return CVE202521756PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version is in affected range
        2. vsock module available (loaded or configured as loadable)
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

        # Module check
        module_loaded = self._MODULE_NAME in kernel_info.loaded_modules
        config_enabled = check_config_enabled(
            self._CONFIG_KEY, kernel_info.config
        )

        if not module_loaded and not config_enabled:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.8,
                error_message=(
                    f"Module {self._MODULE_NAME} not loaded and "
                    f"{self._CONFIG_KEY} not enabled"
                )
            )

        logger.info(
            "Pre-check passed: version=%s, module_loaded=%s, config=%s",
            kernel_info.version, module_loaded, config_enabled
        )
        return None  # passed

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
                "CVE-2025-21756 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
