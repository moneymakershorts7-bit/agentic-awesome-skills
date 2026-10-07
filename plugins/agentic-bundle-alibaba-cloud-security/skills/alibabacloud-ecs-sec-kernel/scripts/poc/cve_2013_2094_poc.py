"""
CVE-2013-2094 PoC Orchestration

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

class CVE20132094PoCVerifier(BasePoCVerifier):
    """CVE-2013-2094 PoC Orchestrator"""

    cve_id = "CVE-2013-2094"
    poc_bin = "poc-bin/cve_2013_2094.bin"
    timeout = 10

    _MODULE_NAME = "perf_event"
    _CONFIG_KEY = "CONFIG_PERF_EVENTS"
    _MIN_VERSION = "3.0.0"
    _FIXED_VERSION = "3.8.9"

    def get_prepare_handler(self):
        """Return CVE-2013-2094 dedicated Prepare handler"""
        from ..detector.cve_2013_2094_prepare import CVE20132094PrepareHandler
        return CVE20132094PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2013-2094 dedicated Post handler"""
        from ..detector.cve_2013_2094_post import CVE20132094PostHandler
        return CVE20132094PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version is in affected range
        2. CONFIG_PERF_EVENTS Configuration enabled
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
                    f"perf_events subsystem not available"
                )
            )

        # Check if perf_event_paranoid is completely disabled
        paranoid_value = self._get_paranoid_value()
        if paranoid_value is not None and paranoid_value >= 3:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.85,
                error_message=(
                    f"perf_event_paranoid={paranoid_value} (>= 3) - "
                    f"perf_events fully disabled by mitigation"
                )
            )

        logger.info(
            "Pre-check passed: version=%s, config_enabled=%s, paranoid=%s",
            kernel_info.version, config_enabled, paranoid_value
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
                "CVE-2013-2094 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result

    def _get_paranoid_value(self):
        """Read current perf_event_paranoid value"""
        try:
            with open("/proc/sys/kernel/perf_event_paranoid", "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None
