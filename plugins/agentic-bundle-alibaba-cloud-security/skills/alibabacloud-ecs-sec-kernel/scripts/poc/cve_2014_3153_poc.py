"""
CVE-2014-3153 PoC orchestration

Custom pre-checks and post-processing for CTF challenge mode.
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)

class CVE20143153PoCVerifier(BasePoCVerifier):
    """CVE-2014-3153 PoC Orchestrator"""

    cve_id = "CVE-2014-3153"
    poc_bin = "poc-bin/cve_2014_3153.bin"
    timeout = 10
    test_modes = ["write_root_file", "read_root_file"]
    retry_count = 3

    _MODULE_NAME = "futex"
    _CONFIG_KEY = "CONFIG_FUTEX"
    _MIN_VERSION = "2.6.32"
    _FIXED_VERSION = "3.14.6"

    def __init__(self):
        self._test_mode = "write_root_file"
        self._ctf_value = ""

    def set_ctf_params(self, test_mode: str = "write_root_file",
                       ctf_value: str = ""):
        """Set CTF parameters for prepare/post handlers"""
        self._test_mode = test_mode
        self._ctf_value = ctf_value

    def get_prepare_handler(self):
        """Return CVE-2014-3153 dedicated Prepare handler"""
        from ..detector.cve_2014_3153_prepare import CVE20143153PrepareHandler
        return CVE20143153PrepareHandler(
            timeout=30,
            test_mode=self._test_mode,
            ctf_value=self._ctf_value,
        )

    def get_post_handler(self):
        """Return CVE-2014-3153 dedicated Post handler"""
        from ..detector.cve_2014_3153_post import CVE20143153PostHandler
        return CVE20143153PostHandler()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version in affected range
        2. CONFIG_FUTEX Configuration enabled
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
                    f"futex subsystem not available"
                )
            )

        logger.info(
            "Pre-check passed: version=%s, config_enabled=%s",
            kernel_info.version, config_enabled
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
                "CVE-2014-3153 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
