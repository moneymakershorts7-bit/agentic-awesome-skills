"""
CVE-2009-2692 PoC orchestrator

Custom pre-check and post-processing for sock_sendpage NULL pointer dereference.
CTF modes are unsupported (NULL pointer deref is not page cache pollution).
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult, PrepareResult, PostResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)


class CVE20092692PoCVerifier(BasePoCVerifier):
    """CVE-2009-2692 PoC orchestrator"""

    cve_id = "CVE-2009-2692"
    poc_bin = "poc-bin/cve_2009_2692.bin"
    timeout = 10

    _CONFIG_KEY = "CONFIG_PPPOE"
    _RANGES = [
        {"min": "2.4.4", "fixed": "2.6.31"},
    ]

    def get_prepare_handler(self):
        """Return CVE-2009-2692 specific Prepare handler"""
        from ..detector.cve_2009_2692_prepare import CVE20092692PrepareHandler
        return CVE20092692PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2009-2692 specific Post handler"""
        from ..detector.cve_2009_2692_post import CVE20092692PostHandler
        return CVE20092692PostHandler()

    def prepare(self, kernel_info: KernelInfo,
                test_mode: str = "write_root_file",
                ctf_value: str = "") -> PrepareResult:
        """Execute prepare phase with CTF parameters.

        Creates root-owned target file with CTF content and stores
        the path for passing to PoC via environment variable.

        Args:
            kernel_info: Kernel info
            test_mode: CTF test mode
            ctf_value: CTF challenge value
        """
        from ..detector.cve_2009_2692_prepare import CVE20092692PrepareHandler
        handler = CVE20092692PrepareHandler(
            timeout=self.timeout,
            test_mode=test_mode,
            ctf_value=ctf_value,
        )
        result = handler.prepare(kernel_info.__dict__ if kernel_info else {})

        return result

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None,
             poc_result: Optional[PoCResult] = None,
             test_mode: str = "write_root_file",
             ctf_value: str = "") -> PostResult:
        """Execute post phase with CTF parameters.

        Verifies CTF challenge result, cleans up residuals, and confirms
        system state is restored.

        Args:
            kernel_info: Kernel info
            prepare_result: Prepare phase result for rollback
            poc_result: PoC execution result for CTF verification
            test_mode: CTF test mode
            ctf_value: CTF challenge value for verification
        """
        from ..detector.cve_2009_2692_post import CVE20092692PostHandler
        handler = CVE20092692PostHandler(
            prepare_result=prepare_result,
            timeout=self.timeout,
            test_mode=test_mode,
            ctf_value=ctf_value,
        )

        # Self-check: verify no residuals left
        self_check_result = handler.self_check(run_user="nobody")

        # Global verify: CTF verification + rollback + system recovery
        effective_prepare = prepare_result or PrepareResult(
            success=False, operations=[], state_snapshot={}
        )
        global_verify_result = handler.global_verify(effective_prepare)

        success = self_check_result.clean and global_verify_result.system_restored

        return PostResult(
            self_check=self_check_result,
            global_verify=global_verify_result,
            success=success,
            duration=0.0
        )

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version in affected range
        2. CONFIG_PPPOE available
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
                "CVE-2009-2692 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
