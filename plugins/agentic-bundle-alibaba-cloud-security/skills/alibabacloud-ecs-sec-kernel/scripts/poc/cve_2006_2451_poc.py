"""
CVE-2006-2451 PoC Orchestration

Custom pre-checks, CTF target file setup, and post-processing.
The prepare phase creates a root-owned target file with CTF content.
The PoC (uid=nobody) attempts to interact with the target via prctl dumpable manipulation.
"""
import logging
import time
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult, PrepareResult, PostResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)


class CVE20062451PoCVerifier(BasePoCVerifier):
    """CVE-2006-2451 PoC Orchestrator"""

    cve_id = "CVE-2006-2451"
    poc_bin = "poc-bin/cve_2006_2451.bin"
    timeout = 10
    test_modes = ["read_root_file", "write_root_file"]

    _CONFIG_KEY = "CONFIG_PROC_FS"
    _MIN_VERSION = "2.6.13"
    _FIXED_VERSION = "2.6.17.4"

    def __init__(self):
        super().__init__()
        self._target_file = ""

    def get_prepare_handler(self):
        """Return CVE-2006-2451 dedicated Prepare handler"""
        from ..detector.cve_2006_2451_prepare import CVE20062451PrepareHandler
        return CVE20062451PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2006-2451 dedicated Post handler"""
        from ..detector.cve_2006_2451_post import CVE20062451PostHandler
        return CVE20062451PostHandler()

    def prepare(self, kernel_info: KernelInfo,
                test_mode: str = "write_root_file",
                ctf_value: str = "") -> PrepareResult:
        """Execute prepare phase via dedicated handler.

        Creates root-owned target file with CTF content and stores
        the path for passing to PoC via environment variable.

        Args:
            kernel_info: Kernel info
            test_mode: CTF test mode
            ctf_value: CTF challenge value
        """
        from ..detector.cve_2006_2451_prepare import CVE20062451PrepareHandler
        handler = CVE20062451PrepareHandler(
            test_mode=test_mode, ctf_value=ctf_value
        )
        result = handler.prepare(kernel_info.__dict__ if kernel_info else {})

        # Extract target file path from state snapshot
        if result.state_snapshot:
            self._target_file = result.state_snapshot.get("target_file", "")
            if self._target_file:
                logger.info(
                    "Prepare created target file: %s", self._target_file
                )

        return result

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None,
             poc_result: Optional[PoCResult] = None,
             test_mode: str = "write_root_file",
             ctf_value: str = "") -> PostResult:
        """Execute post phase via dedicated handler.

        Verifies CTF challenge result, cleans up residuals, and confirms
        system state is restored.

        Args:
            kernel_info: Kernel info
            prepare_result: Prepare phase result for rollback
            poc_result: PoC execution result for CTF verification
            test_mode: CTF test mode
            ctf_value: CTF challenge value for verification
        """
        from ..detector.cve_2006_2451_post import CVE20062451PostHandler

        start_time = time.time()
        handler = CVE20062451PostHandler(
            prepare_result=prepare_result,
            poc_result=poc_result,
            test_mode=test_mode,
            ctf_value=ctf_value
        )

        # Self-check: verify no residuals left
        self_check_result = handler.self_check(run_user="nobody")

        # Global verify: CTF verification + rollback + system recovery
        effective_prepare = prepare_result or PrepareResult(
            success=False, operations=[], state_snapshot={}
        )
        global_verify_result = handler.global_verify(effective_prepare)

        success = self_check_result.clean and global_verify_result.system_restored
        duration = time.time() - start_time

        return PostResult(
            self_check=self_check_result,
            global_verify=global_verify_result,
            success=success,
            duration=duration
        )

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-check:
        1. Kernel version is in affected range
        2. CONFIG_PROC_FS available
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
        return None  # passed

    def get_extra_env(self, kernel_info: KernelInfo) -> Dict[str, str]:
        """Pass target file path and kernel info to C PoC."""
        env = {
            "KERNEL_VERSION": kernel_info.version,
            "KERNEL_ARCH": kernel_info.arch,
        }
        if self._target_file:
            env["POC_TARGET_FILE"] = self._target_file
        return env

    def post_process(self, result: PoCResult,
                     kernel_info: KernelInfo) -> PoCResult:
        """Post-processing: enhance result description"""
        if result.status == "EXPLOITABLE":
            logger.info(
                "CVE-2006-2451 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
        return result
