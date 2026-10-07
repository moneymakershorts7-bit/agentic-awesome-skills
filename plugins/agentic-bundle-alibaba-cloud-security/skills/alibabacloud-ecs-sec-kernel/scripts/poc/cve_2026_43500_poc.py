"""
CVE-2026-43500 PoC Orchestration

Custom pre-checks, root-owned target file setup, and post-processing.
The prepare phase creates a root:root 0644 file with known canary content.
The PoC (uid=nobody) attempts to overwrite it via RxRPC rxkad splice page
cache pollution without requiring unprivileged user namespaces.
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult, PrepareResult, PostResult
from ..core.kernel_info import KernelInfo

logger = logging.getLogger(__name__)


class CVECve202643500PoCVerifier(BasePoCVerifier):
    """CVE-2026-43500 PoC Orchestrator"""

    cve_id = "CVE-2026-43500"
    poc_bin = "poc-bin/cve_2026_43500.bin"
    timeout = 30

    def __init__(self):
        super().__init__()
        self._target_file = ""

    def get_prepare_handler(self):
        """Return CVE-2026-43500 dedicated Prepare handler"""
        from ..detector.cve_2026_43500_prepare import CVE202643500PrepareHandler
        return CVE202643500PrepareHandler()

    def get_post_handler(self):
        """Return CVE-2026-43500 dedicated Post handler"""
        from ..detector.cve_2026_43500_post import CVE202643500PostHandler
        return CVE202643500PostHandler()

    def prepare(self, kernel_info: KernelInfo,
                test_mode: str = "write_root_file",
                ctf_value: str = "") -> PrepareResult:
        """Execute prepare phase via dedicated handler.

        Creates root-owned target file with canary content and stores
        the path for passing to PoC via environment variable.

        Args:
            kernel_info: Kernel info
            test_mode: CTF test mode
            ctf_value: CTF challenge value
        """
        from ..detector.cve_2026_43500_prepare import CVE202643500PrepareHandler
        handler = CVE202643500PrepareHandler(
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
        import time
        from ..detector.cve_2026_43500_post import CVE202643500PostHandler

        start_time = time.time()
        handler = CVE202643500PostHandler(
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
                "CVE-2026-43500 EXPLOITABLE on kernel %s",
                kernel_info.version
            )
            result.description = (
                f"RxRPC rxkad page cache pollution exploitable on "
                f"kernel {kernel_info.version}. "
                f"Page cache write verified via CTF target file."
            )
        return result
