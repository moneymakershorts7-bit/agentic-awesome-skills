"""
CVE-2026-PENDING-FRAGNESIA PoC Orchestration

Custom pre-checks, root-owned target file setup, and post-processing.
The prepare phase creates a root:root 0644 file with known canary content.
The PoC (uid=nobody) attempts to overwrite it via ESP-in-TCP splice page cache
pollution in a user+net namespace.

Core mechanism: skb_try_coalesce() drops SKBFL_SHARED_FRAG flag when
coalescing TCP segments. When a TCP socket converts to espintcp ULP
after splice'd file data is already queued, the kernel treats queued
file pages as ESP ciphertext and XORs AES-GCM keystream into them.
"""
import logging
from typing import Optional, Dict

from .base import BasePoCVerifier
from ..core.result import PoCResult, PrepareResult, PostResult
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)


class FragnesiaPoCVerifier(BasePoCVerifier):
    """CVE-2026-PENDING-FRAGNESIA PoC Orchestrator"""

    cve_id = "CVE-2026-PENDING-FRAGNESIA"
    poc_bin = "poc-bin/cve_2026_pending_fragnesia.bin"
    timeout = 30

    # ESP variant constants
    _ESP_MIN_VERSION = "4.10.0"
    _ESP_MODULES = ["esp4", "esp6"]
    _ESP_CONFIG = "CONFIG_XFRM"

    def __init__(self):
        super().__init__()
        self._target_file = ""

    def get_prepare_handler(self):
        """Return CVE-2026-PENDING-FRAGNESIA dedicated Prepare handler"""
        from ..detector.cve_2026_pending_fragnesia_prepare import CVE2026PendingFragnesiaPrepareHandler
        return CVE2026PendingFragnesiaPrepareHandler()

    def get_post_handler(self):
        """Return CVE-2026-PENDING-FRAGNESIA dedicated Post handler"""
        from ..detector.cve_2026_pending_fragnesia_post import CVE2026PendingFragnesiaPostHandler
        return CVE2026PendingFragnesiaPostHandler()

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
        from ..detector.cve_2026_pending_fragnesia_prepare import CVE2026PendingFragnesiaPrepareHandler
        handler = CVE2026PendingFragnesiaPrepareHandler(
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
        from ..detector.cve_2026_pending_fragnesia_post import CVE2026PendingFragnesiaPostHandler

        start_time = time.time()
        handler = CVE2026PendingFragnesiaPostHandler(
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
        1. Kernel version is in affected range for ESP variant
        2. At least one ESP module available (loaded or configurable)
        """
        # ESP variant version check
        esp_version_ok = version_in_range(
            kernel_info.version, self._ESP_MIN_VERSION, fixed_version=None
        )

        if not esp_version_ok:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.9,
                error_message=(
                    f"Kernel {kernel_info.version} not in affected range. "
                    f"ESP requires >= {self._ESP_MIN_VERSION}"
                )
            )

        # Module check
        esp_modules_loaded = any(
            mod in kernel_info.loaded_modules for mod in self._ESP_MODULES
        )
        esp_config_enabled = check_config_enabled(
            self._ESP_CONFIG, kernel_info.config
        )

        if not esp_modules_loaded and not esp_config_enabled:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.8,
                error_message=(
                    f"No exploitable modules: "
                    f"ESP modules ({self._ESP_MODULES}) not loaded/configured"
                )
            )

        logger.info(
            "Pre-check passed: version=%s, esp_modules=%s, esp_config=%s",
            kernel_info.version, esp_modules_loaded, esp_config_enabled
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
                "CVE-2026-PENDING-FRAGNESIA EXPLOITABLE on kernel %s",
                kernel_info.version
            )
            result.description = (
                f"Fragnesia ESP-in-TCP page cache pollution exploitable on "
                f"kernel {kernel_info.version}. "
                f"Page cache write verified via CTF target file."
            )
        elif result.status == "NOT_EXPLOITABLE":
            result.description = (
                f"Fragnesia not exploitable on kernel {kernel_info.version}. "
                f"ESP variant blocked (unshare denied or modules missing)."
            )
        return result
